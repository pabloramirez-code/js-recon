"""Descarga la página objetivo y los JavaScript que referencia.

Decisiones clave:
- Por defecto SOLO se descargan .js del MISMO host que la URL objetivo.
  Un script de un CDN o de Google Analytics casi nunca está en tu scope, y
  pedirlo es tráfico contra un tercero que no te ha autorizado.
- Cada petición tiene timeout y límite de tamaño, y cada error de red se
  registra y se sigue con el siguiente fichero: un .js caído no debe tirar
  todo el escaneo.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from config import MAX_JS_FILES, MAX_RESPONSE_BYTES, REQUEST_TIMEOUT, USER_AGENT
from utils.io import log


@dataclass
class JsFile:
    url: str  # URL real (o página#inline-N para scripts embebidos)
    content: str  # texto ya decodificado
    inline: bool = False


@dataclass
class FetchResult:
    page_url: str
    html: str = ""
    js_files: list[JsFile] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ScriptCollector(HTMLParser):
    """Recoge <script src="..."> y el código de los <script> inline.

    POR QUÉ HTMLParser de la stdlib y no regex sobre el HTML: el HTML no es
    regular (atributos en cualquier orden, comillas simples/dobles, sin
    comillas...). Un parser tolerante lo maneja sin dependencias extra.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.srcs: list[str] = []
        self.inline: list[str] = []
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        a = dict(attrs)
        # type="application/json", "text/template"... no son JS ejecutable,
        # pero pueden llevar config con claves, así que los aceptamos igual.
        src = a.get("src")  # None si es <script src> sin valor
        if src:
            self.srcs.append(src.strip())
        else:
            self._in_script = True
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            code = "".join(self._buf).strip()
            if code:
                self.inline.append(code)
            self._in_script = False


def validate_target(url: str) -> str:
    """Rechaza URLs que no sean http(s) con host. Devuelve la URL limpia."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"URL no válida (usa http:// o https://): {url!r}")
    return parsed.geturl()


def in_scope(url: str, target_host: str) -> bool:
    """Mismo host exacto (incluido el puerto). Subdominios NO cuentan.

    POR QUÉ tan estricto: "app.ejemplo.com" en scope no implica que
    "cdn.ejemplo.com" lo esté. Si lo está, usa --scope-subdomains o --allow-host.
    """
    return urlparse(url).netloc.lower() == target_host.lower()


@dataclass(frozen=True)
class Scope:
    """Qué hosts se pueden analizar. Por defecto, solo el host exacto.

    Ampliarlo es SIEMPRE explícito (un flag por cada relajación), porque en un
    pentest cada host extra tiene que estar en la autorización por escrito.
    """

    target_host: str  # netloc de la URL objetivo (host[:puerto])
    allow_hosts: frozenset[str] = frozenset()  # --allow-host (sin puerto o con él)
    subdomains: bool = False  # --scope-subdomains
    third_party: bool = False  # --include-third-party: todo vale

    def allows(self, url: str) -> bool:
        if self.third_party or in_scope(url, self.target_host):
            return True
        parsed = urlparse(url)
        netloc, host = parsed.netloc.lower(), (parsed.hostname or "").lower()
        if netloc in self.allow_hosts or host in self.allow_hosts:
            return True
        if self.subdomains:
            # "www.tienda.com" -> se aceptan tienda.com y *.tienda.com. Quitar
            # el "www." es lo que hace útil el flag: los CDN cuelgan del
            # dominio base (cdn.tienda.com), no de www.
            base = (urlparse(f"//{self.target_host}").hostname or "").lower()
            base = base.removeprefix("www.")
            return host == base or host.endswith("." + base)
        return False


def make_scope(
    url: str,
    *,
    include_third_party: bool = False,
    allow_hosts: list[str] | None = None,
    subdomains: bool = False,
) -> Scope:
    return Scope(
        target_host=urlparse(url).netloc,
        allow_hosts=frozenset(h.strip().lower() for h in allow_hosts or [] if h.strip()),
        subdomains=subdomains,
        third_party=include_third_party,
    )


def _get(session: requests.Session, url: str) -> tuple[str, str]:
    """GET con timeout y tope de tamaño. Devuelve (url_final, texto).

    Lanza requests.RequestException (o ValueError si excede el tamaño); el
    llamador decide qué hacer. Aquí solo se descarga, no se decide.
    """
    # stream=True: no descargamos el cuerpo entero de golpe; lo leemos por
    # trozos y cortamos si pasa del límite (protección de memoria).
    with session.get(url, timeout=REQUEST_TIMEOUT, stream=True) as resp:
        resp.raise_for_status()  # 4xx/5xx -> HTTPError en vez de "éxito" vacío
        chunks, total = [], 0
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ValueError(f"respuesta > {MAX_RESPONSE_BYTES} bytes, descartada")
            chunks.append(chunk)
        raw = b"".join(chunks)
        # errors="replace": un byte inválido se convierte en "�" en vez de
        # lanzar UnicodeDecodeError. El extractor nunca recibe bytes.
        text = raw.decode(resp.encoding or "utf-8", errors="replace")
        return resp.url, text  # resp.url = URL tras redirecciones


def _safe_get(session: requests.Session, url: str, result: FetchResult) -> tuple[str, str] | None:
    """Envuelve _get: traduce cada fallo de red a un error registrado."""
    try:
        return _get(session, url)
    except requests.Timeout:
        msg = f"timeout: {url}"
    except requests.ConnectionError as e:  # DNS, conexión rechazada, TLS...
        msg = f"error de conexión: {url} ({type(e).__name__})"
    except requests.HTTPError as e:
        msg = f"HTTP {e.response.status_code}: {url}"
    except requests.RequestException as e:  # cualquier otro error de requests
        msg = f"error de petición: {url} ({e})"
    except (ValueError, LookupError) as e:  # tamaño excedido / encoding raro
        msg = f"{url}: {e}"
    log.warning(msg)
    result.errors.append(msg)
    return None


def fetch_target(
    url: str,
    *,
    include_third_party: bool = False,
    allow_hosts: list[str] | None = None,
    scope_subdomains: bool = False,
    verify_tls: bool = True,
    max_js: int = MAX_JS_FILES,
) -> FetchResult:
    """Descarga la página y sus scripts. Nunca lanza por errores de red."""
    url = validate_target(url)
    target_host = urlparse(url).netloc
    scope = make_scope(
        url,
        include_third_party=include_third_party,
        allow_hosts=allow_hosts,
        subdomains=scope_subdomains,
    )
    result = FetchResult(page_url=url)

    # Session: reutiliza la conexión TCP/TLS entre peticiones (más rápido y
    # menos carga para el servidor) y comparte cabeceras.
    with requests.Session() as session:
        session.headers["User-Agent"] = USER_AGENT
        # verify=False solo para labs con certificado autofirmado (--insecure).
        session.verify = verify_tls

        log.info("Descargando página: %s", url)
        got = _safe_get(session, url, result)
        if got is None:
            return result  # sin HTML no hay scripts que buscar
        final_url, result.html = got
        if not in_scope(final_url, target_host):
            # Una redirección puede sacarte del scope sin que te des cuenta.
            log.warning("La página redirigió fuera del host objetivo: %s", final_url)

        parser = ScriptCollector()
        parser.feed(result.html)

        for i, code in enumerate(parser.inline):
            result.js_files.append(JsFile(url=f"{final_url}#inline-{i}", content=code, inline=True))

        # urljoin resuelve rutas relativas ("/static/app.js", "../x.js",
        # "//cdn.com/x.js") respecto a la URL FINAL de la página.
        # dict.fromkeys = deduplicar conservando el orden.
        candidates = list(dict.fromkeys(urljoin(final_url, s) for s in parser.srcs))
        for js_url in candidates:
            if urlparse(js_url).scheme not in ("http", "https"):
                continue  # data:, blob:, javascript: -> no son descargables
            if not scope.allows(js_url):
                result.out_of_scope.append(js_url)
                log.debug("Fuera de scope, omitido: %s", js_url)
                continue
            if len(result.js_files) - len(parser.inline) >= max_js:
                log.warning("Alcanzado el máximo de %d ficheros JS", max_js)
                break

            log.info("Descargando JS: %s", js_url)
            got = _safe_get(session, js_url, result)
            if got is None:
                continue
            final_js_url, code = got
            if not scope.allows(final_js_url):
                # El .js estaba en scope pero redirigió a otro host: descartar.
                result.out_of_scope.append(final_js_url)
                continue
            result.js_files.append(JsFile(url=final_js_url, content=code))

    if result.out_of_scope:
        log.info("%d scripts de terceros omitidos (fuera de scope)", len(result.out_of_scope))
    return result
