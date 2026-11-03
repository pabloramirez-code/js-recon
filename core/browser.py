"""Modo navegador (--browser): abre Chrome, TÚ navegas y se capturan los .js.

POR QUÉ un navegador real: las tiendas modernas cargan la mayoría de su JS
después del HTML inicial (chunks importados por otros .js, URLs construidas en
runtime, iframes como el checkout, secciones que solo existen tras iniciar
sesión o añadir algo al carrito). Ningún parser estático ve eso; el navegador
sí, porque es quien lo ejecuta.

Decisiones clave:
- No se lanza NINGUNA petición extra: solo se lee lo que el navegador ya
  descargó por tu navegación. El tráfico es el de una visita normal.
- El scope decide qué se ANALIZA, no qué carga el navegador (no podemos
  impedir que una web pida su CDN). Lo que queda fuera se registra en
  out_of_scope y no se guarda ni se manda a la IA.
- La lógica de captura (ScriptCapture) no importa Playwright: así se testea
  con respuestas falsas, sin abrir un navegador.
"""

import contextlib
import hashlib
import re
import tempfile
from pathlib import Path
from typing import Any

from config import BROWSER_CHANNEL, MAX_RESPONSE_BYTES
from core.fetcher import FetchResult, JsFile, Scope, ScriptCollector, validate_target
from utils.io import log

INSTALL_HINT = "instala el modo navegador con: python -m uv sync --extra browser"
# Los <link rel=prefetch> de chunks llegan con resource_type "other", y algunos
# loaders piden el JS por fetch/xhr: los aceptamos si la ruta acaba en .js/.mjs.
_JS_PATH = re.compile(r"\.m?js$", re.IGNORECASE)
_CHARSET = re.compile(r"charset=[\"']?([\w.:-]+)", re.IGNORECASE)


def _decode(body: bytes, content_type: str) -> str:
    """bytes -> texto con el charset de la cabecera (utf-8 si no hay o es raro)."""
    m = _CHARSET.search(content_type or "")
    try:
        return body.decode(m.group(1) if m else "utf-8", errors="replace")
    except LookupError:  # charset inventado o desconocido
        return body.decode("utf-8", errors="replace")


class ScriptCapture:
    """Acumula los scripts que ve el navegador en un FetchResult.

    Deduplica por CONTENIDO (sha256), no por URL: las tiendas versionan con
    ?v=123 y el mismo fichero llega con URLs distintas en cada página.
    """

    def __init__(self, page_url: str, scope: Scope, max_js: int) -> None:
        self.result = FetchResult(page_url=page_url)
        self.scope = scope
        self.max_js = max_js
        self.skipped_by_limit = 0
        self._external = 0  # ficheros externos guardados (los inline no cuentan)
        self._hashes: set[str] = set()
        self._seen_urls: set[str] = set()
        self._oos: set[str] = set()

    # --- entrada desde Playwright --------------------------------------------
    def on_response(self, response: Any) -> None:
        """Handler de context.on("response"). Nunca lanza: un fallo en una
        respuesta no debe cortar la captura del resto de la navegación."""
        try:
            self._handle(response)
        except Exception as e:  # cualquier fallo -> se registra y se sigue
            self._error(f"{getattr(response, 'url', '?')}: {type(e).__name__}: {e}")

    def _handle(self, response: Any) -> None:
        url: str = response.url
        if not url.startswith(("http://", "https://")):
            return  # data:, blob:, chrome-extension:...
        rtype = response.request.resource_type
        is_doc = rtype == "document"
        is_js = rtype == "script" or (
            rtype in ("other", "fetch", "xhr") and _JS_PATH.search(url.split("?", 1)[0])
        )
        if not (is_doc or is_js):
            return
        if not 200 <= response.status < 300:
            return  # redirecciones (su destino llega como otra respuesta) y errores
        if not self.scope.allows(url):
            if is_js and url not in self._oos:
                self._oos.add(url)
                self.result.out_of_scope.append(url)
            return
        if url in self._seen_urls:
            return
        self._seen_urls.add(url)

        body: bytes = response.body()
        if len(body) > MAX_RESPONSE_BYTES:
            self._error(f"{url}: respuesta > {MAX_RESPONSE_BYTES} bytes, descartada")
            return
        text = _decode(body, response.headers.get("content-type", ""))
        if is_doc:
            self.add_document(url, text)
        else:
            self.add_script(url, text)

    # --- lógica pura (testeable) ---------------------------------------------
    def add_script(self, url: str, content: str) -> bool:
        """Guarda un .js externo. Devuelve True si era nuevo."""
        if not self._is_new(content):
            return False
        if self._external >= self.max_js:
            if self.skipped_by_limit == 0:
                log.warning("Alcanzado el máximo de %d ficheros JS (--max-js)", self.max_js)
            self.skipped_by_limit += 1
            return False
        self._external += 1
        self.result.js_files.append(JsFile(url=url, content=content))
        log.info("[+] %s (%d capturados)", url, self._external)
        return True

    def add_document(self, url: str, html: str) -> None:
        """Una página (o iframe) en scope: se extraen sus <script> inline."""
        if not self.result.html:
            self.result.html = html  # primera página en scope = "la página"
        parser = ScriptCollector()
        parser.feed(html)
        for i, code in enumerate(parser.inline):
            if self._is_new(code):
                self.result.js_files.append(
                    JsFile(url=f"{url}#inline-{i}", content=code, inline=True)
                )

    def _is_new(self, content: str) -> bool:
        h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        if h in self._hashes:
            return False
        self._hashes.add(h)
        return True

    def _error(self, msg: str) -> None:
        log.warning(msg)
        self.result.errors.append(msg)


def capture_with_browser(
    url: str,
    scope: Scope,
    *,
    max_js: int,
    profile_dir: Path,
    fresh_profile: bool = False,
    verify_tls: bool = True,
) -> FetchResult:
    """Abre Chrome en `url` y captura los .js hasta que cierres el navegador
    (o pulses Ctrl+C). Lanza RuntimeError si Playwright no está instalado."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as e:  # dependencia opcional
        raise RuntimeError(f"Playwright no está instalado: {INSTALL_HINT}") from e

    url = validate_target(url)
    capture = ScriptCapture(url, scope, max_js)
    # Perfil temporal: se borra al salir del with (nada del objetivo queda en disco).
    # ignore_cleanup_errors: en Windows Chrome puede tardar en soltar ficheros.
    tmp = (
        tempfile.TemporaryDirectory(prefix="js-recon-profile-", ignore_cleanup_errors=True)
        if fresh_profile
        else None
    )
    user_data = Path(tmp.name) if tmp else profile_dir

    try:
        with sync_playwright() as p:

            def launch(channel: str | None) -> Any:
                return p.chromium.launch_persistent_context(
                    str(user_data),
                    channel=channel,
                    headless=False,
                    no_viewport=True,  # la ventana se redimensiona como un Chrome normal
                    ignore_https_errors=not verify_tls,
                )

            try:
                ctx = launch(BROWSER_CHANNEL)
            except PlaywrightError:
                log.warning(
                    "No se pudo abrir Google Chrome; probando el Chromium de Playwright "
                    "(si falla: python -m uv run playwright install chromium)"
                )
                ctx = launch(None)

            # A nivel de CONTEXTO: cubre todas las pestañas y los iframes,
            # también las pestañas que abras tú durante la navegación.
            ctx.on("response", capture.on_response)
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            try:
                page.goto(url, wait_until="domcontentloaded")
            except PlaywrightError as e:
                # No es fatal: el usuario puede navegar a mano desde la ventana.
                capture._error(f"no se pudo abrir {url}: {e.message.splitlines()[0]}")

            log.info("Navega por la web. Cuando termines, CIERRA el navegador o pulsa Ctrl+C.")
            try:
                # timeout=0: sin límite, la sesión dura lo que tú navegues.
                ctx.wait_for_event("close", timeout=0)
            except KeyboardInterrupt:
                log.info("Ctrl+C: se termina la captura")
            except PlaywrightError:
                pass  # el navegador murió (p. ej. por el propio Ctrl+C): ya tenemos lo capturado
            with contextlib.suppress(PlaywrightError, KeyboardInterrupt):
                ctx.close()
    except KeyboardInterrupt:
        # Ctrl+C justo al arrancar o al cerrar: lo capturado sigue en memoria.
        log.info("Ctrl+C: se termina la captura")
    finally:
        if tmp:
            tmp.cleanup()

    r = capture.result
    log.info(
        "Captura terminada: %d .js externos, %d inline, %d fuera de scope",
        sum(not j.inline for j in r.js_files),
        sum(j.inline for j in r.js_files),
        len(r.out_of_scope),
    )
    if capture.skipped_by_limit:
        log.warning("%d .js no guardados por el límite --max-js", capture.skipped_by_limit)
    return r
