"""Pre-filtro con regex: endpoints y posibles secretos en código JavaScript.

POR QUÉ un pre-filtro antes de la IA: un bundle de 2 MB son ~600K tokens.
Mandarlo entero a un LLM es caro y lento. Las regex son gratis, deterministas
y reducen ese bundle a unas decenas de líneas sospechosas. La IA (opcional)
solo razona sobre ese resto.

Reglas de diseño de las regex:
1. Cuantificadores ACOTADOS ({8,200}) y sin cuantificadores anidados como
   (a+)+. Así se evita el ReDoS (backtracking catastrófico): el JS lo controla
   el objetivo, y una regex mal hecha podría colgar la herramienta.
2. La función nunca lanza ante entradas raras (vacío, binario, gigantes):
   eso es justo lo que verifican los tests de property-based testing.
"""

import math
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import asdict, dataclass

from config import GENERIC_SECRET_MIN_ENTROPY, MAX_FINDINGS_PER_FILE, SNIPPET_CONTEXT_CHARS


@dataclass(frozen=True)  # frozen: inmutable y hashable (sirve para deduplicar)
class Finding:
    category: str  # "secret", "logic", "version", "dom" o "endpoint"
    kind: str  # tipo concreto: aws_access_key_id, payment_method, dom_sink, endpoint_path...
    value: str  # el texto capturado (secreto completo, ruta o nombre@versión)
    source: str  # fichero/URL de origen
    line: int  # línea (1-based); en minificado casi siempre 1
    snippet: str  # contexto alrededor, para que un humano o la IA lo juzguen
    # Entorno: "test" (sandbox/pruebas), "live" (producción) o "" (desconocido/no
    # aplica). En secretos prioriza: una clave de test filtrada es ruido; una de
    # producción es un incidente. En lógica (pagos) marca un modo test expuesto.
    env: str = ""

    @property
    def masked(self) -> str:
        return mask_secret(self.value) if self.category == "secret" else self.value

    def to_dict(self) -> dict:
        return {**asdict(self), "masked": self.masked}


# --- Patrones de secretos -----------------------------------------------------
# (nombre, regex, grupo_a_capturar). Grupo 0 = todo el match.
# Los prefijos fijos (AKIA, ghp_, sk_live_...) hacen que sean muy precisos.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), 0),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}"), 0),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,200}"), 0),
    # Stripe: distinguimos clave secreta (sk/rk) de la publicable (pk, pensada
    # para ir en el frontend) y, dentro de cada una, test vs live. La parte
    # _(live|test)_ la lee classify_env() para marcar el entorno.
    ("stripe_secret_key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,99}\b"), 0),
    ("stripe_publishable_key", re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{16,99}\b"), 0),
    # PayPal/Braintree y SendGrid también codifican el entorno en la clave.
    (
        "braintree_token",
        re.compile(r"\b(?:sandbox|production)_[0-9a-z]{8,32}_[0-9a-z]{16,64}\b"),
        0,
    ),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,66}\.[A-Za-z0-9_-]{20,66}"), 0),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,200}"), 0),
    ("openai_api_key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,200}"), 0),
    # JWT: header.payload.firma; los dos primeros empiezan por "eyJ" ('{"' en
    # base64). Firma {0,...}: un JWT con alg "none" no lleva firma (¡hallazgo!).
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{0,2000}"),
        0,
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
        0,
    ),
    ("bearer_token", re.compile(r"\bBearer\s{1,5}([A-Za-z0-9._~+/-]{20,500}={0,2})"), 1),
    # Credenciales embebidas en URL: https://usuario:contraseña@host
    (
        "url_credentials",
        re.compile(r"\bhttps?://[^\s/:@\"'`]{1,100}:[^\s/@\"'`]{1,100}@[\w.-]{1,200}"),
        0,
    ),
]

# Secreto "genérico": nombre de variable sospechoso + valor entre comillas.
# Es el patrón con más falsos positivos, por eso se filtra luego por entropía.
# \w{0,30}? admite un prefijo en el nombre (s3secret, dbPassword, mySecretKey);
# acotado a 30 para no abrir la puerta al backtracking.
GENERIC_SECRET_RE = re.compile(
    r"""(?i)\b\w{0,30}?(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token"""
    r"""|auth[_-]?token|private[_-]?key|password|passwd|pwd)\b["']?\s{0,5}[:=]\s{0,5}"""
    r"""["'`]([^"'`\s]{8,200})["'`]"""
)

# --- Patrones de endpoints ----------------------------------------------------
# Cadenas entre comillas que empiezan por http(s):// o por "/".
ENDPOINT_RE = re.compile(
    r"""["'`](https?://[^\s"'`<>\\]{3,400}|/[A-Za-z0-9_.~%/?=&:+@!$,;{}-]{1,400})["'`]"""
)
# Recursos estáticos: no son superficie de ataque interesante, solo ruido.
STATIC_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map|mp4|mp3)(?:[?#]|$)", re.I
)
# Valores típicos de ejemplo que no son secretos reales.
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|your[_-]|<|\$\{|\{\{|process\.env|example|changeme|placeholder|undefined|null)"
)

# --- Clasificación de entorno (test vs producción) ----------------------------
_VALUE_TEST_RE = re.compile(
    r"(?i)(?:_test_|"
    r"\bsandbox_|"
    r"\w*test\w*|"
    r"\w*sandbox\w*)"
)
_VALUE_LIVE_RE = re.compile(r"(?i)(?:_live_|\bproduction_)")
# Sobre el CONTEXTO (nombre de variable, comentario cercano) sí admitimos más
# palabras, pero con \b para que "stripeLive" o "latest" no cuenten como "live".
_CTX_TEST_RE = re.compile(r"(?i)\b(?:test|sandbox|staging|dev|demo|example)\b")
_CTX_LIVE_RE = re.compile(r"(?i)\b(?:live|production|prod)\b")


def classify_env(kind: str, value: str, snippet: str) -> str:
    """Devuelve "test", "live" o "" para un secreto.

    POR QUÉ: separar riesgo. Una 'sk_test_...' de Stripe no mueve dinero real;
    una 'sk_live_...' sí. El prefijo de la clave (test/live) es intencional del
    proveedor y manda sobre todo. Si la clave no lo dice, el contexto cercano
    solo desempata cuando es inequívoco. Ante la duda, "" (desconocido):
    preferimos NO tocar la severidad sin estar seguros.
    """
    if _VALUE_LIVE_RE.search(value):
        return "live"
    if _VALUE_TEST_RE.search(value):
        return "test"
    in_test, in_live = bool(_CTX_TEST_RE.search(snippet)), bool(_CTX_LIVE_RE.search(snippet))
    if in_test and not in_live:
        return "test"
    if in_live and not in_test:
        return "live"
    return ""


# --- Patrones de versiones / tecnologías --------------------------------------
# POR QUÉ: saber QUÉ librería y QUÉ versión corre el objetivo permite cruzarlo
# con CVEs conocidos (p. ej. jQuery < 3.5 tiene XSS). La IA razona sobre esto.
VERSION_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    # Librería servida desde CDN con versión en la URL:
    # cdn.jsdelivr.net/npm/vue@2.6.14, unpkg.com/react@17.0.2, .../jquery@3.4.1
    (
        "cdn_library",
        re.compile(r"(?:/npm/|unpkg\.com/|/ajax/libs/)([@\w./-]{2,60}@[0-9][\w.-]{1,30})"),
        1,
    ),
    # cdnjs usa ruta en vez de @: /ajax/libs/jquery/3.4.1/jquery.min.js
    ("cdnjs_library", re.compile(r"/ajax/libs/([a-zA-Z0-9._-]{2,40}/[0-9][\w.-]{1,30})"), 1),
    # Banner típico que las librerías dejan en claro: "jQuery v3.6.0",
    # "Bootstrap v4.5.2", "AngularJS v1.5.8", "Vue.js v2.6.14".
    (
        "library_banner",
        re.compile(
            r"(?i)\b(jquery|bootstrap|angular(?:js)?|vue(?:\.js)?|react|lodash|moment|"
            r"d3|ember|backbone|axios)(?:\.js)?\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
        ),
        0,
    ),
    # Asignación de versión genérica: version: "1.2.3" / "version":"1.2.3"
    (
        "declared_version",
        re.compile(
            r"""(?i)\bversion["']?\s{0,3}[:=]\s{0,3}["']([0-9]+\.[0-9]+(?:\.[0-9]+)?)["']"""
        ),
        1,
    ),
    # Source map referenciado: si está publicado, expone el código original.
    ("source_map", re.compile(r"sourceMappingURL=([^\s*]{1,200}\.map)"), 1),
]

# --- Lógica de negocio (category "logic") ---------------------------------------
# POR QUÉ: en una tienda lo más jugoso para un pentest no siempre es una clave,
# sino la LÓGICA que el frontend revela: qué métodos de pago existen (¿hay uno
# de test activo en producción?), qué reglas de precio o pedido mínimo se
# comprueban solo en el navegador, qué flags habilitan/bloquean cosas, qué
# parámetros espera el servidor. Todo eso es lo que luego se manipula en Burp.
_PAY = (
    r"stripe|paypal|bizum|redsys|braintree|adyen|klarna|mollie|sumup|mercadopago|razorpay"
    r"|paycomet|sequra|aplazame|apple_?pay|google_?pay|tpv|cash_?on_?delivery"
    r"|contra_?reembolso|transferencia|bank_?transfer|in_store|cash"
)
# Inicio de identificador: el patrón solo arranca al PRINCIPIO de "a.b.c", no
# en cada carácter de dentro. Sin esto, [\w$.]{0,40} se reintenta desde cada
# posición y el extractor va ~3 veces más lento en bundles grandes.
_ID = r"(?<![\w$.])"
LOGIC_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    # Literal con nombre de pasarela/método: 'stripe_test', 'bizum', 'tpv'...
    ("payment_method", re.compile(rf"""(?i)["'`]([\w-]{{0,25}}(?:{_PAY})[\w-]{{0,25}})["'`]"""), 1),
    # Literales de modo test/sandbox/debug: 'test_mode', 'sandbox', 'preprod'.
    (
        "test_mode",
        re.compile(
            r"""(?i)["'`]([\w-]{0,30}(?:[_-]test\b|\btest[_-]|sandbox|staging|preprod"""
            r"""|debug[_-]?mode|test[_-]?mode|dev[_-]?mode)[\w-]{0,30})["'`]"""
        ),
        1,
    ),
    # Flags de debug/test activados: debug: true, testMode=!0, isDev = "true".
    (
        "debug_flag",
        re.compile(
            r"""\b(?:testMode|test_mode|isTest|isSandbox|sandboxMode|debugMode|debug|DEBUG"""
            r"""|isDev|devMode|isStaging)\s{0,3}[:=]\s{0,3}(?:!0\b|true\b|1\b|["']true["'])"""
        ),
        0,
    ),
    # Parámetros que el cliente manda (body.set('x'), FormData.append('x'),
    # input[name="_csrf"]) o lee de la URL (searchParams.get('next')).
    ("request_param", re.compile(r"""\.(?:set|append)\(\s{0,3}["'`]([\w\[\].-]{1,60})["'`]"""), 1),
    ("request_param", re.compile(r"""\bname=\\?["']([\w\[\].-]{1,60})\\?["']"""), 1),
    (
        "url_param",
        re.compile(r"""(?:searchParams|params|query)\.get\(\s{0,3}["'`]([\w\[\].-]{1,60})["'`]"""),
        1,
    ),
    # Comentarios de desarrollador que sobreviven en el JS servido.
    (
        "dev_comment",
        re.compile(r"(?<![:\w\"'\\/])//[ \t]{0,5}((?:TODO|FIXME|HACK|XXX|BUG|TEMP)\b[^\n]{0,150})"),
        1,
    ),
    (
        "dev_comment",
        re.compile(
            # Sin "password": los comentarios de validación de formularios lo
            # mencionan todo el rato. Esto busca intenciones, no campos.
            r"(?i)(?<![:\w\"'\\/])//([^\n]{0,80}\b(?:hardcode\w{0,3}|bypass"
            r"|backdoor|temporal|no usar|insecure|inseguro|quitar|remove before)\b[^\n]{0,80})"
        ),
        1,
    ),
    # Hosts internos o de pre-producción referenciados desde el frontend.
    (
        "internal_host",
        re.compile(
            r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
            r"(?::\d{2,5})?\b"
        ),
        0,
    ),
    (
        "internal_host",
        re.compile(
            r"(?i)\bhttps?://((?:dev|staging|stg|test|qa|uat|preprod|sandbox|internal|intranet)"
            r"[\w-]{0,20}\.[\w.-]{2,100})"
        ),
        1,
    ),
    (
        "internal_host",
        re.compile(
            r"""["'`/@]([\w-]{1,60}(?:\.[\w-]{1,60}){0,4}\.(?:local|internal|corp|lan))(?![\w.-])"""
        ),
        1,
    ),
]

# --- Comparaciones y asignaciones: una sola pasada, clasificadas en Python ------
# POR QUÉ no una regex por tipo: con cuatro patrones del estilo
# "[\w$.]{0,40}(?:role|admin|...)" el motor prueba cada palabra clave en cada
# posición de cada identificador, y el extractor iba 3 veces más lento en
# bundles grandes. Aquí UNA regex encuentra "identificador op valor" y la
# clasificación por palabra clave se hace sobre el lado izquierdo, ya aislado.
_TYPEOF = r"(?!(?:string|number|undefined|object|function|boolean|bigint|symbol)[\"'`])"
COMPARISON_RE = re.compile(
    rf"""{_ID}(?P<lhs>[\w$.]{{1,80}})\s{{0,3}}(?P<op>[!=]==?|[<>]=?|=(?![=>]))\s{{0,3}}"""
    rf"""(?P<rhs>Math\.\w{{2,10}}\([^;\n]{{0,100}}|-?\d[\d.]{{0,12}}\b"""
    rf"""|["'`]{_TYPEOF}(?P<lit>[\w-]{{1,40}})["'`]|true\b|false\b|!0\b|!1\b)"""
)
# Palabras clave sobre el lado izquierdo (ya aislado: buscar aquí es barato).
_PAY_VAR_RE = re.compile(r"(?i)payment|gateway|pago")  # "method" a secas no: method == 'track'
_ROLE_VAR_RE = re.compile(
    r"(?i)role|admin|staff|superuser|permission|privilege|access_?level|user_?type"
    r"|is_?premium|is_?vip|subscription|tier"
)
_RULE_VAR_RE = re.compile(
    r"(?i)price|precio|total|subtotal|amount|importe|fee|discount|descuento|coupon|cupon"
    r"|promo|voucher|cents|minimum|minimo|stock|quantity|cantidad"
)


def _classify_comparison(m: re.Match[str]) -> list[tuple[str, int | str]]:
    """Devuelve [(kind, grupo_del_valor)] para una comparación/asignación.

    - client_check: flag de texto comparado con 'true'/'false'
      (dataset.stripeAvailable === 'true': si el servidor no lo repite, basta
      con cambiar el atributo en el DOM).
    - payment_method: variable de pago comparada/asignada a un literal
      (paymentMethod === 'card'); el valor es el literal.
    - role_check: autorización decidida en el frontend (role === 'admin').
    - business_rule: precios, mínimos, envíos, cupones (subtotal >= 2500).
    """
    lhs, op, rhs, lit = m["lhs"], m["op"], m["rhs"], m["lit"]
    is_cmp = op not in ("=", "<", ">", "<=", ">=")
    is_bool = rhs in ("true", "false", "!0", "!1")
    out: list[tuple[str, int | str]] = []
    if is_cmp and lit in ("true", "false"):
        out.append(("client_check", 0))
    if lit and _PAY_VAR_RE.search(lhs) and op in ("=", "==", "===", "!=", "!=="):
        out.append(("payment_method", "lit"))
    if is_cmp and (lit or is_bool) and _ROLE_VAR_RE.search(lhs):
        out.append(("role_check", 0))
    if not is_bool and lit not in ("true", "false") and _RULE_VAR_RE.search(lhs):
        out.append(("business_rule", 0))
    return out


# --- DOM: sinks y fuentes de XSS en cliente (category "dom") --------------------
# Un sink (innerHTML, eval...) alimentado por una fuente que controla el
# atacante (location.hash, document.referrer, postMessage) = posible DOM XSS.
# Se captura el lado derecho para que cada asignación distinta sea un hallazgo.
DOM_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("dom_sink", re.compile(r"\b(?:innerHTML|outerHTML)\s{0,3}\+?=(?!=)\s{0,3}[^;\n]{1,80}"), 0),
    ("dom_sink", re.compile(r"\binsertAdjacentHTML\(\s{0,3}[^;\n]{1,80}"), 0),
    ("dom_sink", re.compile(r"\bdocument\.write(?:ln)?\(\s{0,3}[^;\n]{1,80}"), 0),
    ("dom_sink", re.compile(r"(?<![\w$.])eval\(\s{0,3}[^;\n]{1,80}"), 0),
    ("dom_sink", re.compile(r"\bnew Function\(\s{0,3}[^;\n]{0,80}"), 0),
    ("dom_sink", re.compile(r"\bset(?:Timeout|Interval)\(\s{0,3}[\"'`][^;\n]{0,80}"), 0),
    ("dom_sink", re.compile(r"\bdangerouslySetInnerHTML\b|\bv-html="), 0),
    ("dom_sink", re.compile(r"\.html\(\s{0,3}[^)\s][^;\n]{0,80}"), 0),  # jQuery .html(x)
    # Asignar location: open redirect, o XSS con "javascript:".
    (
        "redirect_sink",
        re.compile(
            r"\b(?:window\.|document\.)?location(?:\.href)?\s{0,3}=(?!=)\s{0,3}[^;\n]{1,80}"
        ),
        0,
    ),
    (
        "dom_source",
        re.compile(
            r"\b(?:location\.(?:hash|search)|document\.(?:referrer|URL|documentURI|cookie)"
            r"|window\.name)\b"
        ),
        0,
    ),
    ("postmessage", re.compile(r"""addEventListener\(\s{0,3}["'`]message["'`]"""), 0),
    ("postmessage", re.compile(r"""\.postMessage\([^;\n]{0,150},\s{0,3}["'`]\*["'`]"""), 0),
]

# Entorno de un hallazgo de lógica: más estricto que _VALUE_TEST_RE (que
# acepta "latest" como test). Aquí la palabra tiene que ir separada por _ o -.
_LOGIC_TEST_RE = re.compile(r"(?i)(?:^|[_-])(?:test|sandbox|staging|demo|preprod)(?:$|[_-])")
_LOGIC_LIVE_RE = re.compile(r"(?i)(?:^|[_-])(?:live|prod|production)(?:$|[_-])")
_LOGIC_ENV_KINDS = {"payment_method", "test_mode"}


def _logic_env(kind: str, value: str) -> str:
    """'stripe_test' -> "test". Para la lógica, "test" NO rebaja el riesgo:
    un método de pago de test aceptado en producción permite pedir sin pagar."""
    if kind not in _LOGIC_ENV_KINDS:
        return ""
    if _LOGIC_TEST_RE.search(value):
        return "test"
    if _LOGIC_LIVE_RE.search(value):
        return "live"
    return ""


def shannon_entropy(s: str) -> float:
    """Bits de información por carácter.

    POR QUÉ: un secreto real es aleatorio (entropía alta); "password123" o
    "xxxxxxxx" no. H = -Σ p(c)·log2 p(c). Cadena vacía -> 0.
    """
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def mask_secret(value: str) -> str:
    """Deja ver 4 caracteres a cada lado y oculta el resto (misma longitud).

    Mantener la longitud y los extremos permite reconocer el TIPO de secreto
    (AKIA..., sk_live_...) sin exponer el valor utilizable.
    Valores cortos (<= 8) se ocultan enteros: mostrar 8 de 8 sería no ocultar.
    """
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _line_index(text: str) -> list[int]:
    """Posiciones de cada '\\n'. Permite calcular el nº de línea con
    búsqueda binaria (O(log n)) en vez de contar saltos por cada hallazgo."""
    return [i for i, ch in enumerate(text) if ch == "\n"]


def _snippet(text: str, start: int, end: int) -> str:
    a = max(0, start - SNIPPET_CONTEXT_CHARS)
    b = min(len(text), end + SNIPPET_CONTEXT_CHARS)
    # Colapsar espacios/saltos: el snippet ocupa una línea y gasta menos tokens.
    return re.sub(r"\s+", " ", text[a:b]).strip()


def _is_interesting_endpoint(value: str) -> bool:
    if value in ("/", "//") or len(value) < 2:
        return False
    if STATIC_EXT.search(value):
        return False
    # "/" seguido solo de signos (p. ej. regex "/=/") no es una ruta.
    return any(ch.isalnum() for ch in value)


def extract(text: str, source: str = "<memory>") -> list[Finding]:
    """Devuelve los hallazgos de un texto JS: primero secretos, luego endpoints.

    Garantías (verificadas en tests): nunca lanza para cualquier str; cada
    `value` es un substring literal de `text`; sin duplicados; como mucho
    MAX_FINDINGS_PER_FILE resultados.
    """
    if not text:
        return []
    newlines = _line_index(text)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(category: str, kind: str, m: re.Match[str], group: int | str) -> None:
        value = m.group(group)
        key = (kind, value)
        if key in seen:  # el mismo secreto repetido 30 veces es 1 hallazgo
            return
        seen.add(key)
        start, end = m.span(group)
        line = bisect_right(newlines, start) + 1
        snippet = _snippet(text, start, end)
        # Entorno: secretos (por clave y contexto) y pagos/modos de la lógica.
        if category == "secret":
            env = classify_env(kind, value, snippet)
        elif category == "logic":
            env = _logic_env(kind, value)
        else:
            env = ""
        findings.append(Finding(category, kind, value, source, line, snippet, env))

    for kind, pattern, group in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            add("secret", kind, m, group)

    for m in GENERIC_SECRET_RE.finditer(text):
        value = m.group(1)
        if PLACEHOLDER_RE.match(value) or shannon_entropy(value) < GENERIC_SECRET_MIN_ENTROPY:
            continue  # descartado aquí = tokens que no pagas después
        add("secret", "generic_secret", m, 1)

    for kind, pattern, group in LOGIC_PATTERNS:
        for m in pattern.finditer(text):
            # 'stripe_test' ya sale como payment_method: no repetirlo como test_mode.
            if kind == "test_mode" and ("payment_method", m.group(group)) in seen:
                continue
            add("logic", kind, m, group)

    for m in COMPARISON_RE.finditer(text):
        for kind, group in _classify_comparison(m):
            add("logic", kind, m, group)

    for kind, pattern, group in VERSION_PATTERNS:
        for m in pattern.finditer(text):
            add("version", kind, m, group)

    for kind, pattern, group in DOM_PATTERNS:
        for m in pattern.finditer(text):
            add("dom", kind, m, group)

    for m in ENDPOINT_RE.finditer(text):
        value = m.group(1)
        if _is_interesting_endpoint(value):
            kind = "endpoint_url" if value.startswith("http") else "endpoint_path"
            add("endpoint", kind, m, 1)

    # Orden de prioridad para el recorte: secretos > lógica > versiones > DOM > endpoints.
    rank = {"secret": 0, "logic": 1, "version": 2, "dom": 3, "endpoint": 4}
    findings.sort(key=lambda f: rank.get(f.category, 3))
    return findings[:MAX_FINDINGS_PER_FILE]
