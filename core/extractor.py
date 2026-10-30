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
    category: str  # "secret", "endpoint" o "version"
    kind: str  # tipo concreto: aws_access_key_id, jwt, endpoint_path, library...
    value: str  # el texto capturado (secreto completo, ruta o nombre@versión)
    source: str  # fichero/URL de origen
    line: int  # línea (1-based); en minificado casi siempre 1
    snippet: str  # contexto alrededor, para que un humano o la IA lo juzguen
    # Entorno del secreto: "test" (sandbox/pruebas), "live" (producción) o ""
    # (desconocido/no aplica). Es la señal más útil para priorizar: una clave
    # de test filtrada es ruido; una de producción es un incidente.
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
# Sobre el VALOR solo confiamos en marcadores ESTRUCTURALES del proveedor:
# Stripe (sk_test_/sk_live_), Braintree (sandbox_/production_). No valen
# subcadenas sueltas como "example" o "demo" dentro de una clave aleatoria:
# rebajarían la severidad de una clave real por coincidencia.
_VALUE_TEST_RE = re.compile(r"(?i)(?:_test_|\bsandbox_)")
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

    def add(category: str, kind: str, m: re.Match[str], group: int) -> None:
        value = m.group(group)
        key = (kind, value)
        if key in seen:  # el mismo secreto repetido 30 veces es 1 hallazgo
            return
        seen.add(key)
        start, end = m.span(group)
        line = bisect_right(newlines, start) + 1
        snippet = _snippet(text, start, end)
        # Solo los secretos tienen entorno; el contexto se mira sobre el snippet.
        env = classify_env(kind, value, snippet) if category == "secret" else ""
        findings.append(Finding(category, kind, value, source, line, snippet, env))

    for kind, pattern, group in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            add("secret", kind, m, group)

    for m in GENERIC_SECRET_RE.finditer(text):
        value = m.group(1)
        if PLACEHOLDER_RE.match(value) or shannon_entropy(value) < GENERIC_SECRET_MIN_ENTROPY:
            continue  # descartado aquí = tokens que no pagas después
        add("secret", "generic_secret", m, 1)

    for kind, pattern, group in VERSION_PATTERNS:
        for m in pattern.finditer(text):
            add("version", kind, m, group)

    for m in ENDPOINT_RE.finditer(text):
        value = m.group(1)
        if _is_interesting_endpoint(value):
            kind = "endpoint_url" if value.startswith("http") else "endpoint_path"
            add("endpoint", kind, m, 1)

    # Orden de prioridad para el recorte: secretos > versiones > endpoints.
    rank = {"secret": 0, "version": 1, "endpoint": 2}
    findings.sort(key=lambda f: rank.get(f.category, 3))
    return findings[:MAX_FINDINGS_PER_FILE]
