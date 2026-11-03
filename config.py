"""Configuración central de js-recon.

POR QUÉ un único fichero de config: cualquier valor que quieras ajustar
(modelo, límites, timeouts) está en un solo sitio. Los módulos importan de
aquí en vez de repetir constantes, así un cambio no se queda a medias.
"""

from pathlib import Path

# --- Rutas ------------------------------------------------------------------
# Rutas absolutas basadas en la ubicación de ESTE fichero, no en el directorio
# desde el que lanzas el comando. Así output/ y .env se encuentran siempre.
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
ENV_FILE = BASE_DIR / ".env"

# --- Red (fetcher) ------------------------------------------------------------
# Tupla (connect, read): 5 s para abrir la conexión, 20 s entre bytes recibidos.
# Separarlos importa: un host caído falla rápido sin cortar descargas lentas.
REQUEST_TIMEOUT = (5, 20)
# Tope de .js a descargar: evita que una SPA con 500 chunks te tenga minutos
# lanzando peticiones (y haciendo ruido en el objetivo).
MAX_JS_FILES = 50
# Tope de tamaño por respuesta: protege la memoria frente a respuestas enormes
# o maliciosas (un "JS" de 2 GB). 5 MB cubre de sobra un bundle real.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
# User-Agent honesto: en un pentest autorizado conviene que los logs del
# cliente puedan identificar tu tráfico.
USER_AGENT = "js-recon/0.1 (authorized security testing)"

# --- Modo navegador (--browser) -----------------------------------------------
# Perfil propio de la herramienta (NO tu Chrome personal). Persiste entre
# ejecuciones para no tener que volver a iniciar sesión en la tienda; guarda
# cookies del objetivo, por eso está en .gitignore. --fresh-profile lo evita.
BROWSER_PROFILE_DIR = BASE_DIR / ".browser-profile"
# "chrome" = el Google Chrome instalado (no hace falta descargar Chromium). Si
# no está, se intenta el Chromium de Playwright ("playwright install chromium").
BROWSER_CHANNEL = "chrome"
# Navegando a mano se cargan muchos más .js que en una sola página (cada
# sección de la tienda trae sus chunks), así que el tope por defecto es mayor.
BROWSER_MAX_JS_FILES = 500

# --- Extractor ----------------------------------------------------------------
# Caracteres de contexto a cada lado de un hallazgo. En JS minificado todo es
# UNA línea, así que el contexto se mide en caracteres, no en líneas.
SNIPPET_CONTEXT_CHARS = 60
# Límite de hallazgos por fichero: un bundle con 5000 rutas no aporta más
# señal, solo ruido y tokens.
MAX_FINDINGS_PER_FILE = 300
# Entropía de Shannon mínima (bits/carácter) para aceptar un "secreto
# genérico" del tipo password = "...". "changeme" ≈ 2.75, una clave aleatoria
# ≈ 4-5. Filtra placeholders y reduce falsos positivos (= menos tokens).
GENERIC_SECRET_MIN_ENTROPY = 3.0

# --- IA (analyzer) ------------------------------------------------------------
# Alias cortos para la CLI -> ID exacto del modelo en la API.
MODELS = {
    "haiku": "claude-haiku-5-5",
    "opus": "claude-opus-5-5",
}
# Haiku por defecto: es ~40x más barato que Opus y clasificar hallazgos ya
# pre-filtrados es una tarea acotada. Cambia a "opus" aquí o con --model opus.
DEFAULT_MODEL = "haiku"

# Precio en USD por millón de tokens: (entrada, salida). Fuente: tabla de
# precios de Anthropic (oct-2026). Haiku 5.5 tiene este precio para prompts de
# hasta 100K tokens; nuestro tope (abajo) queda muy por debajo.
PRICING_USD_PER_MTOK = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-opus-5-5": (4.00, 20.00),
}

# Presupuesto máximo de tokens de ENTRADA por análisis. Si los hallazgos lo
# superan, se envían los más prioritarios y se avisa de lo omitido.
MAX_INPUT_TOKENS = 20_000
# Tope de tokens de SALIDA. Ojo: en estos modelos el razonamiento interno
# (thinking) también cuenta como salida, por eso no es un valor muy bajo.
MAX_OUTPUT_TOKENS = 8_000
# "effort" controla cuánto piensa el modelo (y cuánto gasta). "low" basta para
# clasificar; súbelo a "medium"/"high" si quieres un análisis más profundo.
EFFORT = "low"
# Enmascarar los secretos antes de enviarlos: el modelo puede razonar sobre el
# TIPO y el CONTEXTO sin ver la clave completa (minimización de datos).
MASK_SECRETS = True
# Timeout de la llamada a la API (segundos). El SDK reintenta 2 veces por
# defecto ante 429/5xx/errores de red.
API_TIMEOUT_SECONDS = 120.0

# --- Modo profundo (--deep): análisis del contenido COMPLETO de los .js -------
# Presupuesto de tokens de ENTRADA por petición. Empaquetamos varios ficheros
# en un mismo lote hasta este tope para amortizar el system prompt y la
# sobrecarga por petición. 120K deja holgura para la salida en el contexto de
# 1M y mantiene Haiku en su tramo de precio más barato (<=100K... lo superamos
# ligeramente a propósito; si quieres el precio mínimo, bájalo a 90_000).
DEEP_BATCH_TOKENS = 120_000
# Techo DURO de tokens de entrada para toda la ejecución profunda. Es la red de
# seguridad contra un coste disparado: si el total lo supera, se analizan los
# ficheros que quepan y se avisa del resto en vez de gastar sin límite.
DEEP_MAX_TOTAL_TOKENS = 1_000_000
# Si el coste estimado supera este umbral (USD), se pide confirmación antes de
# gastar (salvo --yes). El modo profundo puede costar dinero de verdad.
DEEP_CONFIRM_USD = 0.25
