# js-recon — Manual de uso

Herramienta de reconocimiento para pentest web **autorizado**: descarga los
archivos JavaScript de una URL, extrae endpoints y posibles secretos con regex
(pre-filtro gratuito y local) y, opcionalmente, envía solo los fragmentos
sospechosos a la API de Claude para un análisis razonado.

> Úsala únicamente contra objetivos para los que tengas autorización por
> escrito: tu laboratorio, plataformas de práctica o un engagement con scope
> firmado. Ver [Comprobación de scope](#2-comprobación-de-scope).

---

## Índice

1. [Instalación](#1-instalación)
2. [Comprobación de scope](#2-comprobación-de-scope)
3. [Uso rápido](#3-uso-rápido)
4. [Opciones de la CLI](#4-opciones-de-la-cli)
4b. [Modo navegador (`--browser`)](#4b-modo-navegador---browser)
5. [Qué hace por dentro](#5-qué-hace-por-dentro)
6. [Interpretar los resultados](#6-interpretar-los-resultados)
7. [Coste de la IA](#7-coste-de-la-ia)
8. [Configuración avanzada](#8-configuración-avanzada)
9. [Escenarios típicos](#9-escenarios-típicos)
10. [Solución de problemas](#10-solución-de-problemas)
11. [Limitaciones conocidas](#11-limitaciones-conocidas)
12. [Tests y desarrollo](#12-tests-y-desarrollo)

---

## 1. Instalación

**Requisitos:** Python 3.12+, [uv](https://docs.astral.sh/uv/), y una API key
de Anthropic solo si vas a usar el análisis con IA.

```powershell
# 1. Instalar uv si no lo tienes
python -m pip install --user uv

# 2. Entrar en el proyecto e instalar dependencias (crea .venv automáticamente)
cd "C:\Users\Usuario\Desktop\Prácticas\js-recon"
python -m uv sync

# 3. Configurar la API key (solo para el análisis con IA)
copy .env.example .env
notepad .env        # escribe: ANTHROPIC_API_KEY=sk-ant-...
```

**Modo navegador (opcional):** instala Playwright solo si vas a usar
`--browser` (ver §4b). Usa tu Google Chrome instalado, no descarga Chromium:

```powershell
python -m uv sync --extra browser
```

> Si `uv` está en tu PATH, puedes escribir `uv` en vez de `python -m uv` en
> todos los comandos.

**Sobre `.env`:** está en `.gitignore` y nunca debe subirse a git. La clave no
aparece en el código, los logs ni los informes. Si la expones, revócala en la
consola de Anthropic y genera otra.

Comprobar que todo funciona:

```powershell
python -m uv run python main.py --help
python -m uv run pytest -q          # todos los tests deben pasar
```

---

## 2. Comprobación de scope

La herramienta te preguntará si el objetivo está en scope antes de lanzar
tráfico. No respondas por inercia; comprueba esto primero:

- El **host exacto** está en tu autorización. `app.ejemplo.com` en scope no
  implica `api.ejemplo.com` ni `cdn.ejemplo.com`.
- El **puerto** también está incluido (`:8443` puede ser otro servicio).
- Estás dentro de la **ventana horaria** autorizada, si la hay.
- Para `--include-third-party`: todos esos hosts externos están en scope
  (normalmente los CDNs y analytics **no** lo están).
- Para la IA: el engagement permite enviar datos del objetivo (aunque vayan
  enmascarados) a un servicio externo.

Por defecto, js-recon solo descarga JS del **mismo host y puerto** que la URL
que le das, y descarta cualquier script que redirija a otro host.

---

## 3. Uso rápido

Ejecuta siempre desde la carpeta del proyecto:

```powershell
cd "C:\Users\Usuario\Desktop\Prácticas\js-recon"

# Solo pre-filtro regex: sin API, coste 0. Empieza siempre por aquí.
python -m uv run python main.py https://mi-lab.local/ --no-ai

# Estima el coste en tokens sin llamar al modelo
python -m uv run python main.py https://mi-lab.local/ --dry-run

# Análisis con Claude Haiku (barato, por defecto)
python -m uv run python main.py https://mi-lab.local/

# Análisis más profundo con Claude Opus
python -m uv run python main.py https://mi-lab.local/ --model opus

# Laboratorio con certificado autofirmado
python -m uv run python main.py https://10.0.0.5:8443/ --insecure --no-ai
```

La herramienta pide confirmación del scope cada vez. Responde `s` para
continuar.

---

## 4. Opciones de la CLI

```
usage: js-recon [-h] [--no-ai] [--deep] [--model {haiku,opus}] [--dry-run]
                [--include-third-party] [--allow-host HOST]
                [--scope-subdomains] [--browser] [--fresh-profile]
                [--insecure] [--max-js MAX_JS] [-y] [-v] url
```

| Opción | Para qué sirve |
|---|---|
| `url` | URL objetivo (`http://` o `https://`). Argumento obligatorio. |
| `--no-ai` | Solo pre-filtro regex, sin llamar a la API. Coste 0. |
| `--deep` | Análisis profundo: manda el **código completo** de los `.js` a la IA (ver §7b). Más caro; pide confirmación de coste. |
| `--model {haiku,opus}` | Modelo para el análisis. Por defecto `haiku`. |
| `--dry-run` | Cuenta tokens y estima coste, pero no llama al modelo. |
| `--include-third-party` | Analiza también JS de **cualquier** otro host. Solo si están en scope. |
| `--allow-host HOST` | Analiza también los JS de ese host (p. ej. `cdn.tienda.com`). Se puede repetir. |
| `--scope-subdomains` | Analiza también el dominio base y sus subdominios: con `www.tienda.com` acepta `tienda.com` y `*.tienda.com`. |
| `--browser` | Abre Chrome, navegas tú y se capturan todos los `.js` que cargue la web (ver §4b). |
| `--fresh-profile` | Con `--browser`: perfil temporal limpio, sin cookies ni sesiones previas. |
| `--insecure` | No verifica el certificado TLS (labs autofirmados). |
| `--max-js MAX_JS` | Máximo de ficheros JS (por defecto 50; 500 con `--browser`). |
| `-y`, `--yes` | Confirma el scope sin preguntar. Solo para scripts. |
| `-v`, `--verbose` | Logs de depuración. |

> `--yes` existe para automatizar en scripts o CI. No lo uses de forma
> interactiva para saltarte la pregunta de scope.

**Código de salida:** `0` todo bien · `1` error en ejecución (red, scope no
confirmado) · `2` error de uso (URL inválida).

---

## 4b. Modo navegador (`--browser`)

El modo normal solo ve los `<script src>` del HTML inicial. Las tiendas online
y las SPA cargan la mayoría de su JS **después**: chunks que importan otros
`.js`, URLs construidas al ejecutar, iframes (checkout, pagos) y secciones que
solo existen tras iniciar sesión o añadir algo al carrito. En la tienda demo de
Shopify el modo normal encuentra 17 `.js`; con `--browser`, unos 160 en una
sola página.

```powershell
python -m uv run python main.py https://tienda-autorizada.com/ --browser --no-ai
```

1. Confirmas el scope, como siempre.
2. Se abre Google Chrome en la URL. **Navega con normalidad**: categorías,
   productos, buscador, carrito, login, checkout…
3. En la terminal aparece cada `.js` capturado: `[+] https://... (37 capturados)`.
4. Cuando termines, **cierra el navegador** (o pulsa Ctrl+C en la terminal).
   Lo capturado se analiza con el flujo de siempre (`--no-ai`, `--deep`,
   `--model`... funcionan igual) y se guarda en `output/`.

Cómo funciona y qué tener en cuenta:

- **No lanza peticiones extra**: solo lee lo que Chrome ya descargó por tu
  navegación. El tráfico es el de una visita normal.
- **El scope decide qué se analiza**, no qué carga el navegador (una web
  siempre pedirá su CDN o sus analytics). Lo que queda fuera aparece en
  `out_of_scope` del informe y no se guarda ni se envía a la IA. Para incluir
  el CDN de la tienda: `--allow-host cdn.tienda.com` o `--scope-subdomains`.
- Se guardan los `.js` de todas las pestañas e iframes, y los `<script>`
  inline de cada página visitada. Se **deduplica por contenido**: el mismo
  fichero con distinto `?v=123` cuenta una sola vez.
- **Perfil propio** en `.browser-profile/` (no es tu Chrome personal). Guarda
  cookies y sesiones, así no tienes que volver a iniciar sesión en la tienda
  entre escaneos. Está en `.gitignore`; bórralo al acabar el engagement o usa
  `--fresh-profile` para un perfil temporal que se borra al salir.
- Si no tienes Google Chrome, usa el Chromium de Playwright:
  `python -m uv run playwright install chromium`.
- Algunos antibots detectan el navegador automatizado y muestran un captcha:
  resuélvelo a mano y sigue navegando.

---

## 5. Qué hace por dentro

```
URL → [fetcher] descarga HTML + JS del mismo host
        ↓
      [extractor] regex: endpoints y secretos (gratis, local)
        ↓
      [analyzer] envía solo lo sospechoso a Claude (opcional, --no-ai lo salta)
        ↓
      output/<host>_<fecha>/  →  report.md · report.json · js/
```

1. **fetcher** — Descarga la página y los `<script>` que referencia. Solo del
   mismo host y puerto (salvo `--include-third-party`, `--allow-host` o
   `--scope-subdomains`). Con `--browser` lo sustituye **browser**, que captura
   los `.js` que carga Chrome mientras navegas (§4b). Cada petición tiene
   timeout y un límite de 5 MB; un `.js` caído se registra y no detiene el
   resto.
2. **extractor** — Aplica regex para encontrar claves de AWS/Google/GitHub,
   Stripe, JWT, tokens Bearer, claves privadas, credenciales en URL y secretos
   genéricos (filtrados por entropía para reducir falsos positivos), además de
   endpoints y **versiones de librerías/tecnologías**. Es gratis y determinista.
   - **Entorno test vs producción:** cada secreto se etiqueta como `test`
     (sandbox/pruebas, riesgo bajo), `live` (producción, riesgo alto) o vacío
     (desconocido). Se deduce del prefijo que pone el proveedor (`sk_test_` vs
     `sk_live_` en Stripe, `sandbox_` vs `production_` en Braintree) y, si la
     clave no lo dice, del contexto cercano. Ante la duda se deja en blanco:
     nunca se rebaja la severidad de una clave real por una coincidencia.
   - **Lógica de negocio** (`logic`): lo que el frontend revela de cómo
     funciona la tienda y que luego se manipula en la petición (Burp):
     - `payment_method`: métodos y pasarelas de pago (`'stripe_test'`,
       `'bizum'`, `'tpv'`, `'cash'`…). Un método de **test** en la web real
       se marca `🧪 TEST` y sale como aviso en la terminal: puede permitir
       pedir sin pagar de verdad.
     - `test_mode` / `debug_flag`: modos test, sandbox, staging o debug
       (`'preprod'`, `debug: true`).
     - `client_check`: bloqueos que solo hace el navegador
       (`form.dataset.stripeAvailable === 'true'`).
     - `role_check`: autorización en el frontend (`role === 'admin'`).
     - `business_rule`: precios, mínimos, gastos de envío, cupones
       (`subtotal >= 2500`, `coupon == 'BLACKFRIDAY50'`).
     - `request_param` / `url_param`: parámetros que envía o lee el cliente
       (`_csrf`, `searchParams.get('redirect')`).
     - `dev_comment` (`// TODO`, `// temporal: bypass…`) e `internal_host`
       (`localhost`, IPs privadas, `staging-api.…`, `*.internal`).
   - **DOM** (`dom`): sinks de XSS (`innerHTML =`, `eval(`,
     `document.write(`), redirecciones (`location.href =`), fuentes que
     controla el atacante (`location.hash`, `document.referrer`) y
     `postMessage`. Un sink alimentado por una fuente = posible DOM XSS.
   - **Versiones:** librerías servidas por CDN con versión (`vue@2.6.14`),
     banners (`jQuery v1.8.2`), versiones declaradas y source maps (`.map`)
     expuestos. Sirve para cruzar con CVEs conocidos.
3. **analyzer** — Opcional. Envía al modelo **solo** los hallazgos del
   pre-filtro, en formato compacto y con los secretos **enmascarados**
   (`AKIA****MPLE`). El modelo recibe la etiqueta de entorno y las versiones, y
   razona sobre severidad (una `sk_live_` es un incidente; una `sk_test_` no) y
   sobre CVEs de las versiones detectadas. El JS del objetivo se trata como
   datos, no como instrucciones.

---

## 6. Interpretar los resultados

Cada ejecución crea `output/<host>_<fecha>/` con:

- **`report.md`** — Informe legible: secretos (enmascarados, con 🔴 LIVE /
  🟢 test), lógica de negocio (con 🧪 TEST en pagos de prueba), sinks y
  fuentes DOM, versiones detectadas, endpoints y, si usaste IA, el análisis
  razonado con su coste.
- **`report.json`** — Los mismos datos en formato máquina, para encadenar con
  otras herramientas.
- **`js/`** — Los `.js` descargados tal cual. Son tu evidencia y te permiten
  repetir el análisis offline sin volver a tocar el objetivo.

> Los informes pueden contener **secretos reales** del objetivo. Trátalos como
> confidenciales; `output/` está en `.gitignore`.

**Un hallazgo no es una vulnerabilidad confirmada.** Verifica a mano:

- Algunas claves son **públicas por diseño** (claves de cliente de Firebase o
  Google Maps). El análisis con IA ayuda a distinguirlas.
- Los secretos genéricos pueden ser falsos positivos aunque pasen el filtro de
  entropía.
- Un endpoint listado solo indica que la ruta aparece en el código, no que sea
  explotable.

---

## 7. Coste de la IA

Fórmula:

```
coste = tokens_entrada/1M × precio_entrada + tokens_salida/1M × precio_salida
```

| Modelo | Entrada ($/1M) | Salida ($/1M) |
|---|---|---|
| `haiku` (`claude-haiku-5-5`) | 0,10 | 0,50 |
| `opus` (`claude-opus-5-5`) | 4,00 | 20,00 |

- Un escaneo típico envía unos cientos de tokens: **menos de una décima de
  céntimo con Haiku**.
- Los tokens de **salida** cuestan 5× los de entrada e incluyen el
  razonamiento interno del modelo.
- `--dry-run` cuenta los tokens exactos con `count_tokens` (gratis) y muestra
  el coste **antes** de pagar nada.

Cómo gastar menos:

- Usa `--no-ai` siempre que el pre-filtro te baste.
- Mantén `haiku` por defecto; pasa a `opus` solo cuando necesites un análisis
  más fino.
- Baja `EFFORT` en `config.py` (ver abajo) para reducir los tokens de salida.

---

## 7b. Modo profundo (`--deep`)

El análisis normal solo manda a la IA los **hallazgos** del pre-filtro: es
barato, pero no "lee" la lógica del código (flujos de autenticación,
validaciones que se hacen solo en el cliente, usos peligrosos del DOM...). El
modo profundo manda el **código fuente completo** de cada `.js`, para un
análisis mucho más rico.

```powershell
python -m uv run python main.py https://mi-lab.local/ --deep --dry-run   # estima coste
python -m uv run python main.py https://mi-lab.local/ --deep             # analiza (pide confirmación)
```

Como mandar código entero es caro, está optimizado para gastar lo mínimo:

1. **Deduplicación por contenido** — un bundle idéntico servido en varias
   rutas se analiza **una sola vez** (comparación por hash SHA-256).
2. **Empaquetado en lotes** — se meten varios ficheros en una misma petición
   hasta `DEEP_BATCH_TOKENS`, así el system prompt y la sobrecarga por petición
   se pagan una vez por lote y no por fichero.
3. **Caché del system prompt** — las instrucciones son idénticas en todos los
   lotes, así que con `cache_control` la API las cobra ~una sola vez.
4. **Troceado** — un fichero más grande que un lote se parte en trozos, de modo
   que el análisis es realmente **completo** (no se descarta código).
5. **Recuento antes de gastar** — cuenta los tokens exactos y te enseña el
   coste máximo **antes** de llamar al modelo.
6. **Confirmación de coste** — si el coste estimado supera `DEEP_CONFIRM_USD`
   (0,25 $ por defecto), pide confirmación salvo que uses `--yes`.
7. **Síntesis final** — si hubo varios lotes, los fusiona en un único informe
   priorizado con una llamada extra barata.

Además hay un **techo duro** de tokens para toda la ejecución
(`DEEP_MAX_TOTAL_TOKENS`): si se alcanza, analiza lo que quepa y avisa del
resto, para que un objetivo enorme no dispare la factura por sorpresa.

> Combínalo con el modelo: `--deep` con `haiku` para una primera lectura
> completa barata, `--deep --model opus` cuando quieras el máximo detalle.

---

## 8. Configuración avanzada

Todos los valores ajustables están en `config.py`:

| Valor | Qué controla |
|---|---|
| `DEFAULT_MODEL` | Modelo por defecto (`"haiku"` / `"opus"`). |
| `EFFORT` | Cuánto "piensa" el modelo: `"low"` … `"max"`. Más = más tokens de salida. |
| `MASK_SECRETS` | Enmascarar los secretos antes de enviarlos (recomendado: `True`). |
| `MAX_INPUT_TOKENS` | Presupuesto de entrada; si se supera, se envían los más prioritarios y se avisa. |
| `MAX_OUTPUT_TOKENS` | Tope de la respuesta del modelo. |
| `MAX_JS_FILES` | Máximo de `.js` por escaneo. |
| `BROWSER_MAX_JS_FILES` | (modo `--browser`) Máximo de `.js` capturados por sesión. |
| `BROWSER_PROFILE_DIR` | (modo `--browser`) Carpeta del perfil persistente de Chrome. |
| `BROWSER_CHANNEL` | (modo `--browser`) `"chrome"` usa tu Google Chrome; `None`, el Chromium de Playwright. |
| `MAX_RESPONSE_BYTES` | Tamaño máximo por respuesta (protege la memoria). |
| `REQUEST_TIMEOUT` | `(conexión, lectura)` en segundos. |
| `GENERIC_SECRET_MIN_ENTROPY` | Umbral de entropía para aceptar un secreto genérico. |
| `DEEP_BATCH_TOKENS` | (modo `--deep`) Tokens de entrada por lote/petición. |
| `DEEP_MAX_TOTAL_TOKENS` | (modo `--deep`) Techo duro de tokens para toda la ejecución. |
| `DEEP_CONFIRM_USD` | (modo `--deep`) Umbral de coste que dispara la confirmación. |

---

## 9. Escenarios típicos

**Primera pasada sobre un objetivo nuevo** (sin gastar en API):

```powershell
python -m uv run python main.py https://mi-lab.local/ --no-ai -v
```

**Confirmar el coste antes de usar la IA:**

```powershell
python -m uv run python main.py https://mi-lab.local/ --dry-run
```

**Tienda online / SPA con muchos chunks, incluyendo su CDN (si está en scope):**

```powershell
python -m uv run python main.py https://tienda.local/ --browser --scope-subdomains --no-ai
```

**Análisis de los hallazgos del pre-filtro con Opus:**

```powershell
python -m uv run python main.py https://mi-lab.local/ --model opus
```

**Análisis profundo del código completo** (lee toda la lógica, ver §7b):

```powershell
python -m uv run python main.py https://mi-lab.local/ --deep            # con Haiku, barato
python -m uv run python main.py https://mi-lab.local/ --deep --model opus  # máximo detalle
```

---

## 10. Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| `Falta ANTHROPIC_API_KEY` | No hay clave en `.env`. Añádela o usa `--no-ai`. |
| `Entrada no interactiva: usa --yes` | Lo ejecutas sin terminal (script/CI). Añade `--yes` tras verificar el scope. |
| `URL no válida` | Falta `http://` o `https://`, o la URL no tiene host. |
| Errores de TLS en un lab | Certificado autofirmado: añade `--insecure`. |
| `No se pudo descargar la página objetivo` | Host caído, DNS, firewall o fuera de línea. Revisa con `-v`. |
| `anthropic could not be resolved` en VS Code | Selecciona el intérprete `.venv\Scripts\python.exe`. |
| `Playwright no está instalado` | Falta el extra: `python -m uv sync --extra browser`. |
| `No se pudo abrir Google Chrome` | No hay Chrome instalado: `python -m uv run playwright install chromium`. |
| `No se capturó ningún .js dentro del scope` | La web carga todo desde otro host (CDN): añade `--allow-host` o `--scope-subdomains`. |
| `No resource with given identifier` en errores | Chrome descartó el cuerpo de un chunk precargado antes de leerlo. Es raro y no detiene la captura. |
| Acentos raros en la consola | Cosmético. El `report.md` en disco está en UTF-8 correcto. |

---

## 11. Limitaciones conocidas

- **JS cargado dinámicamente** (imports que se resuelven en tiempo de
  ejecución, WebAssembly) no aparece en el modo normal: solo se leen los
  `<script>` del HTML inicial. Usa `--browser` (§4b). Aun así, el navegador
  solo ve el JS de las secciones que **visites**.
- La lógica de negocio y los sinks DOM son **pistas**, no vulnerabilidades:
  que el cliente compruebe `subtotal >= 2500` solo importa si el servidor
  **no** lo repite. Verifícalo modificando la petición, sin completar pagos
  reales. En código minificado los nombres cambian (`t.a === "x"`) y se
  detecta menos que en código legible.
- El pre-filtro busca **patrones conocidos**. Un secreto con un formato
  inusual puede escaparse; un valor con pinta de clave puede ser un falso
  positivo.
- El modo normal no ejecuta JavaScript ni rastrea enlaces: analiza una sola
  página por ejecución.
- El enmascarado reduce la exposición de secretos, pero el análisis con IA
  sigue enviando contexto a un servicio externo. Si el engagement lo prohíbe,
  usa `--no-ai`.

---

## 12. Tests y desarrollo

```powershell
python -m uv run pytest -q              # tests (property-based con Hypothesis)
python -m uv run ruff check .           # linter
python -m uv run ruff format .          # formateador
```

Los tests del extractor usan **property-based testing**: en vez de unos pocos
ejemplos, Hypothesis genera cientos de entradas (JS vacío, binario, unicode
raro, entradas gigantes) para comprobar que las regex nunca lanzan, que no hay
backtracking catastrófico (ReDoS) y que los secretos nunca se filtran sin
enmascarar en lo que se envía a la API.

**Estructura del proyecto:**

```
js-recon/
├── main.py            orquestador + CLI
├── config.py          toda la configuración ajustable
├── core/
│   ├── fetcher.py     descarga HTML y JS (scope, timeouts, errores)
│   ├── browser.py     modo --browser: captura los JS mientras navegas
│   ├── extractor.py   regex: endpoints y secretos (pre-filtro)
│   └── analyzer.py    análisis opcional con Claude
├── utils/
│   └── io.py          logging con colores y guardado de informes
├── tests/
│   ├── test_extractor.py
│   ├── test_deep.py
│   ├── test_browser.py
│   └── test_logic.py
├── output/            resultados (en .gitignore)
└── .env               API key (en .gitignore)
```
