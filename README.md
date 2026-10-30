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

> Si `uv` está en tu PATH, puedes escribir `uv` en vez de `python -m uv` en
> todos los comandos.

**Sobre `.env`:** está en `.gitignore` y nunca debe subirse a git. La clave no
aparece en el código, los logs ni los informes. Si la expones, revócala en la
consola de Anthropic y genera otra.

Comprobar que todo funciona:

```powershell
python -m uv run python main.py --help
python -m uv run pytest -q          # debe decir "8 passed"
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
usage: js-recon [-h] [--no-ai] [--model {haiku,opus}] [--dry-run]
                [--include-third-party] [--insecure] [--max-js MAX_JS]
                [-y] [-v] url
```

| Opción | Para qué sirve |
|---|---|
| `url` | URL objetivo (`http://` o `https://`). Argumento obligatorio. |
| `--no-ai` | Solo pre-filtro regex, sin llamar a la API. Coste 0. |
| `--deep` | Análisis profundo: manda el **código completo** de los `.js` a la IA (ver §7b). Más caro; pide confirmación de coste. |
| `--model {haiku,opus}` | Modelo para el análisis. Por defecto `haiku`. |
| `--dry-run` | Cuenta tokens y estima coste, pero no llama al modelo. |
| `--include-third-party` | Descarga también JS de otros hosts. Solo si están en scope. |
| `--insecure` | No verifica el certificado TLS (labs autofirmados). |
| `--max-js MAX_JS` | Máximo de ficheros JS a descargar (por defecto 50). |
| `-y`, `--yes` | Confirma el scope sin preguntar. Solo para scripts. |
| `-v`, `--verbose` | Logs de depuración. |

> `--yes` existe para automatizar en scripts o CI. No lo uses de forma
> interactiva para saltarte la pregunta de scope.

**Código de salida:** `0` todo bien · `1` error en ejecución (red, scope no
confirmado) · `2` error de uso (URL inválida).

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
   mismo host y puerto (salvo `--include-third-party`). Cada petición tiene
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
  🟢 test), versiones detectadas, endpoints y, si usaste IA, el análisis
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

**SPA con muchos chunks, incluyendo su CDN (si está en scope):**

```powershell
python -m uv run python main.py https://mi-lab.local/ --include-third-party --max-js 100 --no-ai
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
| Acentos raros en la consola | Cosmético. El `report.md` en disco está en UTF-8 correcto. |

---

## 11. Limitaciones conocidas

- **JS cargado dinámicamente** (imports que se resuelven en tiempo de
  ejecución, WebAssembly) puede no aparecer: solo se leen los `<script>` del
  HTML inicial.
- El pre-filtro busca **patrones conocidos**. Un secreto con un formato
  inusual puede escaparse; un valor con pinta de clave puede ser un falso
  positivo.
- No ejecuta JavaScript ni rastrea enlaces: analiza una sola página por
  ejecución.
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
│   ├── extractor.py   regex: endpoints y secretos (pre-filtro)
│   └── analyzer.py    análisis opcional con Claude
├── utils/
│   └── io.py          logging con colores y guardado de informes
├── tests/
│   └── test_extractor.py
├── output/            resultados (en .gitignore)
└── .env               API key (en .gitignore)
```
