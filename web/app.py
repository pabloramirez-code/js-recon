"""Interfaz web de js-recon.

Arranque local:   python -m uv run --extra web python -m web.app
Con Docker:       docker compose up --build   ->  http://localhost:8000

Diseño:
- Usa exactamente el mismo pipeline que la CLI (core.scan.run_scan).
- Un único escaneo a la vez: evita mezclar logs y, sobre todo, lanzar ráfagas
  de tráfico contra el objetivo por error (doble clic, varias pestañas).
- SIN autenticación: está pensada para escuchar solo en localhost. Por eso se
  valida la cabecera Host (anti DNS rebinding) y se exige JSON en los POST
  (un formulario de otra web no puede enviarlo sin preflight CORS).
"""

import json
import logging
import os
import re
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from config import (
    BROWSER_MAX_JS_FILES,
    DEFAULT_MODEL,
    ENV_FILE,
    MAX_JS_FILES,
    MODELS,
    OUTPUT_DIR,
    PRICING_USD_PER_MTOK,
)
from core.fetcher import validate_target
from core.scan import ScanError, ScanOptions, run_scan
from utils.io import log, setup_logging

STATIC_DIR = Path(__file__).resolve().parent / "static"
IN_DOCKER = os.environ.get("JSRECON_IN_DOCKER") == "1"
# Hosts con los que se puede llamar a la interfaz (cabecera Host, sin puerto).
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("JSRECON_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
    if h.strip()
}
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
MAX_LOG_LINES = 2000

app = Flask(__name__, static_folder=None)


# --- Estado del escaneo en curso --------------------------------------------------
class Job:
    def __init__(self, opts: ScanOptions) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.opts = opts
        self.status = "running"  # running | done | error
        self.error = ""
        self.run_id = ""
        self.logs: list[dict] = []
        self.started = datetime.now(UTC).isoformat(timespec="seconds")


class JobLogHandler(logging.Handler):
    """Copia los logs de js-recon al job para mostrarlos en vivo en la web."""

    def __init__(self, job: Job) -> None:
        super().__init__(logging.DEBUG)
        self.job = job
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        if len(self.job.logs) >= MAX_LOG_LINES:
            return
        self.job.logs.append(
            {
                "t": datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
                "level": record.levelname.lower(),
                "msg": self.format(record),
            }
        )


_lock = threading.Lock()
_current: Job | None = None


def _run(job: Job) -> None:
    handler = JobLogHandler(job)
    if log.getEffectiveLevel() > logging.INFO:
        log.setLevel(logging.INFO)  # la consola web necesita al menos el progreso
    log.addHandler(handler)
    try:
        result = run_scan(job.opts)
        job.run_id = result.run_dir.name
        job.status = "done"
    except (ScanError, ValueError) as e:
        log.error("%s", e)
        job.error, job.status = str(e), "error"
    except Exception as e:  # que un fallo inesperado no deje el job colgado
        log.exception("Error inesperado")
        job.error, job.status = f"Error inesperado: {e}", "error"
    finally:
        log.removeHandler(handler)


# --- Seguridad básica -------------------------------------------------------------
@app.before_request
def _guard() -> None:
    host = (request.host or "").lower()
    host = host.rsplit(":", 1)[0] if not host.endswith("]") else host
    if "*" not in ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        abort(403, description=f"Host no permitido: {host} (JSRECON_ALLOWED_HOSTS)")
    if request.method == "POST" and not request.is_json:
        abort(415, description="Se espera application/json")


@app.after_request
def _headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'"
    )
    return resp


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(409)
@app.errorhandler(415)
def _json_error(e):
    return jsonify(error=e.description), e.code


# --- API --------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/static/<path:name>")
def static_files(name: str):
    return send_from_directory(STATIC_DIR, name)


def _browser_available() -> tuple[bool, str]:
    if IN_DOCKER:
        return False, "No disponible en Docker: necesita abrir un Chrome visible en tu equipo."
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, "Instala el extra: python -m uv sync --extra browser --extra web"
    return True, ""


@app.get("/api/meta")
def meta():
    load_dotenv(ENV_FILE)
    browser_ok, browser_why = _browser_available()
    return jsonify(
        models=[
            {"key": k, "id": v, "price": PRICING_USD_PER_MTOK.get(v)} for k, v in MODELS.items()
        ],
        default_model=DEFAULT_MODEL,
        max_js=MAX_JS_FILES,
        browser_max_js=BROWSER_MAX_JS_FILES,
        api_key=bool(os.environ.get("ANTHROPIC_API_KEY")),
        browser=browser_ok,
        browser_reason=browser_why,
        docker=IN_DOCKER,
        job=_current.id if _current is not None and _current.status == "running" else None,
    )


def _parse_options(data: dict) -> ScanOptions:
    if data.get("scope_confirmed") is not True:
        abort(400, description="Confirma que el objetivo está dentro del scope autorizado")
    try:
        url = validate_target(str(data.get("url", "")).strip())
    except ValueError as e:
        abort(400, description=str(e))
    model = data.get("model", DEFAULT_MODEL)
    if model not in MODELS:
        abort(400, description=f"Modelo desconocido: {model}")
    hosts = data.get("allow_hosts") or []
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        abort(400, description="allow_hosts debe ser una lista de hosts")
    hosts = [h.strip().lower() for h in hosts if h.strip()]
    if any(not re.fullmatch(r"[a-z0-9.\-\[\]:]{1,253}", h) for h in hosts):
        abort(400, description="Host permitido con caracteres no válidos")
    max_js = data.get("max_js")
    if max_js in ("", None):
        max_js = None
    else:
        try:
            max_js = int(max_js)
        except (TypeError, ValueError):
            abort(400, description="max_js debe ser un número")
        if not 1 <= max_js <= 5000:
            abort(400, description="max_js debe estar entre 1 y 5000")
    mode = data.get("mode", "noai")
    if mode not in ("noai", "ai", "deep"):
        abort(400, description="Modo de análisis no válido")
    browser = bool(data.get("browser"))
    if browser and not _browser_available()[0]:
        abort(400, description=_browser_available()[1])
    return ScanOptions(
        url=url,
        no_ai=mode == "noai",
        deep=mode == "deep",
        model=model,
        dry_run=bool(data.get("dry_run")) and mode != "noai",
        include_third_party=bool(data.get("include_third_party")),
        allow_hosts=hosts,
        scope_subdomains=bool(data.get("scope_subdomains")),
        browser=browser,
        fresh_profile=bool(data.get("fresh_profile")) and browser,
        insecure=bool(data.get("insecure")),
        max_js=max_js,
        accept_cost=bool(data.get("accept_cost")),
    )


@app.post("/api/scan")
def start_scan():
    global _current
    opts = _parse_options(request.get_json(silent=True) or {})
    with _lock:
        if _current is not None and _current.status == "running":
            abort(409, description="Ya hay un escaneo en curso")
        job = Job(opts)
        _current = job
    threading.Thread(target=_run, args=(job,), daemon=True, name=f"scan-{job.id}").start()
    return jsonify(id=job.id), 202


@app.get("/api/scan/<job_id>")
def scan_status(job_id: str):
    job = _current
    if job is None or job.id != job_id:
        abort(404, description="Escaneo no encontrado")
    since = request.args.get("since", 0, type=int)
    return jsonify(
        id=job.id,
        status=job.status,
        error=job.error,
        run_id=job.run_id,
        target=job.opts.url,
        browser=job.opts.browser,
        logs=job.logs[since:],
        next=len(job.logs),
    )


def _run_dir(run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id) or run_id.startswith("."):
        abort(404, description="Informe no encontrado")
    path = (OUTPUT_DIR / run_id).resolve()
    if path.parent != OUTPUT_DIR.resolve() or not (path / "report.json").is_file():
        abort(404, description="Informe no encontrado")
    return path


@app.get("/api/reports")
def list_reports():
    out = []
    if OUTPUT_DIR.is_dir():
        for d in OUTPUT_DIR.iterdir():
            rep = d / "report.json"
            if not rep.is_file():
                continue
            try:
                data = json.loads(rep.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            counts: dict[str, int] = {}
            live = 0
            for f in data.get("findings", []):
                counts[f.get("category", "?")] = counts.get(f.get("category", "?"), 0) + 1
                live += f.get("category") == "secret" and f.get("env") == "live"
            out.append(
                {
                    "id": d.name,
                    "target": data.get("target", ""),
                    "generated_at": data.get("generated_at", ""),
                    "js_files": len(data.get("js_files", [])),
                    "counts": counts,
                    "live": live,
                    "ai": bool(data.get("analysis")),
                }
            )
    out.sort(key=lambda r: r["generated_at"], reverse=True)
    return jsonify(out)


@app.get("/api/reports/<run_id>")
def get_report(run_id: str):
    return send_file(_run_dir(run_id) / "report.json", mimetype="application/json")


@app.get("/api/reports/<run_id>/download/<fmt>")
def download_report(run_id: str, fmt: str):
    names = {"json": "report.json", "md": "report.md"}
    if fmt not in names:
        abort(404, description="Formato no disponible")
    path = _run_dir(run_id) / names[fmt]
    if not path.is_file():
        abort(404, description="Formato no disponible")
    return send_file(path, as_attachment=True, download_name=f"{run_id}.{fmt}")


def main() -> None:
    setup_logging(os.environ.get("JSRECON_VERBOSE") == "1")
    host = os.environ.get("JSRECON_HOST", "127.0.0.1")
    port = int(os.environ.get("JSRECON_PORT", "8000"))
    from waitress import serve

    log.info("Interfaz web en http://%s:%d", "localhost" if host == "0.0.0.0" else host, port)  # noqa: S104
    serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
