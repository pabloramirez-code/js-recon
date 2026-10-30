"""Entrada/salida: logging con colores y guardado de informes en output/.

POR QUÉ separar esto del resto: fetcher/extractor/analyzer no deben saber
nada de ficheros ni de colores. Así se pueden testear en memoria y reutilizar.
"""

import hashlib
import json
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

# Logger con nombre propio (no el raíz) para no interferir con los logs de
# librerías como urllib3 o anthropic.
log = logging.getLogger("js_recon")


class ColorFormatter(logging.Formatter):
    """Formatter que colorea el nivel con códigos ANSI.

    POR QUÉ ANSI a mano y no una librería: son 5 códigos, no justifican una
    dependencia, y Windows Terminal / PowerShell modernos los entienden.
    """

    COLORS: ClassVar[dict[int, str]] = {
        logging.DEBUG: "\033[90m",  # gris: detalle que normalmente no miras
        logging.INFO: "\033[36m",  # cian: progreso normal
        logging.WARNING: "\033[33m",  # amarillo: algo a revisar
        logging.ERROR: "\033[31m",  # rojo: algo falló
        logging.CRITICAL: "\033[41m",  # fondo rojo: aborta
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if not self.use_color:
            return msg
        color = self.COLORS.get(record.levelno, "")
        return f"{color}{msg}{self.RESET}"


def setup_logging(verbose: bool = False) -> None:
    """Configura el logger de la herramienta."""
    handler = logging.StreamHandler(sys.stderr)  # logs a stderr, datos a stdout
    # Solo coloreamos si la salida es una terminal (no al redirigir a fichero,
    # donde los códigos ANSI serían basura) y si el usuario no pidió NO_COLOR.
    use_color = sys.stderr.isatty() and "NO_COLOR" not in os.environ
    if use_color and os.name == "nt":
        os.system("")  # noqa: S605,S607 - truco conocido: activa ANSI en la consola de Windows
    handler.setFormatter(ColorFormatter(use_color))
    log.handlers[:] = [handler]  # [:] evita handlers duplicados si se llama 2 veces
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.propagate = False


def safe_filename(url: str, suffix: str = ".js") -> str:
    """Convierte una URL en un nombre de fichero SEGURO.

    POR QUÉ no usar la ruta de la URL tal cual: el servidor controla la URL.
    Algo como /static/../../../Windows/x.js o un nombre con ":" o "con.js"
    podría escribir fuera de output/ o romper en Windows (path traversal).
    Solución: un nombre "legible" saneado + hash corto para que sea único.
    """
    path_part = urlparse(url).path.rsplit("/", 1)[-1] or "index"
    # Solo caracteres inocuos; todo lo demás -> "_". Truncado a 40.
    readable = re.sub(r"[^A-Za-z0-9._-]", "_", path_part)[:40].strip(".") or "file"
    digest = hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()[:10]
    stem = readable.removesuffix(suffix)
    return f"{stem}_{digest}{suffix}"


def make_run_dir(target_url: str) -> Path:
    """Crea output/<host>_<timestamp>/ para que cada ejecución no pise otra."""
    from config import OUTPUT_DIR  # import local: evita ciclos al testear

    host = re.sub(r"[^A-Za-z0-9.-]", "_", urlparse(target_url).netloc) or "target"
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")  # UTC: sin líos de zona
    run_dir = OUTPUT_DIR / f"{host}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def save_json(path: Path, data: Any) -> None:
    """Guarda JSON legible. ensure_ascii=False para no destrozar acentos."""
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), "utf-8")


def save_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def render_markdown_report(report: dict[str, Any]) -> str:
    """Genera un informe Markdown para leer a ojo (el JSON es para máquinas)."""
    lines = [
        f"# js-recon — {report['target']}",
        "",
        f"- Fecha (UTC): {report['generated_at']}",
        f"- Ficheros JS analizados: {len(report['js_files'])}",
        f"- Fuera de scope (no descargados): {len(report['out_of_scope'])}",
        f"- Errores de red: {len(report['errors'])}",
        "",
        "## Posibles secretos",
        "",
    ]
    secrets = [f for f in report["findings"] if f["category"] == "secret"]
    if not secrets:
        lines.append("_Ninguno detectado por el pre-filtro._")
    for f in secrets:
        # En el informe local mostramos el valor enmascarado: el fichero
        # puede acabar adjunto a un ticket o un correo.
        # El entorno (test/live) va al principio: es lo que marca la urgencia.
        env = {"live": "🔴 LIVE ", "test": "🟢 test ", "": ""}[f.get("env", "")]
        lines.append(f"- {env}**{f['kind']}** `{f['masked']}` — {f['source']}:{f['line']}")
    lines += ["", "## Versiones / tecnologías", ""]
    versions = sorted({f["value"] for f in report["findings"] if f["category"] == "version"})
    lines += [f"- `{v}`" for v in versions] or ["_Ninguna detectada._"]
    lines += ["", "## Endpoints", ""]
    endpoints = sorted({f["value"] for f in report["findings"] if f["category"] == "endpoint"})
    lines += [f"- `{e}`" for e in endpoints] or ["_Ninguno._"]
    if report.get("analysis"):
        a = report["analysis"]
        lines += [
            "",
            f"## Análisis IA ({a['model']})",
            "",
            f"_Tokens: {a['input_tokens']} entrada / {a['output_tokens']} salida — "
            f"coste ≈ ${a['cost_usd']:.4f}_",
            "",
            a["text"],
        ]
    if report["errors"]:
        lines += ["", "## Errores", ""] + [f"- {e}" for e in report["errors"]]
    return "\n".join(lines) + "\n"
