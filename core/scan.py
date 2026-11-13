"""Pipeline de escaneo compartido por la CLI (main.py) y la interfaz web (web/).

POR QUÉ aquí y no en main.py: si la CLI y la web orquestasen cada una a su
manera, tarde o temprano darían resultados distintos para el mismo objetivo.
Este módulo NO pregunta nada al usuario: la confirmación de scope (y la de
coste del modo profundo) la resuelve quien lo llama.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config import BROWSER_MAX_JS_FILES, BROWSER_PROFILE_DIR, DEFAULT_MODEL, MAX_JS_FILES
from core.analyzer import analyze, analyze_deep
from core.browser import capture_with_browser
from core.extractor import extract
from core.fetcher import fetch_target, make_scope, validate_target
from utils.io import log, make_run_dir, render_markdown_report, safe_filename, save_json, save_text


class ScanError(Exception):
    """Fallo que impide generar informe (red, Playwright, nada capturado...)."""


@dataclass
class ScanOptions:
    url: str
    no_ai: bool = False
    deep: bool = False
    model: str = DEFAULT_MODEL
    dry_run: bool = False
    include_third_party: bool = False
    allow_hosts: list[str] = field(default_factory=list)
    scope_subdomains: bool = False
    browser: bool = False
    fresh_profile: bool = False
    insecure: bool = False
    max_js: int | None = None
    # Solo para --deep: acepta el coste estimado sin preguntar.
    accept_cost: bool = False


@dataclass
class ScanResult:
    report: dict[str, Any]
    run_dir: Path


def run_scan(opts: ScanOptions) -> ScanResult:
    """Ejecuta el escaneo completo y guarda el informe. Lanza ScanError o ValueError."""
    url = validate_target(opts.url)  # ValueError si la URL no es válida
    if opts.insecure:
        log.warning("Verificación TLS desactivada (--insecure)")
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if opts.browser:
        scope = make_scope(
            url,
            include_third_party=opts.include_third_party,
            allow_hosts=opts.allow_hosts,
            subdomains=opts.scope_subdomains,
        )
        try:
            fetched = capture_with_browser(
                url,
                scope,
                max_js=opts.max_js or BROWSER_MAX_JS_FILES,
                profile_dir=BROWSER_PROFILE_DIR,
                fresh_profile=opts.fresh_profile,
                verify_tls=not opts.insecure,
            )
        except RuntimeError as e:  # Playwright no instalado
            raise ScanError(str(e)) from e
        if not fetched.js_files:
            raise ScanError("No se capturó ningún .js dentro del scope")
    else:
        fetched = fetch_target(
            url,
            include_third_party=opts.include_third_party,
            allow_hosts=opts.allow_hosts,
            scope_subdomains=opts.scope_subdomains,
            verify_tls=not opts.insecure,
            max_js=opts.max_js or MAX_JS_FILES,
        )
        if not fetched.html:
            raise ScanError("No se pudo descargar la página objetivo")

    run_dir = make_run_dir(url)
    js_dir = run_dir / "js"
    js_dir.mkdir(exist_ok=True)
    findings = []
    for js in fetched.js_files:
        # Guardamos cada JS: es tu evidencia y te permite repetir el análisis
        # offline sin volver a tocar el objetivo.
        save_text(js_dir / safe_filename(js.url), js.content)
        found = extract(js.content, source=js.url)
        log.debug("%s -> %d hallazgos", js.url, len(found))
        findings.extend(found)

    by_cat = Counter(f.category for f in findings)
    live = sum(f.category == "secret" and f.env == "live" for f in findings)
    log.info(
        "Pre-filtro: %d ficheros, %d secretos (%d LIVE), %d lógica, %d DOM, "
        "%d versiones, %d endpoints",
        len(fetched.js_files),
        by_cat["secret"],
        live,
        by_cat["logic"],
        by_cat["dom"],
        by_cat["version"],
        by_cat["endpoint"],
    )
    # Un modo test en pagos o flags de debug en la web real merece verse ya.
    for f in findings:
        if f.category == "logic" and f.env == "test":
            log.warning("Modo TEST expuesto: %s %r en %s:%d", f.kind, f.value, f.source, f.line)

    analysis = None
    if opts.no_ai:
        log.info("Sin IA: se omite el análisis con Claude")
    elif opts.deep:
        analysis = analyze_deep(
            fetched.js_files, opts.model, dry_run=opts.dry_run, assume_yes=opts.accept_cost
        )
    else:
        analysis = analyze(findings, opts.model, dry_run=opts.dry_run)

    report = {
        "target": url,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "js_files": [
            {"url": j.url, "inline": j.inline, "chars": len(j.content)} for j in fetched.js_files
        ],
        "out_of_scope": fetched.out_of_scope,
        "errors": fetched.errors,
        "findings": [f.to_dict() for f in findings],
        "analysis": vars(analysis) if analysis else None,
    }
    save_json(run_dir / "report.json", report)
    save_text(run_dir / "report.md", render_markdown_report(report))
    log.info("Informe guardado en %s", run_dir)
    return ScanResult(report, run_dir)
