"""js-recon: orquestador y CLI.

Flujo: confirmar scope -> fetcher (descarga) -> extractor (regex) ->
analyzer (IA, opcional) -> informe en output/.

main.py solo coordina: no contiene lógica de red, regex ni API. Si mañana
cambias requests por httpx o la IA por otra, este fichero apenas cambia.
"""

import argparse
import sys
from datetime import UTC, datetime

from config import DEFAULT_MODEL, MAX_JS_FILES, MODELS
from core.analyzer import analyze
from core.extractor import extract
from core.fetcher import fetch_target, validate_target
from utils.io import (
    log,
    make_run_dir,
    render_markdown_report,
    safe_filename,
    save_json,
    save_text,
    setup_logging,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="js-recon",
        description="Descarga los JS de una URL, extrae endpoints/secretos y (opcional) "
        "los analiza con Claude. Úsalo SOLO contra objetivos autorizados.",
    )
    p.add_argument("url", help="URL objetivo (http:// o https://)")
    p.add_argument("--no-ai", action="store_true", help="solo pre-filtro regex, sin API (coste 0)")
    p.add_argument(
        "--model",
        choices=sorted(MODELS),
        default=DEFAULT_MODEL,
        help=f"modelo para el análisis (por defecto: {DEFAULT_MODEL})",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="cuenta tokens y estima coste, pero no llama al modelo",
    )
    p.add_argument(
        "--include-third-party",
        action="store_true",
        help="descarga también JS de otros hosts (¡solo si están en scope!)",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="no verificar TLS (labs con certificado autofirmado)",
    )
    p.add_argument("--max-js", type=int, default=MAX_JS_FILES, help="máximo de ficheros JS")
    p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="confirmo que el objetivo está en scope (no preguntar)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="logs de depuración")
    return p.parse_args(argv)


def confirm_scope(url: str, assume_yes: bool) -> bool:
    """Fricción deliberada: obliga a pensar en el scope antes de lanzar tráfico."""
    print(f"\n  Objetivo: {url}", file=sys.stderr)
    print("  ¿Está este host DENTRO del scope autorizado por escrito?", file=sys.stderr)
    if assume_yes:
        print("  (--yes: confirmado por argumento)\n", file=sys.stderr)
        return True
    if not sys.stdin.isatty():
        # Sin terminal interactiva (script, CI) no podemos preguntar: exigir --yes.
        log.error("Entrada no interactiva: usa --yes para confirmar el scope")
        return False
    return input("  Escribe 's' para continuar: ").strip().lower() in ("s", "si", "sí", "y")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    try:
        url = validate_target(args.url)
    except ValueError as e:
        log.error("%s", e)
        return 2  # 2 = error de uso, convención de las CLI de Unix
    if not confirm_scope(url, args.yes):
        log.error("Abortado: confirma el scope antes de escanear")
        return 1
    if args.insecure:
        log.warning("Verificación TLS desactivada (--insecure)")
        # Silenciar el aviso de urllib3 en cada petición: ya avisamos una vez.
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # 1) Descarga
    fetched = fetch_target(
        url,
        include_third_party=args.include_third_party,
        verify_tls=not args.insecure,
        max_js=args.max_js,
    )
    if not fetched.html:
        log.error("No se pudo descargar la página objetivo")
        return 1

    # 2) Pre-filtro regex (gratis, local)
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

    n_secrets = sum(f.category == "secret" for f in findings)
    n_versions = sum(f.category == "version" for f in findings)
    n_endpoints = len(findings) - n_secrets - n_versions
    live = sum(f.category == "secret" and f.env == "live" for f in findings)
    log.info(
        "Pre-filtro: %d ficheros, %d secretos (%d LIVE), %d versiones, %d endpoints",
        len(fetched.js_files),
        n_secrets,
        live,
        n_versions,
        n_endpoints,
    )

    # 3) IA opcional
    analysis = None
    if args.no_ai:
        log.info("--no-ai: se omite el análisis con IA")
    else:
        analysis = analyze(findings, args.model, dry_run=args.dry_run)

    # 4) Informe
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

    if analysis and not analysis.dry_run:
        print(analysis.text)  # stdout: el resultado; stderr: los logs
    return 0


if __name__ == "__main__":
    # sys.exit con el código de retorno: permite encadenar en scripts
    # (js-recon ... && siguiente_paso).
    sys.exit(main())
