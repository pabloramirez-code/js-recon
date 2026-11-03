"""js-recon: orquestador y CLI.

Flujo: confirmar scope -> fetcher (descarga) -> extractor (regex) ->
analyzer (IA, opcional) -> informe en output/.

main.py solo coordina: no contiene lógica de red, regex ni API. Si mañana
cambias requests por httpx o la IA por otra, este fichero apenas cambia.
"""

import argparse
import sys
from collections import Counter
from datetime import UTC, datetime

from config import (
    BROWSER_MAX_JS_FILES,
    BROWSER_PROFILE_DIR,
    DEFAULT_MODEL,
    MAX_JS_FILES,
    MODELS,
)
from core.analyzer import analyze, analyze_deep
from core.browser import capture_with_browser
from core.extractor import extract
from core.fetcher import fetch_target, make_scope, validate_target
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
        "--deep",
        action="store_true",
        help="análisis profundo: manda el CÓDIGO COMPLETO de los .js a la IA "
        "(más caro; optimizado con dedup, lotes y caché). Pide confirmación de coste.",
    )
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
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="analiza también los JS de este host (repetible; p. ej. cdn.tienda.com)",
    )
    p.add_argument(
        "--scope-subdomains",
        action="store_true",
        help="analiza también los JS del dominio base y sus subdominios (*.tienda.com)",
    )
    p.add_argument(
        "--browser",
        action="store_true",
        help="abre Chrome: navegas tú y se capturan todos los .js que cargue la web; "
        "al cerrar el navegador se analizan",
    )
    p.add_argument(
        "--fresh-profile",
        action="store_true",
        help="con --browser: usa un perfil temporal limpio (sin cookies ni sesiones previas)",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="no verificar TLS (labs con certificado autofirmado)",
    )
    p.add_argument(
        "--max-js",
        type=int,
        default=None,
        help=f"máximo de ficheros JS (por defecto {MAX_JS_FILES}; "
        f"{BROWSER_MAX_JS_FILES} con --browser)",
    )
    p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="confirmo que el objetivo está en scope (no preguntar)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="logs de depuración")
    return p.parse_args(argv)


def confirm_scope(url: str, assume_yes: bool) -> bool:
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
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.browser:
        max_js = args.max_js or BROWSER_MAX_JS_FILES
        scope = make_scope(
            url,
            include_third_party=args.include_third_party,
            allow_hosts=args.allow_host,
            subdomains=args.scope_subdomains,
        )
        try:
            fetched = capture_with_browser(
                url,
                scope,
                max_js=max_js,
                profile_dir=BROWSER_PROFILE_DIR,
                fresh_profile=args.fresh_profile,
                verify_tls=not args.insecure,
            )
        except RuntimeError as e:  # Playwright no instalado
            log.error("%s", e)
            return 1
        if not fetched.js_files:
            log.error("No se capturó ningún .js dentro del scope")
            return 1
    else:
        fetched = fetch_target(
            url,
            include_third_party=args.include_third_party,
            allow_hosts=args.allow_host,
            scope_subdomains=args.scope_subdomains,
            verify_tls=not args.insecure,
            max_js=args.max_js or MAX_JS_FILES,
        )
        if not fetched.html:
            log.error("No se pudo descargar la página objetivo")
            return 1

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

    # 3) IA opcional
    analysis = None
    if args.no_ai:
        log.info("--no-ai: se omite el análisis con IA")
    elif args.deep:
        # Modo profundo: todo el código a la IA (optimizado). El scope ya se
        # confirmó; el coste se confirma aparte salvo --yes.
        analysis = analyze_deep(
            fetched.js_files, args.model, dry_run=args.dry_run, assume_yes=args.yes
        )
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
