"""js-recon: orquestador y CLI.

Flujo: confirmar scope -> core.scan.run_scan (fetcher -> extractor ->
analyzer opcional -> informe en output/). La interfaz web usa el mismo run_scan.

main.py solo coordina: no contiene lógica de red, regex ni API. Si mañana
cambias requests por httpx o la IA por otra, este fichero apenas cambia.
"""

import argparse
import sys

from config import BROWSER_MAX_JS_FILES, DEFAULT_MODEL, MAX_JS_FILES, MODELS
from core.fetcher import validate_target
from core.scan import ScanError, ScanOptions, run_scan
from utils.io import log, setup_logging


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

    opts = ScanOptions(
        url=url,
        no_ai=args.no_ai,
        deep=args.deep,
        model=args.model,
        dry_run=args.dry_run,
        include_third_party=args.include_third_party,
        allow_hosts=args.allow_host,
        scope_subdomains=args.scope_subdomains,
        browser=args.browser,
        fresh_profile=args.fresh_profile,
        insecure=args.insecure,
        max_js=args.max_js,
        # El scope ya se confirmó; el coste de --deep se pregunta aparte salvo --yes.
        accept_cost=args.yes,
    )
    try:
        result = run_scan(opts)
    except ScanError as e:
        log.error("%s", e)
        return 1

    analysis = result.report["analysis"]
    if analysis and not analysis["dry_run"]:
        print(analysis["text"])  # stdout: el resultado; stderr: los logs
    return 0


if __name__ == "__main__":
    # sys.exit con el código de retorno: permite encadenar en scripts
    # (js-recon ... && siguiente_paso).
    sys.exit(main())
