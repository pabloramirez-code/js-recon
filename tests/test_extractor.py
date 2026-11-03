"""Tests de propiedades del extractor (y del enmascarado del analyzer).

POR QUÉ property-based testing: con tests de ejemplo pruebas 5 entradas que
se te ocurren. Hypothesis genera cientos de entradas (unicode raro, bytes
nulos, cadenas enormes...) buscando una que rompa una REGLA, y si la
encuentra la "encoge" al contraejemplo mínimo para que lo entiendas.
"""

import math
import string
import time

from hypothesis import example, given, settings
from hypothesis import strategies as st

from config import MAX_FINDINGS_PER_FILE
from core.analyzer import build_payload
from core.extractor import Finding, extract, mask_secret, shannon_entropy

# deadline=None: el extractor hace trabajo real; un deadline fijo daría
# fallos intermitentes en un PC lento (y un test inestable acaba borrado).
PBT = settings(max_examples=300, deadline=None)

# Texto con "forma de JS": mezcla de unicode arbitrario y fragmentos que
# activan las regex. Con texto 100% aleatorio casi nunca se ejecutaría la
# rama de "hay hallazgo", y el test sería vacuo.
JS_FRAGMENTS = st.sampled_from(
    [
        '"',
        "'",
        "`",
        "/",
        "/api/v1/",
        "https://",
        "=",
        ":",
        "\n",
        " ",
        "AKIA",
        "eyJ",
        "Bearer ",
        "password",
        "api_key",
        "-----BEGIN PRIVATE KEY",
        "sk_live_",
        ".",
        "\x00",
        "﻿",
        "\\",
        "${",
        "}",
    ]
)
JS_LIKE = st.lists(st.one_of(JS_FRAGMENTS, st.text(max_size=20)), max_size=60).map("".join)
ANY_TEXT = st.one_of(st.text(), JS_LIKE)


def check_invariants(text: str) -> list[Finding]:
    """Las reglas que DEBEN cumplirse para cualquier entrada."""
    findings = extract(text, source="t.js")
    assert isinstance(findings, list)
    assert len(findings) <= MAX_FINDINGS_PER_FILE
    max_line = text.count("\n") + 1
    keys = set()
    for f in findings:
        assert isinstance(f, Finding)
        assert f.category in ("secret", "logic", "version", "dom", "endpoint")
        assert f.value, "un hallazgo vacío no aporta nada"
        # Solo secretos y lógica tienen entorno, y solo uno de estos tres valores.
        assert f.env in ("", "test", "live")
        if f.category not in ("secret", "logic"):
            assert f.env == ""
        # Invariante fuerte: lo capturado existe LITERALMENTE en la entrada.
        # Si un offset estuviera mal, esto falla.
        assert f.value in text
        assert 1 <= f.line <= max_line
        keys.add((f.kind, f.value))
    assert len(keys) == len(findings), "hay duplicados"
    return findings


# --- 1. Robustez frente a entradas raras --------------------------------------
@PBT
@given(ANY_TEXT)
@example("")  # JS vacío
@example("\x00" * 1000)  # bytes nulos
@example("\n" * 5000)  # solo saltos de línea
@example("﻿")  # BOM suelto
@example("\ud800")  # surrogate suelto: str válido en Python pero unicode inválido
@example('"' * 3000)  # comillas sin contenido
def test_extract_invariants_on_text(text):
    check_invariants(text)


@PBT
@given(st.binary(max_size=4096), st.sampled_from(["utf-8", "latin-1", "utf-16"]))
@example(b"", "utf-8")
@example(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "utf-8")  # cabecera PNG real
@example(b"\xff\xfe\x00\xd8", "utf-16")  # UTF-16 con surrogate roto
def test_extract_on_binary_decoded_like_fetcher(data, encoding):
    # Mismo camino que en el fetcher: bytes -> decode(errors="replace") -> extract.
    check_invariants(data.decode(encoding, errors="replace"))


# --- 2. Metamórfica: un secreto plantado se encuentra siempre -------------------
AWS_KEY = st.builds(
    lambda prefix, body: prefix + body,
    st.sampled_from(["AKIA", "ASIA"]),
    st.text(alphabet=string.ascii_uppercase + string.digits, min_size=16, max_size=16),
)


@PBT
@given(JS_LIKE, AWS_KEY, JS_LIKE)
def test_planted_aws_key_is_always_found(before, key, after):
    # Rodeamos con comillas: delimitador realista que garantiza el límite \b.
    text = f'{before}"{key}"{after}'
    found = {f.value for f in check_invariants(text) if f.kind == "aws_access_key_id"}
    assert key in found


@PBT
@given(st.text(alphabet=string.ascii_lowercase + "/_-", min_size=1, max_size=40))
def test_planted_endpoint_is_found(path):
    # Necesita al menos un alfanumérico para ser "interesante" (ver extractor).
    path = "/api/" + path + "x"
    text = f'fetch("{path}")'
    assert path in {f.value for f in check_invariants(text) if f.category == "endpoint"}


# --- 3. Enmascarado: nunca se filtra el secreto completo --------------------------
@PBT
@given(st.text(min_size=0, max_size=300))
def test_mask_secret_properties(value):
    masked = mask_secret(value)
    assert len(masked) == len(value)  # la longitud es pista útil, se conserva
    if len(value) > 8:
        assert masked[:4] == value[:4] and masked[-4:] == value[-4:]
        assert set(masked[4:-4]) == {"*"}
    else:
        assert set(masked) <= {"*"}


def _windows(s: str, n: int) -> set[str]:
    return {s[i : i + n] for i in range(len(s) - n + 1)}


@PBT
@given(JS_LIKE, AWS_KEY, st.integers(min_value=0, max_value=120), AWS_KEY, JS_LIKE)
@example("", "AKIAAAAAAAAAAAAAAAAA", 0, "AKIABBBBBBBBBBBBBBBB", "")
def test_payload_never_leaks_secret_fragments(before, key1, gap, key2, after):
    # Dos claves CERCA: el snippet de una contiene la otra (entera o cortada
    # por el borde del contexto). `gap` mueve ese borde por toda la clave.
    # Fallo real que encontró la prueba end-to-end: un corte dejaba
    # "q8Zr2LmP0" (9 chars de un secreto) en claro.
    text = f'{before} k1="{key1}";{" " * gap}k2="{key2}" {after}'
    payload, _ = build_payload(extract(text, source="t.js"), mask=True)
    # Enmascarado correcto = como mucho 4+4 caracteres visibles, separados.
    # Por tanto NINGÚN fragmento de 9 caracteres de la clave puede aparecer...
    # ...salvo que ese fragmento exista también en el texto que NO es clave
    # (Hypothesis encontró after="000000000" con key="AKIA0000..."; eso es
    # contexto legítimo, no una fuga: la propiedad original estaba mal).
    rest = text.replace(key1, "\x00").replace(key2, "\x00")
    for key in (key1, key2):
        leaked = [w for w in _windows(key, 9) if w in payload and w not in rest]
        assert not leaked, f"fragmentos de {key} en el payload: {leaked}"


# --- 4. Entropía: dentro de los límites matemáticos ------------------------------
@PBT
@given(st.text(max_size=200))
def test_entropy_bounds(s):
    h = shannon_entropy(s)
    # 0 <= H <= log2(nº de símbolos distintos), con tolerancia de coma flotante.
    assert 0.0 <= h <= math.log2(max(1, len(set(s)))) + 1e-9


# --- 5. ReDoS: entradas adversarias no deben disparar el tiempo ------------------
@settings(max_examples=20, deadline=None)
@given(
    st.sampled_from(
        [
            '"/' + "a" * 200_000,  # comilla abierta que nunca cierra
            "eyJ" + "A" * 200_000 + ".eyJ",  # JWT casi completo
            "password=" + '"' + "x" * 200_000,  # asignación sin cerrar
            "Bearer " * 30_000,
            "https://" + "a:" * 100_000,  # muchos candidatos a credenciales en URL
            "AKIA" * 50_000,
        ]
    )
)
def test_no_catastrophic_backtracking(text):
    start = time.perf_counter()
    check_invariants(text)
    # Lineal ≈ milisegundos; un backtracking catastrófico serían minutos.
    assert time.perf_counter() - start < 2.0


# --- 6. Entorno test/live: una clave Stripe se clasifica por su prefijo ----------
STRIPE_BODY = st.text(alphabet=string.ascii_letters + string.digits, min_size=16, max_size=40)


@PBT
@given(JS_LIKE, st.sampled_from(["sk", "rk", "pk"]), st.sampled_from(["test", "live"]), STRIPE_BODY)
@example("", "sk", "live", "A" * 24)
@example("", "sk", "test", "A" * 24)
def test_stripe_key_env_matches_prefix(before, prefix, mode, body):
    key = f"{prefix}_{mode}_{body}"
    text = f'{before} stripe="{key}"'
    matches = [f for f in check_invariants(text) if f.value == key]
    assert matches, "la clave de Stripe debería detectarse"
    # La propiedad clave: el entorno SIEMPRE coincide con el prefijo de la clave,
    # porque el prefijo lo pone Stripe a propósito. Esto es lo que separa "mueve
    # dinero real" de "no lo mueve".
    assert all(f.env == mode for f in matches)


@PBT
@given(st.sampled_from(["sk_live_", "rk_live_"]), STRIPE_BODY)
def test_live_key_never_downgraded_to_test(prefix, body):
    # Aunque el contexto diga "test", una clave _live_ NO debe rebajarse: el
    # prefijo de la clave manda sobre el nombre de la variable.
    key = prefix + body
    text = f'var testKey = "{key}"; // entorno de test'
    matches = [f for f in extract(text, "t.js") if f.value == key]
    assert matches and all(f.env == "live" for f in matches)


# --- 7. Versiones: una librería con versión se detecta ---------------------------
@PBT
@given(
    JS_LIKE,
    st.sampled_from(["jquery", "vue", "react", "lodash", "axios"]),
    st.tuples(st.integers(0, 99), st.integers(0, 99), st.integers(0, 99)),
)
def test_cdn_versioned_library_is_detected(before, lib, ver):
    v = f"{ver[0]}.{ver[1]}.{ver[2]}"
    text = f'{before}<script src="https://cdn.jsdelivr.net/npm/{lib}@{v}/dist.js">'
    versions = {f.value for f in check_invariants(text) if f.category == "version"}
    assert f"{lib}@{v}" in versions


@PBT
@given(st.sampled_from(["jQuery", "Bootstrap", "Vue.js", "AngularJS"]), st.integers(0, 20))
def test_library_banner_is_detected(lib, minor):
    text = f"/*! {lib} v3.{minor}.0 | (c) foundation */"
    found = [f for f in check_invariants(text) if f.category == "version"]
    assert any(f"3.{minor}.0" in f.value for f in found)
