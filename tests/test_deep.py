"""Tests de propiedades de los helpers del modo profundo (--deep).

Estos helpers (trocear, empaquetar, deduplicar) son funciones PURAS: no tocan
la red ni la API. Por eso se pueden verificar exhaustivamente con Hypothesis.
Las propiedades que comprobamos son justo las que, si fallan, o rompen el
presupuesto de coste (lotes demasiado grandes) o pierden código del objetivo
(trozos que no reconstruyen el original) — los dos fallos que más importan aquí.
"""

from types import SimpleNamespace

from hypothesis import given, settings
from hypothesis import strategies as st

from core.analyzer import _assemble, _chunk, _dedupe_files, _pack_batches

PBT = settings(max_examples=300, deadline=None)


# --- _chunk: trocear sin perder nada ------------------------------------------
@PBT
@given(st.text(max_size=3000), st.integers(min_value=1, max_value=200))
def test_chunk_reconstructs_and_respects_size(text, max_chars):
    parts = _chunk(text, max_chars)
    # 1) Sin pérdidas: unir los trozos devuelve EXACTAMENTE el original.
    #    Esta es la garantía de que "completo" es cierto: no se cae código.
    assert "".join(parts) == text
    # 2) Ningún trozo pasa del tope (si text está vacío, no hay trozos).
    assert all(len(p) <= max_chars for p in parts)
    # 3) Sin trozos vacíos (serían peticiones desperdiciadas).
    assert all(p for p in parts) or text == ""


@PBT
@given(st.text(min_size=1, max_size=500))
def test_chunk_small_text_is_single_piece(text):
    # Un texto que cabe de sobra no debe trocearse.
    assert _chunk(text, len(text) + 10) == [text]


# --- _pack_batches: respetar el presupuesto y no perder ficheros --------------
# Nombres y textos acotados; el empaquetado asume que cada item ya cabe en el
# presupuesto (el troceado se hace antes), así que generamos textos pequeños.
FILES = st.lists(
    st.tuples(st.text(max_size=20), st.text(max_size=100)),
    max_size=30,
)


@PBT
@given(FILES, st.integers(min_value=200, max_value=2000))
def test_pack_preserves_all_files_in_order(items, budget):
    batches = _pack_batches(items, budget)
    flat = [item for batch in batches for item in batch]
    # Todos los ficheros acaban en algún lote, y en el mismo orden.
    assert flat == items
    # Ningún lote queda vacío.
    assert all(batch for batch in batches)


@PBT
@given(FILES, st.integers(min_value=200, max_value=2000))
def test_pack_batch_within_budget(items, budget):
    # Cada lote, salvo que tenga un solo item, respeta el presupuesto. Un lote
    # de un único item puede superarlo (ya debería venir troceado antes), por
    # eso la excepción es solo para len == 1.
    for batch in _pack_batches(items, budget):
        size = sum(len(t) + len(n) + 20 for n, t in batch)
        assert size <= budget or len(batch) == 1


# --- _dedupe_files: colapsar contenido idéntico -------------------------------
def _js(url, content):
    return SimpleNamespace(url=url, content=content, inline=False)


@PBT
@given(st.lists(st.text(max_size=50), min_size=1, max_size=15))
def test_dedupe_collapses_identical_content(contents):
    files = [_js(f"http://h/{i}.js", c) for i, c in enumerate(contents)]
    unique = _dedupe_files(files)
    # Hay tantos resultados como contenidos DISTINTOS.
    assert len(unique) == len(set(contents))
    # Cada contenido único aparece una sola vez entre los resultados.
    assert sorted(c for _, c in unique) == sorted(set(contents))


def test_dedupe_annotates_copies():
    files = [_js("a.js", "X"), _js("b.js", "X"), _js("c.js", "Y")]
    unique = dict(_dedupe_files(files))  # {label: content}
    # El contenido repetido ("X", 2 copias) se marca; el único ("Y") no.
    assert any("copias" in label and content == "X" for label, content in unique.items())
    assert "c.js" in unique and unique["c.js"] == "Y"


def test_assemble_marks_each_file():
    text = _assemble([("app.js", "code1"), ("lib.js", "code2")])
    assert "<<<FILE: app.js>>>" in text and "<<<FILE: lib.js>>>" in text
    assert "code1" in text and "code2" in text
