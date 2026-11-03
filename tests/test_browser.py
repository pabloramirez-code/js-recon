"""Tests del modo navegador y del scope ampliable.

ScriptCapture no depende de Playwright: le pasamos respuestas FALSAS con la
misma forma (url, status, headers, request.resource_type, body()). Así se
prueba toda la lógica de captura sin abrir un navegador.
"""

from types import SimpleNamespace

from core.browser import ScriptCapture, _decode
from core.fetcher import make_scope

TARGET = "https://www.tienda.com/"


def resp(url, body, rtype="script", status=200, ctype="application/javascript"):
    data = body.encode("utf-8") if isinstance(body, str) else body
    return SimpleNamespace(
        url=url,
        status=status,
        headers={"content-type": ctype},
        request=SimpleNamespace(resource_type=rtype),
        body=lambda: data,
    )


def capture(max_js=100, **scope_kw):
    return ScriptCapture(TARGET, make_scope(TARGET, **scope_kw), max_js)


# --- Scope ----------------------------------------------------------------------
def test_scope_default_is_exact_host():
    s = make_scope(TARGET)
    assert s.allows("https://www.tienda.com/a.js")
    assert not s.allows("https://cdn.tienda.com/a.js")
    assert not s.allows("https://www.tienda.com:8443/a.js")  # otro puerto = otro servicio


def test_scope_subdomains_strips_www():
    s = make_scope(TARGET, subdomains=True)
    assert s.allows("https://cdn.tienda.com/a.js")
    assert s.allows("https://tienda.com/a.js")
    # Que acabe en "tienda.com" no basta: tiene que ser un subdominio de verdad.
    assert not s.allows("https://mitienda.com/a.js")
    assert not s.allows("https://tienda.com.evil.net/a.js")


def test_scope_allow_host():
    s = make_scope(TARGET, allow_hosts=["CDN.Shopify.com ", ""])
    assert s.allows("https://cdn.shopify.com/x.js")
    assert not s.allows("https://evil.shopify.com/x.js")


def test_scope_third_party_allows_everything():
    assert make_scope(TARGET, include_third_party=True).allows("https://x.net/a.js")


# --- Captura ----------------------------------------------------------------------
def test_captures_in_scope_script():
    c = capture()
    c.on_response(resp("https://www.tienda.com/app.js", "var a=1"))
    assert [(j.url, j.content) for j in c.result.js_files] == [
        ("https://www.tienda.com/app.js", "var a=1")
    ]


def test_out_of_scope_is_recorded_not_saved():
    c = capture()
    for _ in range(2):  # repetido: se registra una sola vez
        c.on_response(resp("https://cdn.otro.com/lib.js", "x"))
    assert c.result.js_files == []
    assert c.result.out_of_scope == ["https://cdn.otro.com/lib.js"]


def test_dedupes_by_content_not_url():
    # Misma versión del fichero con distinto ?v= -> se guarda una vez.
    c = capture()
    c.on_response(resp("https://www.tienda.com/app.js?v=1", "same"))
    c.on_response(resp("https://www.tienda.com/app.js?v=2", "same"))
    c.on_response(resp("https://www.tienda.com/app.js?v=3", "different"))
    assert len(c.result.js_files) == 2


def test_ignores_non_js_and_non_2xx():
    c = capture()
    c.on_response(resp("https://www.tienda.com/logo.png", "png", rtype="image"))
    c.on_response(resp("https://www.tienda.com/api/cart", "{}", rtype="fetch"))
    c.on_response(resp("https://www.tienda.com/gone.js", "x", status=404))
    c.on_response(resp("https://www.tienda.com/moved.js", "", status=301))
    assert c.result.js_files == []


def test_prefetched_chunk_with_js_extension_is_captured():
    # <link rel=prefetch> de un chunk llega como resource_type "other".
    c = capture()
    c.on_response(resp("https://www.tienda.com/chunk.abc.mjs?x=1", "chunk", rtype="other"))
    assert len(c.result.js_files) == 1


def test_document_inline_scripts_and_html():
    c = capture()
    html = "<html><script>var k='inline1'</script><script src='/a.js'></script></html>"
    c.on_response(resp(TARGET, html, rtype="document", ctype="text/html; charset=utf-8"))
    assert c.result.html == html
    assert [(j.url, j.inline) for j in c.result.js_files] == [(TARGET + "#inline-0", True)]


def test_max_js_limit_counts_only_external():
    c = capture(max_js=2)
    c.on_response(resp(TARGET, "<script>inl</script>", rtype="document", ctype="text/html"))
    for i in range(5):
        c.on_response(resp(f"https://www.tienda.com/{i}.js", f"code{i}"))
    assert sum(not j.inline for j in c.result.js_files) == 2
    assert sum(j.inline for j in c.result.js_files) == 1
    assert c.skipped_by_limit == 3


def test_oversized_response_is_discarded(monkeypatch):
    monkeypatch.setattr("core.browser.MAX_RESPONSE_BYTES", 10)
    c = capture()
    c.on_response(resp("https://www.tienda.com/big.js", "x" * 11))
    assert c.result.js_files == []
    assert len(c.result.errors) == 1


def test_body_failure_does_not_raise():
    # Si el navegador ya no tiene el cuerpo, se registra el error y se sigue.
    c = capture()
    r = resp("https://www.tienda.com/a.js", "x")
    r.body = lambda: (_ for _ in ()).throw(RuntimeError("No resource"))
    c.on_response(r)
    c.on_response(resp("https://www.tienda.com/b.js", "y"))
    assert len(c.result.errors) == 1
    assert [j.url for j in c.result.js_files] == ["https://www.tienda.com/b.js"]


def test_decode_uses_charset_and_falls_back():
    assert _decode("ñ".encode("latin-1"), "text/javascript; charset=ISO-8859-1") == "ñ"
    assert _decode("ñ".encode(), "text/javascript") == "ñ"
    assert _decode(b"ok", "text/javascript; charset=inventado") == "ok"
