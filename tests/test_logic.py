"""Tests de las categorías "logic" (lógica de negocio) y "dom" (sinks/fuentes XSS).

Casos concretos sacados de JS real de tiendas (incluida la línea de
checkout.js que motivó esta categoría) y falsos positivos típicos que NO deben
saltar. Los invariantes generales (nunca lanza, sin ReDoS, value literal...)
ya los cubren los tests de propiedades de test_extractor.py.
"""

from core.extractor import extract


def found(text: str, kind: str) -> dict[str, str]:
    """{valor: env} de los hallazgos de un tipo."""
    return {f.value: f.env for f in extract(text) if f.kind == kind}


# --- Pagos -----------------------------------------------------------------------
def test_checkout_payment_methods_and_test_mode():
    js = "const online = method => method === 'stripe_test' || method === 'bizum';"
    pay = found(js, "payment_method")
    assert pay["stripe_test"] == "test"  # pasarela de TEST en la web real
    assert pay["bizum"] == ""
    # Ya está como payment_method: no se duplica como test_mode.
    assert "stripe_test" not in found(js, "test_mode")


def test_payment_assignment_and_comparison():
    js = "if (method.value === 'tpv') method.value = 'cash'; x = {in_store: 1, k: 'in_store'}"
    assert {"tpv", "cash", "in_store"} <= set(found(js, "payment_method"))


def test_fetch_method_post_is_not_a_payment():
    js = "fetch(url, { method: 'POST', credentials: 'same-origin' })"
    assert found(js, "payment_method") == {}


def test_live_payment_is_marked_live():
    assert found("const g = 'redsys_live';", "payment_method") == {"redsys_live": "live"}


def test_latest_is_not_test():
    # _VALUE_TEST_RE consideraría "latest" como test; aquí no debe.
    assert found("provider = 'stripe_latest'", "payment_method")["stripe_latest"] == ""


# --- Modos test / debug ------------------------------------------------------------
def test_test_mode_literals_and_debug_flags():
    js = "mode='test_mode'; env = 'preprod'; cfg={debug: true, isDev:!0}; x.test(y)"
    assert {"test_mode", "preprod"} <= set(found(js, "test_mode"))
    assert {"debug: true", "isDev:!0"} <= set(found(js, "debug_flag"))
    # Regex.test() no es un modo test.
    assert not any("test(" in v for v in found(js, "test_mode"))


# --- Controles y reglas en cliente ------------------------------------------------
def test_client_checks_on_dataset_flags():
    js = "ok = form.dataset.stripeAvailable === 'true' && form.dataset.orderingOpen !== 'false'"
    assert set(found(js, "client_check")) == {
        "form.dataset.stripeAvailable === 'true'",
        "form.dataset.orderingOpen !== 'false'",
    }


def test_role_check():
    js = "if (user.role === 'admin' || isAdmin == true) show()"
    assert set(found(js, "role_check")) == {"user.role === 'admin'", "isAdmin == true"}


def test_business_rules_prices_and_coupons():
    js = (
        "quote.deliveryFeeCents === Math.min(1000, 300 + d);"
        " if (subtotal >= 2500) ok(); if (coupon == 'BLACKFRIDAY50') discount = 0.5;"
    )
    rules = set(found(js, "business_rule"))
    assert "quote.deliveryFeeCents === Math.min(1000, 300 + d)" in rules
    assert "subtotal >= 2500" in rules
    assert "coupon == 'BLACKFRIDAY50'" in rules
    assert "discount = 0.5" in rules


def test_typeof_is_not_a_rule():
    js = (
        "if (typeof seed.dataset.perKmCents === 'string') x(); if (typeof role === 'undefined') y()"
    )
    assert found(js, "business_rule") == {}
    assert found(js, "role_check") == {}


# --- Parámetros, comentarios y hosts ----------------------------------------------
def test_request_and_url_params():
    js = (
        "const csrf = form.querySelector('input[name=\"_csrf\"]'); body.set('quoteId', q);"
        " fd.append('price', p); const next = url.searchParams.get('redirect_to');"
    )
    assert {"_csrf", "quoteId", "price"} <= set(found(js, "request_param"))
    assert set(found(js, "url_param")) == {"redirect_to"}


def test_dev_comments_but_not_urls():
    js = (
        "// TODO: validar el precio también en el servidor\n"
        "x = 1; // temporal: bypass del pago para pruebas\n"
        "// Los validadores comprueban la repetición de la contraseña\n"
        "const u = 'https://ejemplo.com/TODO';"
    )
    comments = set(found(js, "dev_comment"))
    assert "TODO: validar el precio también en el servidor" in comments
    assert any("bypass del pago" in c for c in comments)
    assert not any("contraseña" in c for c in comments)
    assert not any("ejemplo.com" in c for c in comments)


def test_internal_hosts():
    js = (
        "a='http://localhost:8080/api'; b='https://staging-api.tienda.com/v1';"
        " c='http://192.168.1.20/x'; d='//backend.corp'; window.localStorage; this.internal"
    )
    hosts = set(found(js, "internal_host"))
    assert {"localhost:8080", "staging-api.tienda.com", "192.168.1.20", "backend.corp"} <= hosts
    assert not any("localStorage" in h or "this" in h for h in hosts)


# --- DOM ---------------------------------------------------------------------------
def test_dom_sinks_sources_and_postmessage():
    js = (
        "el.innerHTML = location.hash.slice(1); document.write(x);"
        " window.addEventListener('message', h); w.postMessage(data, '*');"
        " window.location.href = params.next; if (a.innerHTML == b) z();"
    )
    sinks = set(found(js, "dom_sink"))
    assert "innerHTML = location.hash.slice(1)" in sinks
    assert "document.write(x)" in sinks
    assert not any("==" in s for s in sinks)  # una comparación no es un sink
    assert "location.hash" in found(js, "dom_source")
    assert len(found(js, "postmessage")) == 2
    assert "window.location.href = params.next" in found(js, "redirect_sink")


def test_eval_but_not_method_named_eval():
    js = "eval(userInput); obj.eval(x); retrieval(y)"
    assert set(found(js, "dom_sink")) == {"eval(userInput)"}
