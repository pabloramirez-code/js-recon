"""Tests de la interfaz web: guardas de seguridad y flujo de un escaneo."""

import json
import time

import pytest

flask = pytest.importorskip("flask")  # solo si está instalado el extra "web"

import web.app as webapp  # noqa: E402
from core.fetcher import FetchResult, JsFile  # noqa: E402

JSON = {"Content-Type": "application/json"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr("config.OUTPUT_DIR", tmp_path)  # make_run_dir lo importa de config
    monkeypatch.setattr(webapp, "_current", None)
    webapp.app.testing = True
    return webapp.app.test_client()


def test_rechaza_host_ajeno(client):
    # Anti DNS rebinding: una web maliciosa que resuelva a 127.0.0.1 llega con su Host.
    r = client.get("/api/meta", headers={"Host": "evil.example"})
    assert r.status_code == 403


def test_post_exige_json(client):
    # Un <form> de otra web solo puede mandar form-urlencoded/text sin preflight.
    r = client.post("/api/scan", data="url=http://x", headers={"Host": "localhost"})
    assert r.status_code == 415


def test_exige_confirmar_scope(client):
    body = json.dumps({"url": "http://lab.local/"})
    r = client.post("/api/scan", data=body, headers={**JSON, "Host": "localhost"})
    assert r.status_code == 400
    assert "scope" in r.get_json()["error"]


@pytest.mark.parametrize(
    "payload",
    [
        {"url": "ftp://lab.local/"},
        {"url": "http://lab.local/", "mode": "rm -rf"},
        {"url": "http://lab.local/", "model": "gpt"},
        {"url": "http://lab.local/", "max_js": 0},
        {"url": "http://lab.local/", "allow_hosts": ["a b"]},
    ],
)
def test_valida_opciones(client, payload):
    body = json.dumps({**payload, "scope_confirmed": True})
    r = client.post("/api/scan", data=body, headers={**JSON, "Host": "localhost"})
    assert r.status_code == 400


@pytest.mark.parametrize("run_id", ["..", "..%2F..%2Fconfig.py", ".env", "no-existe"])
def test_informes_sin_path_traversal(client, run_id):
    r = client.get(f"/api/reports/{run_id}", headers={"Host": "localhost"})
    assert r.status_code == 404


# Clave falsa montada en ejecución: si estuviera literal en el código, el
# escaneo de secretos de GitHub (push protection) bloquearía el push.
FAKE_LIVE_KEY = "sk_" + "live_" + "Zz9Fake0Key1For2Tests3Only4"


def test_escaneo_completo(client, monkeypatch):
    js = f'const k = "{FAKE_LIVE_KEY}"; fetch("/api/admin/users");'
    fake = FetchResult(
        "http://lab.local/", html="<html>", js_files=[JsFile("http://lab.local/a.js", js)]
    )
    monkeypatch.setattr("core.scan.fetch_target", lambda *a, **k: fake)

    body = json.dumps({"url": "http://lab.local/", "scope_confirmed": True, "mode": "noai"})
    r = client.post("/api/scan", data=body, headers={**JSON, "Host": "localhost"})
    assert r.status_code == 202
    job = r.get_json()["id"]

    for _ in range(100):
        st = client.get(f"/api/scan/{job}", headers={"Host": "localhost"}).get_json()
        if st["status"] != "running":
            break
        time.sleep(0.05)
    assert st["status"] == "done", st
    assert any("Pre-filtro" in line["msg"] for line in st["logs"])

    reports = client.get("/api/reports", headers={"Host": "localhost"}).get_json()
    assert [x["id"] for x in reports] == [st["run_id"]]
    assert reports[0]["live"] == 1

    rep = client.get(f"/api/reports/{st['run_id']}", headers={"Host": "localhost"}).get_json()
    kinds = {f["kind"] for f in rep["findings"]}
    assert "stripe_secret_key" in kinds
    md = client.get(f"/api/reports/{st['run_id']}/download/md", headers={"Host": "localhost"})
    assert md.status_code == 200
    assert FAKE_LIVE_KEY.encode() not in md.data  # el .md va enmascarado
