"""Exercise the real Django adapter, including CSRF and public-engine integration."""
import json
import os
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
import pytest

from analyzer.engine import analyze
from analyzer.model import empty_model, fact

SOURCES = Path(__file__).resolve().parents[1] / "data" / "sources"


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=["testserver"]):
        yield Client(enforce_csrf_checks=True)


def csrf(client):
    response = client.get("/")
    assert response.status_code == 200
    return client.cookies["csrftoken"].value


def upload(client, name, content):
    token = csrf(client)
    return client.post("/api/analyze/", {"file": SimpleUploadedFile(name, content)}, HTTP_X_CSRFTOKEN=token)


def test_page_uses_one_fixed_graph_scenario_without_configuration_forms(client):
    response = client.get("/")
    text = response.content.decode()
    assert 'data-scenario-url="/api/scenario/"' in text
    assert 'csrfmiddlewaretoken' in text
    assert 'id="security-graph"' in text
    assert 'id="repair-button"' in text
    assert 'id="before-tab"' in text and 'id="after-tab"' in text
    assert '<select' not in text and 'type="file"' not in text
    assert 'href="/tests/"' not in text
    assert 'name="fstec"' not in text
    assert 'name="attack_mode"' not in text


def test_csrf_is_required_for_analyze(client):
    response = client.post("/api/analyze/", {"file": SimpleUploadedFile("model.json", b"{}")})
    assert response.status_code == 403
    assert client.get("/api/analyze/").status_code == 405


@pytest.mark.parametrize("filename,nodes,edges", [
    ("graf-svyazey-pk.html", 231, 1100),
    ("Четыре_конфигурации_ПК_уязвим.xlsx", 229, 1088),
])
def test_structural_upload_preserves_strict_unknown_semantics(client, filename, nodes, edges):
    response = upload(client, filename, (SOURCES / filename).read_bytes())
    assert response.status_code == 200, response.content[:1000]
    payload = response.json()
    state = payload["states"]["imported"]
    assert payload["display_mode"] == "fresh_analysis"
    assert len(state["model"]["nodes"]) == nodes
    assert payload["import_metadata"]["edge_count"] == edges
    assert state["model"]["profile"] == "strict"
    assert state["model"]["transitions"] == []
    assert state["model"]["requirements"] == []
    assert state["analysis"]["summary"] == {}
    assert payload["assumptions"] == []
    assert "отсутствие находок не означает PASS" in payload["notice"]


def test_json_model_rechecks_public_engine_with_file_policy(client):
    model = empty_model("declared-state", "user-profile")
    model["nodes"] = {"service": {"types": ["function"]}}
    model["facts"] = [fact("present", ["service"]), fact("enabled", ["service"], "FALSE"), fact("healthy", ["service"])]
    model["requirements"] = [{"id": "must-work", "checker": "required_function", "object": "service"}]
    response = upload(client, "model.json", json.dumps(model).encode())
    assert response.status_code == 200
    state = response.json()["states"]["uploaded"]
    assert state["analysis"]["summary"] == analyze(model)["summary"] == {"FAIL": 1}
    assert state["model"] == model
    assert state["analysis"]["profile"] == "user-profile"


def test_saved_bundle_is_labelled_as_saved_and_preserves_each_state(client):
    bundle = {"kind": "analysis_bundle", "states": {
        "baseline": {"analysis": {"results": [], "summary": {}}},
        "experiment": {"analysis": {"results": [{"status": "FAIL", "object": "1:83"}], "summary": {"FAIL": 1}}},
        "repaired": {"analysis": {"results": [{"status": "PASS", "object": "1:83"}], "summary": {"PASS": 1}}},
    }, "repair": {"actions": ["restore"]}, "assumptions": ["explicit demo"]}
    response = upload(client, "bundle.json", json.dumps(bundle).encode())
    assert response.status_code == 200
    actual = response.json()
    assert actual["display_mode"] == "saved_report"
    assert actual["states"] == bundle["states"]
    assert actual["repair"] == bundle["repair"]
    assert "без повторного вычисления" in actual["notice"]


def test_bad_and_oversized_uploads_have_actionable_errors(client, monkeypatch):
    for name, data in [("script.js", b"alert(1)"), ("model.json", b"[]"), ("bad.html", b"<script>alert(1)</script>"), ("bad.xlsx", b"not a zip")]:
        response = upload(client, name, data)
        assert response.status_code == 400
        assert response.json()["error"]
    monkeypatch.setattr("core.views.MAX_UPLOAD_BYTES", 100)
    response = upload(client, "large.json", b" " * 101)
    assert response.status_code == 413
