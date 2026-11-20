"""Real scenario HTTP adapter and expected-vs-actual result semantics."""
import json
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()

from django.test import Client, override_settings
import pytest

from analyzer.engine import analyze as public_analyze
from analyzer.scenarios import run_scenario


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=["testserver"]):
        yield Client(enforce_csrf_checks=True)


def post(client, scenario, payload=None):
    client.get("/analysis/")
    return client.post(f"/api/test-scenarios/{scenario}/run/", json.dumps(payload or {}),
                       content_type="application/json", HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)


def test_catalogue_has_named_scenarios_with_explicit_expectations_and_defaults(client):
    response = client.get("/api/test-scenarios/")
    assert response.status_code == 200
    catalog = response.json()
    assert len(catalog["scenarios"]) == 9
    assert len({item["id"] for item in catalog["scenarios"]}) == 9
    assert catalog["defaults"] == {"repair": False, "closed_inventory": False}
    changed = next(item for item in catalog["scenarios"] if item["id"] == "changed")
    assert changed["expected_summary"] == {"PASS": 11, "UNKNOWN": 1}
    assert changed["expected_summary_closed"] == {"PASS": 11, "FAIL": 1}
    assert changed["uses_inventory_assumption"]


def test_scenario_execution_requires_post_and_csrf(client):
    assert client.get("/api/test-scenarios/keyed_backup/run/").status_code == 405
    assert client.post("/api/test-scenarios/keyed_backup/run/", "{}", content_type="application/json").status_code == 403


@pytest.mark.parametrize("payload", [[], {"repair": "true"}, {"closed_inventory": 1}, {"path": "/etc/passwd"}, {"command": "pytest"}])
def test_request_cannot_select_paths_commands_or_coerce_assumptions(client, payload):
    client.get("/analysis/")
    response = client.post("/api/test-scenarios/keyed_backup/run/", json.dumps(payload), content_type="application/json",
                           HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)
    assert response.status_code == 400
    assert response.json()["error"]


def test_unknown_and_unsupported_repair_requests_are_explicit_errors(client):
    assert post(client, "not-a-scenario").status_code == 404
    assert post(client, "keyed_backup", {"repair": True}).status_code == 400


@pytest.mark.parametrize("scenario,summary", [
    ("dependency_cycle", {"UNKNOWN": 1}),
    ("keyed_backup", {"FAIL": 1}),
    ("common_dependency", {"FAIL": 1}),
    ("configuration_and_duties", {"FAIL": 5, "REQUIRES_EVIDENCE": 1, "NOT_CHECKED": 1}),
])
def test_expected_security_failure_or_unknown_still_passes_test(client, scenario, summary):
    response = post(client, scenario)
    assert response.status_code == 200
    result = response.json()
    assert result["test"]["passed"]
    assert all(item["passed"] for item in result["test"]["expectations"])
    assert result["report"]["states"]["fixture"]["analysis"]["summary"] == summary
    assert result["duration_ms"] >= 0
    assert result["report"]["display_mode"] == "fresh_analysis"


def test_changed_inventory_is_unknown_until_completeness_is_explicit(client):
    opened = post(client, "changed").json()
    closed = post(client, "changed", {"closed_inventory": True}).json()
    assert opened["test"]["passed"] and closed["test"]["passed"]
    assert opened["report"]["states"]["changed"]["analysis"]["summary"] == {"PASS": 11, "UNKNOWN": 1}
    assert closed["report"]["states"]["changed"]["analysis"]["summary"] == {"PASS": 11, "FAIL": 1}
    assert opened["options"]["closed_inventory"] is False
    assert closed["report"]["comparison"]["assumptions"][0]["value"] is True


@pytest.mark.parametrize("closed,count,summary", [
    (False, 3, {"PASS": 11, "UNKNOWN": 1}),
    (True, 4, {"PASS": 12}),
])
def test_joint_repair_rechecks_all_pcs_and_keeps_unknowns_visible(client, closed, count, summary):
    response = post(client, "experiment", {"closed_inventory": closed, "repair": True})
    assert response.status_code == 200
    result = response.json()
    assert result["test"]["passed"], result["test"]
    repair = result["report"]["repair"]
    assert repair["status"] == "OPTIMAL_REPAIR"
    assert repair["objective_value"] == [count, count]
    assert repair["independently_rechecked"]
    assert result["report"]["states"]["baseline"]["analysis"]["summary"] == {"PASS": 12}
    repaired = result["report"]["states"]["repaired"]
    assert repaired["analysis"]["summary"] == summary
    assert public_analyze(repaired["model"])["summary"] == summary


def test_source_comparison_runs_actual_importers(client):
    result = post(client, "source_comparison").json()
    assert result["test"]["passed"]
    report = result["report"]
    assert report["comparison"]["missing_in_xlsx"] == ["1:59", "2:90"]
    assert len(report["states"]["html"]["model"]["nodes"]) == 231
    assert len(report["states"]["xlsx"]["model"]["nodes"]) == 229
    assert report["states"]["html"]["analysis"]["summary"] == {}


def test_quantum_scenario_keeps_passive_and_active_outcomes_separate(client):
    result = post(client, "quantum").json()
    assert result["test"]["passed"]
    outcomes = {item["id"]: item["status"] for item in result["report"]["states"]["quantum"]["analysis"]["results"]}
    assert outcomes["passive_confidentiality"] == outcomes["active_read_not_created"] == "FAIL"
    assert outcomes["write_not_created"] == "PASS"


def test_real_analysis_regression_is_not_reported_as_a_passing_test(monkeypatch):
    def wrong_result(model):
        result = public_analyze(model)
        result["results"][0]["status"] = "PASS"
        result["summary"] = {"PASS": 1}
        return result
    monkeypatch.setattr("analyzer.scenarios.analyze", wrong_result)
    result = run_scenario("keyed_backup")
    assert result["test"]["passed"] is False
    failed = [item for item in result["test"]["expectations"] if not item["passed"]]
    assert failed and failed[0]["expected"] != failed[0]["actual"]
