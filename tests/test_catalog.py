"""Catalogue coverage is not inferred from text import or a partial checker PASS."""
from pathlib import Path

import pytest

from analyzer.catalog import FORMALIZATIONS, MAPPING_IDS, coverage, load_catalog


SOURCE = Path(__file__).resolve().parents[1] / "data/sources/katalog_pravil_logicheskogo_analizatora.docx"


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(SOURCE)


def test_catalogue_has_actual_324_unique_rules_and_47_sections(catalog):
    assert catalog["rule_count"] == 324
    assert catalog["section_count"] == 47
    assert len({r["rule_id"] for r in catalog["rules"]}) == 324
    assert [s["number"] for s in catalog["sections"]] == list(range(1, 48))
    assert catalog["date"] == "2026-11-18"
    assert catalog["version"] == "1.0"


def test_each_original_field_and_location_is_preserved(catalog):
    required = {"applicability", "required_data", "violation", "unknown_condition", "repair", "basis", "mode"}
    for rule in catalog["rules"]:
        assert required <= rule["fields"].keys()
        assert all(rule["fields"][field] for field in required)
        assert rule["provenance"]["location"].startswith("word/document.xml:p[")
        assert rule["provenance"]["kind"] == "imported"
        assert rule["rule_id"] in rule["source_paragraphs"][0]
        assert rule["applicability"]["value"] == "UNKNOWN"
    assert "Приложение А" in "\n".join(catalog["source_paragraphs"])
    assert "Приложение А" not in "\n".join(catalog["rules"][-1]["source_paragraphs"])
    assert catalog["fls_definition"] is None


def test_mappings_reference_real_ids_and_have_executable_contracts(catalog):
    from analyzer.engine import CHECKERS
    all_ids = {r["rule_id"] for r in catalog["rules"]}
    for checker, ids in MAPPING_IDS.items():
        assert set(ids.split()) <= all_ids
        assert checker in FORMALIZATIONS
        assert checker in CHECKERS
    for rule in catalog["rules"]:
        f = rule["formalization"]
        assert f["whole_rule_implemented"] is False
        assert f["reason"]
        assert f["uncovered_conditions"]
        if f["support_status"] == "implemented":
            assert f["checkers"]
            for checker in f["checkers"]:
                for field in ("condition", "input_facts", "completeness_scope", "explanation", "repair_templates", "test_refs", "covered_scope"):
                    assert checker[field]


def test_import_is_not_execution_or_applicability(catalog):
    report = coverage(catalog)
    assert report["rule_count"] == 324
    assert report["summary"] == {"UNKNOWN": 324}
    assert not any(r["status"] in {"PASS", "NOT_APPLICABLE"} for r in report["rules"])
    assert report["support_summary"]["requires_evidence"] > 0
    assert report["support_summary"]["unsupported"] > 0


def _entry(catalog, analysis, apply="TRUE"):
    return next(r for r in coverage(catalog, analysis, {"FT019": apply})["rules"] if r["rule_id"] == "FT019")


def test_partial_pass_never_certifies_whole_rule(catalog):
    analysis = {"results": [{"id": "local-acl", "rule_id": "LOCAL001", "catalog_rule_ids": ["FT019"], "status": "PASS"}]}
    assert _entry(catalog, analysis)["status"] == "NOT_CHECKED"
    assert _entry(catalog, analysis, "UNKNOWN")["status"] == "UNKNOWN"
    analysis["results"][0]["catalog_scope"] = "complete"
    assert _entry(catalog, analysis)["status"] == "PASS"


def test_confirmed_failure_survives_secondary_unknown(catalog):
    analysis = {"results": [{"rule_id": "FT019", "status": "FAIL"}, {"rule_id": "FT019", "status": "UNKNOWN"}]}
    assert _entry(catalog, analysis)["status"] == "FAIL"
    assert _entry(catalog, analysis, "FALSE")["status"] == "NOT_APPLICABLE"


def test_evidence_unsupported_and_data_gap_are_separate(catalog):
    representatives = {}
    for rule in catalog["rules"]:
        representatives.setdefault(rule["formalization"]["support_status"], rule["rule_id"])
    report = coverage(catalog, applicability={key: "TRUE" for key in representatives.values()})
    statuses = {r["rule_id"]: r["status"] for r in report["rules"]}
    assert statuses[representatives["requires_evidence"]] == "REQUIRES_EVIDENCE"
    assert statuses[representatives["requires_additional_data"]] == "UNKNOWN"
    assert statuses[representatives["unsupported"]] == "NOT_CHECKED"


def test_txt_roundtrip_and_duplicate_id_rejected(catalog, tmp_path):
    path = tmp_path / "catalogue.txt"
    path.write_text("\n".join(catalog["source_paragraphs"]), encoding="utf-8")
    parsed = load_catalog(path)
    assert [(r["rule_id"], r["fields"]) for r in parsed["rules"]] == [(r["rule_id"], r["fields"]) for r in catalog["rules"]]
    path.write_text(path.read_text(encoding="utf-8") + "\nMD001 Duplicate\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_catalog(path)


def test_invalid_applicability_is_not_silently_accepted(catalog):
    with pytest.raises(ValueError, match="Invalid applicability"):
        coverage(catalog, applicability={"FT019": "maybe"})


def test_global_model_error_prevents_catalogue_pass(catalog):
    analysis = {"model_errors": [{"code": "CONFLICTING_FACTS"}],
                "results": [{"rule_id": "FT019", "status": "PASS", "catalog_scope": "complete"}]}
    assert _entry(catalog, analysis)["status"] == "MODEL_ERROR"


def test_active_quantum_and_hybrid_are_not_claimed_supported(catalog):
    index = {r["rule_id"]: r for r in catalog["rules"]}
    for rule_id in ("CR042", "CR043", "CR046"):
        assert index[rule_id]["formalization"]["support_status"] == "unsupported"
        assert not index[rule_id]["formalization"]["checkers"]
