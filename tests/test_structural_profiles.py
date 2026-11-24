"""Opt-in mandate semantics preserve the source and expose incomplete scope."""
from copy import deepcopy
import json

import pytest

from analyzer.engine import analyze
from analyzer.model import validate_model
from analyzer.structural_profiles import compile_mandate_flows, detect_mandate_profile, validate_input_graph


def graph():
    nodes = {
        "rank/low": {"name": "Мандат 2 — Общий", "cluster": "Мандаты"},
        "rank/high": {"name": "Мандат 11 – Закрытый", "cluster": "Мандаты"},
        "source:α": {"name": "Произвольный источник", "cluster": "Отдел А"},
        "target/β": {"name": "Произвольный приёмник", "cluster": "Облако"},
        "unlabelled": {"name": "Неизвестный узел", "cluster": "Облако"},
    }
    edges = [{"source": a, "target": b, "provenance": [{"file": "fixture.xlsx", "sheet": "Граф", "cell": f"E{n}", "raw_value": b}]}
             for n, (a, b) in enumerate([
                 ("rank/low", "target/β"), ("rank/high", "source:α"),
                 ("source:α", "target/β"), ("target/β", "source:α"),
                 ("source:α", "unlabelled"),
             ], 2)]
    return {"nodes": nodes, "edges": edges}


def test_detection_is_optional_and_does_not_change_graph():
    source = graph()
    before = deepcopy(source)
    result = detect_mandate_profile(source)
    assert source == before
    assert result["id"] == "mandate-flows-v1" and result["can_apply"]
    assert [entry["rank"] for entry in result["levels"]] == [2, 11]
    assert result["counts"] == {"levels": 2, "assignments": 2, "labeled_nodes": 2,
                                "flows": 3, "checked_flows": 2, "unchecked_flows": 1,
                                "unlabeled_nodes": 1, "marker_edges_excluded": 2, "unresolved_references": 0}
    assert not any("security_label" in node for node in source["nodes"].values())


def test_compile_directional_transfer_policy_without_acl_types_or_human_attribution():
    source = graph()
    before = deepcopy(source)
    model = compile_mandate_flows(source)
    assert source == before == model["source_graph"]
    assert not validate_model(model)
    assert model["security_policy"]["confidentiality_levels"] == ["Общий", "Закрытый"]
    assert all(n["types"] == ["unknown"] for n in model["nodes"].values())
    assert "security_label" not in model["nodes"]["unlabelled"]
    assert "security_label" not in model["nodes"]["rank/high"]
    assert model["nodes"]["source:α"]["security_label"] == {"level": "Закрытый", "categories": []}
    assert {f["predicate"] for f in model["facts"]} == {"present", "transition_enabled"}
    # Each separately enumerated flow has a complete, isolated transition
    # context. This does NOT close unknown/unlabelled flows or grant edits.
    assert len(model["completeness"]) == len(model["transitions"]) == 2
    assert all(scope["predicate"] == "transitions" and scope["complete"] is True
               for scope in model["completeness"])
    assert not model["mutable"]
    assert not model.get("fls_channels") and not model.get("action_catalog")
    assert len({t["scenario"] for t in model["transitions"]}) == 2
    result = analyze(model)
    assert not result["model_errors"]
    assert result["summary"] == {"FAIL": 1, "PASS": 1, "UNKNOWN": 1}
    failure = next(r for r in result["results"] if r["status"] == "FAIL")
    assert failure["witness"]["nodes"] == ["source:α", "target/β"]
    assert len(failure["witness"]["edges"]) == 1
    assert failure["catalog_rule_ids"] == ["FT025"] and failure["catalog_scope"] == "fragment"
    assert not model["profile_coverage"]["coverage_complete"]
    assert "1 узлов на 1 связях" in result["results"][-1]["missing_semantics"][0]
    assert failure["requirement_provenance"][0]["source_references"][0]["cell"] == "E4"
    json.dumps(model, ensure_ascii=False, allow_nan=False)


def test_unlabeled_flows_are_aggregated_and_cannot_produce_empty_pass():
    source = graph()
    source["edges"] = [e for e in source["edges"] if e["source"] != "rank/high"]
    model = compile_mandate_flows(source)
    assert model["transitions"] == []
    assert len(model["requirements"]) == 1
    assert analyze(model)["summary"] == {"UNKNOWN": 1}
    assert model["profile_coverage"]["unchecked_flows"] == 3


def test_complete_labeled_scope_does_not_add_missing_label_requirement():
    source = graph()
    source["edges"].pop()
    model = compile_mandate_flows(source)
    assert model["profile_coverage"]["coverage_complete"]
    assert len(model["requirements"]) == 2
    assert analyze(model)["summary"] == {"PASS": 1, "FAIL": 1}


def test_raw_semantic_attributes_cannot_supply_labels_clearance_or_facts():
    source = graph()
    source["edges"][0]["source"] = "rank/high"  # Both assigned endpoints are high.
    source["nodes"]["source:α"].update(
        clearance={"level": "Общий", "categories": []},
        clearance_provenance=[{"kind": "foreign", "value": "low ceiling"}],
        field_provenance={"clearance": [{"kind": "foreign"}], "name": [{"cell": "C1"}]},
        enabled=False, healthy=False,
    )
    source["nodes"]["unlabelled"].update(
        security_label={"level": "Чужой высокий уровень", "categories": []},
        integrity_label={"level": "Чужая целостность", "categories": []},
        security_label_provenance=[{"kind": "foreign"}],
        integrity_label_provenance=[{"kind": "foreign"}],
        field_provenance={"security_label": [{"kind": "foreign"}], "integrity_label": [{"kind": "foreign"}]},
    )
    before = deepcopy(source)
    model = compile_mandate_flows(source)
    assert source == before == model["source_graph"]
    assert analyze(model)["summary"] == {"PASS": 2, "UNKNOWN": 1}
    assert model["profile_coverage"]["labeled_nodes"] == 2
    assert model["profile_coverage"]["unchecked_flows"] == 1
    assert "clearance" not in model["nodes"]["source:α"]
    assert "clearance_provenance" not in model["nodes"]["source:α"]
    assert model["nodes"]["source:α"]["field_provenance"] == {"name": [{"cell": "C1"}]}
    for field in ("security_label", "integrity_label", "security_label_provenance", "integrity_label_provenance"):
        assert field not in model["nodes"]["unlabelled"]
    assert model["nodes"]["unlabelled"]["field_provenance"] == {}
    assert {f["predicate"] for f in model["facts"]} == {"present", "transition_enabled"}


def test_unresolved_source_references_prevent_complete_scope_claim():
    source = graph()
    source["edges"].pop()
    source["issues"] = [{"kind": "ambiguous_reference"}, {"kind": "unresolved_reference"},
                        {"kind": "asymmetric_declaration"}]
    model = compile_mandate_flows(source)
    assert model["profile_coverage"]["unresolved_references"] == 2
    assert not model["profile_coverage"]["coverage_complete"]
    assert analyze(model)["summary"] == {"PASS": 1, "FAIL": 1, "UNKNOWN": 1}
    assert "2 исходных ссылок" in model["requirements"][-1]["missing"][0]


@pytest.mark.parametrize("name,cluster", [
    ("Мандат 1 — Открытый", "Другая группа"), ("Мандат 01 — Открытый", "Мандаты"),
    ("Мандат 0 — Открытый", "Мандаты"), ("Мандат 1: Открытый", "Мандаты"),
    ("Допуск 1 — Открытый", "Мандаты"),
])
def test_detection_requires_exact_declared_cluster_and_name_grammar(name, cluster):
    source = {"nodes": {"anything": {"name": name, "cluster": cluster}}, "edges": []}
    assert detect_mandate_profile(source) is None
    with pytest.raises(ValueError, match="не найден профиль"):
        compile_mandate_flows(source)


@pytest.mark.parametrize("conflict", ["assignment", "rank", "label", "marker_target"])
def test_conflicts_are_reported_then_rejected_without_selecting_a_label(conflict):
    source = graph()
    if conflict == "assignment":
        source["edges"].append({"source": "rank/low", "target": "source:α"})
    elif conflict == "rank":
        source["nodes"]["rank/high"]["name"] = "Мандат 2 — Закрытый"
    elif conflict == "label":
        source["nodes"]["rank/high"]["name"] = "Мандат 11 — Общий"
    else:
        source["edges"].append({"source": "rank/low", "target": "rank/high"})
    before = deepcopy(source)
    descriptor = detect_mandate_profile(source)
    assert not descriptor["can_apply"] and descriptor["diagnostics"]
    with pytest.raises(ValueError, match=r"\$\.profile"):
        compile_mandate_flows(source)
    assert source == before


def test_incoming_marker_edge_is_not_a_reverse_assignment_or_data_flow():
    source = graph()
    source["edges"].append({"source": "unlabelled", "target": "rank/low"})
    descriptor = detect_mandate_profile(source)
    assert descriptor["can_apply"]
    assert descriptor["diagnostics"][0]["kind"] == "incoming_mandate_edge"
    assert descriptor["counts"]["marker_edges_excluded"] == 3
    model = compile_mandate_flows(source)
    assert "security_label" not in model["nodes"]["unlabelled"]
    assert len(model["transitions"]) == 2


@pytest.mark.parametrize("mutate,path", [
    (lambda g: g.update(nodes=[]), "nodes"),
    (lambda g: g.update(edges={}), "edges"),
    (lambda g: g["nodes"]["source:α"].update(name=4), "name"),
    (lambda g: g["nodes"]["source:α"].update(cluster=[]), "cluster"),
    (lambda g: g["nodes"]["source:α"].update(key="wrong"), "key"),
    (lambda g: g["edges"][0].update(target="missing"), "target"),
    (lambda g: g["edges"][0].update(source=[]), "source"),
    (lambda g: g["edges"][0].update(provenance=[None]), "provenance"),
    (lambda g: g.update(metadata=[]), "metadata"),
    (lambda g: g.update(issues="hidden"), "issues"),
    (lambda g: g.update(extra=float("nan")), "JSON"),
])
def test_invalid_graphs_fail_before_compilation(mutate, path):
    source = graph()
    mutate(source)
    with pytest.raises(ValueError, match=path):
        validate_input_graph(source)


def test_limits_are_explicit_and_do_not_truncate(monkeypatch):
    source = graph()
    monkeypatch.setattr("analyzer.structural_profiles.MAX_NODES", 4)
    with pytest.raises(ValueError, match="не более 4 узлов"):
        validate_input_graph(source)
    monkeypatch.setattr("analyzer.structural_profiles.MAX_NODES", 5000)
    monkeypatch.setattr("analyzer.structural_profiles.MAX_EDGES", 4)
    with pytest.raises(ValueError, match="не более 4 рёбер"):
        validate_input_graph(source)
    monkeypatch.setattr("analyzer.structural_profiles.MAX_EDGES", 20000)
    monkeypatch.setattr("analyzer.structural_profiles.MAX_REQUIREMENTS", 2)
    assert not detect_mandate_profile(source)["can_apply"]
    with pytest.raises(ValueError, match="Профиль ограничен"):
        compile_mandate_flows(source)


def test_edge_permutation_keeps_requirement_ids_and_arbitrary_renaming_keeps_results():
    source = graph()
    first = compile_mandate_flows(source)
    permuted = deepcopy(source)
    permuted["nodes"] = dict(reversed(list(permuted["nodes"].items())))
    permuted["edges"].reverse()
    second = compile_mandate_flows(permuted)
    assert [r["id"] for r in first["requirements"]] == [r["id"] for r in second["requirements"]]
    assert analyze(first)["summary"] == analyze(second)["summary"]
    keys = {key: "новое имя / " + str(i) for i, key in enumerate(source["nodes"])}
    renamed = {"nodes": {keys[key]: deepcopy(node) for key, node in source["nodes"].items()},
               "edges": [{**deepcopy(edge), "source": keys[edge["source"]], "target": keys[edge["target"]]} for edge in source["edges"]]}
    third = compile_mandate_flows(renamed)
    assert analyze(third)["summary"] == analyze(first)["summary"]
    assert third["profile_coverage"] == first["profile_coverage"]
    failure = next(r for r in analyze(third)["results"] if r["status"] == "FAIL")
    assert failure["witness"]["nodes"] == [keys["source:α"], keys["target/β"]]
