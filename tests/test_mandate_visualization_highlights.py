"""Mandate-flow failures must highlight proven edges without alleging users."""
from copy import deepcopy

from analyzer.engine import analyze
from analyzer.transitions import apply_actions
from analyzer.structural_profiles import compile_mandate_flows
from analyzer.visualization import build_graph


def _source_graph():
    return {
        "nodes": {
            "low-level": {"name": "Мандат 1 — Общий", "cluster": "Мандаты"},
            "high-level": {"name": "Мандат 3 — Секретный", "cluster": "Мандаты"},
            "a": {"name": "А", "cluster": "ПК 1"},
            "b": {"name": "Б", "cluster": "ПК 2"},
        },
        "edges": [
            {"source": "high-level", "target": "a"},
            {"source": "low-level", "target": "b"},
            {"source": "a", "target": "b"},  # confirmed forbidden flow
            {"source": "b", "target": "a"},  # allowed flow
        ],
    }


def test_proven_mandate_flow_red_before_green_after_without_user_accusation():
    model = compile_mandate_flows(_source_graph())
    original = deepcopy(model)
    before = build_graph(model, analyze(model))
    assert before["summary"]["fail_count"] == 1
    flow_edges = [edge for edge in before["edges"] if edge["kind"] == "flow"]
    assert len(flow_edges) == 2
    forbidden = [edge for edge in flow_edges if edge["source"] == "a"]
    allowed = [edge for edge in flow_edges if edge["source"] == "b"]
    assert len(forbidden) == len(allowed) == 1
    assert forbidden[0]["witness"] and forbidden[0]["value"] == "TRUE"
    assert not allowed[0]["witness"]
    assert not any(edge["witness"] for edge in before["edges"] if edge["kind"] == "structural")
    assert before["summary"]["violators"] == []
    assert not any(node["is_violator"] for node in before["nodes"])

    identifier = forbidden[0]["transition_id"]
    editable = deepcopy(model)
    editable["mutable"].append({"predicate": "transition_enabled", "args": [identifier]})
    changed = apply_actions(editable, [{"id": "revoke-test-flow",
        "effects": [{"predicate": "transition_enabled", "args": [identifier], "value": "FALSE"}]}],
        new_state="after")
    after = build_graph(changed, analyze(changed))
    after_flow = {edge["id"]: edge for edge in after["edges"] if edge["kind"] == "flow"}
    repaired_edge = after_flow[forbidden[0]["id"]]
    assert repaired_edge["value"] == "FALSE" and repaired_edge["blocked"]
    assert repaired_edge["changed"] and not repaired_edge["witness"]
    assert after["summary"]["fail_count"] == 0
    assert model == original  # visual projection and repair do not mutate source


def test_unknown_or_unproven_flow_is_never_marked_red():
    model = compile_mandate_flows(_source_graph())
    for fact in model["facts"]:
        if fact["predicate"] == "transition_enabled" and fact["args"][0] == next(
            tr["id"] for tr in model["transitions"] if tr["source"] == "a"
        ):
            fact["value"] = "UNKNOWN"
    projected = build_graph(model)
    assert not any(edge["witness"] for edge in projected["edges"] if edge["kind"] == "flow")
