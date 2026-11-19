import copy
import itertools
import random

import pytest

from analyzer.engine import Engine, analyze, reachability, structural_reachability
from analyzer.logic import TRUE, FALSE, UNKNOWN, conjunction, disjunction, negate, exists, forall
from analyzer.model import FactBase, empty_model, fact
from analyzer.transitions import apply_actions, disable_component, fail_component, remove_component


def fixture():
    m = empty_model("baseline", "test")
    types = {"user": ["subject"], "attacker": ["subject"], "file": ["data"],
             "cpu": ["component"], "os": ["component"], "guard": ["component"],
             "alt": ["component"], "a": ["component"], "b": ["component"],
             "event": ["event"], "logger": ["component"], "backup": ["data", "component"],
             "key": ["key"], "channel": ["channel"], "change": ["change"],
             "role_a": ["role"], "role_b": ["role"]}
    m["nodes"] = {key: {"types": ts, "name": key} for key, ts in types.items()}
    complete(m, "dependencies", [])
    for key in m["nodes"]:
        for predicate in ("present", "enabled", "healthy"):
            put(m, predicate, [key], "TRUE", mutable=True)
    return m


def put(m, predicate, args, value, mutable=False):
    m["facts"] = [f for f in m["facts"] if (f["predicate"], f["args"]) != (predicate, args)]
    m["facts"].append(fact(predicate, args, value, [{"file": "unit fixture", "kind": "declared", "state": m["state"], "raw_value": value, "transformation": "explicit fixture"}]))
    if mutable:
        entry = {"predicate": predicate, "args": args}
        if entry not in m["mutable"]:
            m["mutable"].append(entry)


def complete(m, predicate, args_prefix):
    m["completeness"].append({"predicate": predicate, "args_prefix": args_prefix, "complete": True,
                              "provenance": [{"kind": "declared", "file": "unit fixture"}]})


def req(m, checker, obj="file", **kwargs):
    item = {"id": checker + ":" + obj + ":" + str(len(m["requirements"])), "checker": checker, "object": obj, **kwargs}
    m["requirements"].append(item)
    return item


def transition(m, source, target, *, subject="user", op="read", conditions=None, via=None, scenario="default"):
    item = {"id": "t" + str(len(m["transitions"])), "source": source, "target": target,
            "subject": subject, "operation": op, "scenario": scenario, "conditions": conditions or [],
            "value": "TRUE", "provenance": [{"kind": "declared", "file": "unit fixture"}]}
    if via:
        item["via"] = via
    m["transitions"].append(item)
    return item


def status(m):
    report = analyze(m)
    assert not report["model_errors"], report
    return [r["status"] for r in report["results"]]


def test_complete_scope_cannot_hide_explicitly_incomplete_subscope():
    m = fixture()
    m['completeness'] += [
        {'predicate': 'transitions', 'args_prefix': [], 'complete': True},
        {'predicate': 'transitions', 'args_prefix': ['user', 'read'], 'complete': False}]
    assert analyze(m)['summary'] == {'MODEL_ERROR': 1}
    # An incomplete large domain can contain a completely described subdomain.
    m['completeness'][-2]['complete'] = False
    m['completeness'][-1]['complete'] = True
    assert not analyze(m)['model_errors']


def test_strong_kleene_and_incomplete_quantifiers():
    assert conjunction([FALSE, UNKNOWN]) == FALSE
    assert disjunction([TRUE, UNKNOWN]) == TRUE
    assert negate(UNKNOWN) == UNKNOWN
    assert exists([], False) == UNKNOWN
    assert exists([], True) == FALSE
    assert forall([], False) == UNKNOWN
    assert forall([], True) == TRUE
    assert exists([TRUE], False) == TRUE


def test_raw_connectivity_never_proves_permission():
    m = fixture()
    m["raw_graph"] = {"edges": [["user", "a"], ["a", "file"]]}
    assert structural_reachability(m, "user", "file") == ["user", "a", "file"]
    req(m, "forbidden_operation", subject="user", operation="read")
    assert status(m) == ["UNKNOWN"]
    complete(m, "transitions", ["user", "read", "default", "access"])
    assert status(m) == ["PASS"]


def test_forbidden_policy_does_not_filter_actual_acl():
    m = fixture()
    put(m, "acl", ["user", "file", "read"], "TRUE", True)
    transition(m, "user", "file", conditions=[{"predicate": "acl", "args": ["user", "file", "read"]}])
    req(m, "forbidden_operation", subject="user", operation="read")
    assert status(m) == ["FAIL"]
    report = analyze(m)["results"][0]
    assert report["witness"]["nodes"] == ["user", "file"]
    assert any(f.get("predicate") == "acl" for f in report["evidence"])
    put(m, "acl", ["user", "file", "read"], "UNKNOWN")
    assert status(m) == ["UNKNOWN"]


def test_subject_operation_and_scenario_context_cannot_mix():
    m = fixture()
    transition(m, "user", "a")
    transition(m, "a", "file", subject="attacker")
    transition(m, "a", "file", op="write")
    transition(m, "a", "file", scenario="other")
    complete(m, "transitions", ["user", "read", "default", "access"])
    assert reachability(m, "user", "file", "read")["value"] == FALSE


def test_one_remaining_bypass_preserves_violation():
    m = fixture()
    for node in ("a", "b"):
        put(m, "acl", ["attacker", node, "read"], "TRUE", True)
        transition(m, "attacker", node, subject="attacker", conditions=[{"predicate": "acl", "args": ["attacker", node, "read"]}])
        transition(m, node, "file", subject="attacker")
    req(m, "forbidden_operation", subject="attacker", operation="read")
    complete(m, "transitions", ["attacker", "read", "default", "access"])
    close_a = {"id": "close_a", "effects": [{"predicate": "acl", "args": ["attacker", "a", "read"], "value": "FALSE"}]}
    close_b = {"id": "close_b", "effects": [{"predicate": "acl", "args": ["attacker", "b", "read"], "value": "FALSE"}]}
    assert status(apply_actions(m, [close_a])) == ["FAIL"]
    assert status(apply_actions(m, [close_a, close_b])) == ["PASS"]
    assert status(m) == ["FAIL"]  # snapshot is immutable


def test_logger_state_changes_do_not_change_access_and_alternative_works():
    m = fixture()
    transition(m, "user", "file")
    put(m, "event_possible", ["event"], "TRUE")
    put(m, "logger", ["event", "logger"], "TRUE")
    complete(m, "logger", ["event"])
    req(m, "logging", "event")
    req(m, "required_operation", subject="user", operation="read")
    assert status(m) == ["PASS", "PASS"]
    changed = disable_component(m, "logger")
    assert status(changed) == ["FAIL", "PASS"]
    put(changed, "logger", ["event", "alt"], "TRUE")
    assert status(changed) == ["PASS", "PASS"]


def test_missing_mechanism_needs_complete_alternatives():
    m = fixture()
    req(m, "protection", control="filtering")
    assert status(m) == ["UNKNOWN"]
    complete(m, "cover", ["file", "filtering"])
    assert status(m) == ["FAIL"]
    put(m, "cover", ["file", "filtering", "guard"], "TRUE")
    assert status(m) == ["PASS"]


def test_removing_password_does_not_bypass_alternative_authentication():
    m = fixture()
    put(m, "cover", ["file", "authentication", "guard"], "TRUE")
    put(m, "cover", ["file", "authentication", "alt"], "TRUE")
    complete(m, "cover", ["file", "authentication"])
    req(m, "authentication")
    assert status(remove_component(m, "guard")) == ["PASS"]
    assert status(remove_component(remove_component(m, "guard"), "alt")) == ["FAIL"]


def test_removal_never_creates_path_but_disabling_filtering_can():
    m = fixture()
    transition(m, "attacker", "file", subject="attacker", via="guard",
               conditions=[{"predicate": "enabled", "args": ["guard"], "expected": "FALSE"}])
    complete(m, "transitions", ["attacker", "read", "default", "access"])
    assert reachability(m, "attacker", "file", "read")["value"] == FALSE
    assert reachability(disable_component(m, "guard"), "attacker", "file", "read")["value"] == TRUE
    assert reachability(remove_component(m, "guard"), "attacker", "file", "read")["value"] == FALSE


def test_explicit_fail_open_and_fail_closed_transport_semantics():
    m = fixture()
    put(m, "failure_mode", ["guard"], "normal", True)
    put(m, "transport_enabled", ["guard"], "TRUE", True)
    transition(m, "user", "file", via="guard", conditions=[{"predicate": "transport", "args": ["guard"]}])
    complete(m, "transitions", ["user", "read", "default", "access"])
    assert reachability(fail_component(m, "guard", "fail_open"), "user", "file", "read")["value"] == TRUE
    assert reachability(fail_component(m, "guard", "fail_closed"), "user", "file", "read")["value"] == FALSE


def test_dependency_cycle_is_not_self_supporting_and_or_has_ground():
    m = fixture()
    m["dependencies"] = {"a": {"all": ["b"]}, "b": {"all": ["a"]}}
    req(m, "required_function", "a")
    assert status(m) == ["UNKNOWN"]
    m["dependencies"]["b"] = {"any": ["a", "cpu"]}
    assert status(m) == ["PASS"]
    put(m, "healthy", ["cpu"], "FALSE")
    assert status(m) == ["UNKNOWN"]
    m["dependencies"] = {"a": {"all": ["b", "cpu"]}, "b": {"all": ["a"]}}
    assert status(m) == ["FAIL"]


def test_dependency_failures_reach_mandatory_service():
    m = fixture()
    m["dependencies"] = {"os": {"all": ["cpu"]}, "a": {"any": ["os", "alt"]}}
    req(m, "required_function", "a")
    put(m, "healthy", ["cpu"], "FALSE")
    assert status(m) == ["PASS"]
    put(m, "healthy", ["alt"], "FALSE")
    assert status(m) == ["FAIL"]


def test_redundancy_not_implied_by_two_nodes_and_common_dependency():
    m = fixture()
    req(m, "redundancy", replicas=["a", "b"], replicas_complete=True)
    assert status(m) == ["UNKNOWN"]
    put(m, "independent", ["a", "b"], "TRUE")
    assert status(m) == ["PASS"]
    m["dependencies"] = {"a": {"all": ["cpu"]}, "b": {"all": ["cpu"]}}
    assert status(m) == ["FAIL"]
    assert analyze(m)["results"][0]["common_dependencies"] == [{"replicas": ["a", "b"], "dependencies": ["cpu"]}]


def test_backup_requires_accessible_key_and_complete_key_inventory():
    m = fixture()
    put(m, "backup", ["file", "backup"], "TRUE")
    put(m, "readable", ["backup"], "TRUE")
    complete(m, "backup", ["file"])
    req(m, "recovery")
    assert status(m) == ["UNKNOWN"]
    put(m, "key_required", ["backup", "key"], "TRUE")
    put(m, "key_accessible", ["key"], "FALSE")
    complete(m, "key_required", ["backup"])
    assert status(m) == ["FAIL"]
    put(m, "key_accessible", ["key"], "TRUE")
    assert status(m) == ["PASS"]


def test_model_contradiction_is_not_a_policy_violation():
    m = fixture()
    req(m, "required_function", "os")
    m["facts"].append(fact("healthy", ["os"], "FALSE"))
    assert analyze(m)["summary"] == {"MODEL_ERROR": 1}
    m = fixture()
    req(m, "required_operation", subject="user", operation="read")
    req(m, "forbidden_operation", subject="user", operation="read")
    assert analyze(m)["model_errors"][0]["code"] == "CONTRADICTORY_POLICY"
    m = fixture()
    req(m, "configuration", "os", predicate="trusted_boot")
    put(m, "trusted_boot", ["os"], "FALSE")
    assert status(m) == ["FAIL"]


def test_supported_statuses_are_distinct():
    m = fixture()
    req(m, "unknown_checker")
    req(m, "configuration", "os", applicable="FALSE")
    req(m, "configuration", "os", applicable="UNKNOWN")
    req(m, "evidence", "os", document="certification")
    assert status(m) == ["NOT_CHECKED", "NOT_APPLICABLE", "UNKNOWN", "REQUIRES_EVIDENCE"]


def test_roles_change_integrity_crypto_checks():
    m = fixture()
    for role in ("role_a", "role_b"):
        put(m, "has_role", ["user", role], "TRUE")
    put(m, "changed", ["change"], "TRUE")
    put(m, "approved", ["change"], "FALSE")
    put(m, "integrity", ["file"], "FALSE")
    put(m, "crypto_protected", ["channel"], "FALSE")
    req(m, "incompatible_roles", "file", subject="user", roles=["role_a", "role_b"])
    req(m, "authorized_change", "change")
    req(m, "configuration", predicate="integrity")
    req(m, "crypto", "channel")
    assert status(m) == ["FAIL"] * 4


def test_passive_quantum_exposure_never_creates_active_permissions():
    m = fixture()
    put(m, "crypto_algorithm", ["channel"], "RSA")
    put(m, "crypto_function", ["channel"], "key_exchange")
    put(m, "crypto_bits", ["channel"], "2048")
    put(m, "observes", ["attacker", "channel"], "TRUE")
    put(m, "material_available", ["attacker", "channel"], "TRUE")
    put(m, "quantum_capable", ["attacker", "test-horizon"], "TRUE")
    put(m, "horizon_valid", ["channel", "test-horizon"], "TRUE")
    req(m, "quantum", "channel", subject="attacker", horizon="test-horizon")
    req(m, "required_operation", subject="attacker", operation="read")
    req(m, "forbidden_operation", subject="attacker", operation="write")
    complete(m, "transitions", ["attacker"])
    assert status(m) == ["FAIL", "FAIL", "PASS"]
    put(m, "crypto_algorithm", ["channel"], "UNKNOWN")
    assert status(m)[0] == "UNKNOWN"


def test_unknown_and_policy_and_derived_mutations_rejected():
    m = fixture()
    put(m, "acl", ["user", "file", "read"], "UNKNOWN", True)
    for predicate, args in [("acl", ["user", "file", "read"]), ("can_perform", ["user", "file", "read"]), ("required", ["file"])]:
        m["mutable"].append({"predicate": predicate, "args": args})
        with pytest.raises(ValueError):
            apply_actions(m, [{"id": "invalid", "effects": [{"predicate": predicate, "args": args, "value": "TRUE"}]}])
    put(m, "evidence", ["os", "certificate"], "FALSE", True)
    with pytest.raises(ValueError):
        apply_actions(m, [{"id": "invent", "effects": [{"predicate": "evidence", "args": ["os", "certificate"], "value": "TRUE"}]}])


def test_atomic_preconditions_and_conflicts():
    m = fixture()
    action = {"id": "off", "preconditions": [{"predicate": "acl", "args": ["user", "file", "read"], "value": "TRUE"}],
              "effects": [{"predicate": "enabled", "args": ["os"], "value": "FALSE"}]}
    with pytest.raises(ValueError):
        apply_actions(m, [action])
    action.pop("preconditions")
    other = {"id": "on", "effects": [{"predicate": "enabled", "args": ["os"], "value": "TRUE"}]}
    with pytest.raises(ValueError):
        apply_actions(m, [action, other])
    before = copy.deepcopy(m)
    after = apply_actions(m, [action], "new")
    assert m == before
    assert after["parent_state"] == "baseline"
    assert after["diff"][0]["before"] == "TRUE"


def test_negative_recursive_or_identity_changing_program_is_diagnosed():
    m = fixture()
    m["dependencies"] = {"a": {"not": ["b"]}}
    assert analyze(m)["summary"] == {"MODEL_ERROR": 1}
    m = fixture()
    t = transition(m, "user", "file")
    t["switch_subject"] = "attacker"
    assert analyze(m)["summary"] == {"MODEL_ERROR": 1}


def test_reachability_matches_independent_warshall_on_small_complete_graphs():
    rng = random.Random(42)
    for _ in range(20):
        m = fixture()
        keys = ["user", "a", "b", "file"]
        reachable = {(a, b): False for a in keys for b in keys}
        for a, b in itertools.product(keys, repeat=2):
            if a != b and rng.random() < .35:
                transition(m, a, b)
                reachable[a, b] = True
        for mid in keys:
            for a in keys:
                for b in keys:
                    reachable[a, b] |= reachable[a, mid] and reachable[mid, b]
        complete(m, "transitions", ["user", "read", "default", "access"])
        for target in keys:
            value = reachability(m, "user", target, "read")["value"]
            assert (value == TRUE) == reachable["user", target]


def test_permuting_facts_nodes_requirements_preserves_semantics():
    m = fixture()
    transition(m, "user", "file")
    req(m, "forbidden_operation", subject="user", operation="read")
    req(m, "required_function", "os")
    expected = {r["id"]: r["status"] for r in analyze(m)["results"]}
    changed = copy.deepcopy(m)
    changed["facts"].reverse()
    changed["nodes"] = dict(reversed(list(changed["nodes"].items())))
    changed["requirements"].reverse()
    assert {r["id"]: r["status"] for r in analyze(changed)["results"]} == expected


def test_unknown_dependency_inventory_cannot_prove_working_function():
    m = fixture()
    m["completeness"] = []
    req(m, "required_function", "os")
    assert status(m) == ["UNKNOWN"]
    m["dependencies"]["os"] = {"all": []}
    assert status(m) == ["PASS"]


def test_consistent_key_renaming_preserves_semantics_including_symmetry():
    m = fixture()
    put(m, "independent", ["a", "b"], "TRUE")
    req(m, "redundancy", replicas=["a", "b"], replicas_complete=True)
    transition(m, "user", "a")
    transition(m, "a", "file")
    req(m, "forbidden_operation", subject="user", operation="read")
    mapping = {key: f"renamed-{len(m['nodes']) - i}" for i, key in enumerate(m["nodes"])}
    renamed = copy.deepcopy(m)
    renamed["nodes"] = {mapping[key]: value for key, value in m["nodes"].items()}
    for entry in renamed["facts"]:
        entry["args"] = [mapping.get(arg, arg) for arg in entry["args"]]
    for entry in renamed["mutable"]:
        entry["args"] = [mapping.get(arg, arg) for arg in entry["args"]]
    for entry in renamed["transitions"]:
        for field in ("subject", "source", "target", "via"):
            if field in entry:
                entry[field] = mapping[entry[field]]
    for entry in renamed["requirements"]:
        for field in ("subject", "object"):
            if field in entry:
                entry[field] = mapping[entry[field]]
        for field in ("replicas", "roles"):
            if field in entry:
                entry[field] = [mapping[value] for value in entry[field]]
    assert status(m) == status(renamed) == ["PASS", "FAIL"]


def test_bad_applicability_or_condition_is_reported_as_model_error():
    m = fixture()
    req(m, "configuration", "os", applicable="MAYBE")
    assert analyze(m)["summary"] == {"MODEL_ERROR": 1}
    m = fixture()
    transition(m, "user", "file", conditions=[{"predicate": "acl", "args": ["file"]}])
    assert analyze(m)["summary"] == {"MODEL_ERROR": 1}
    m = fixture()
    req(m, "incompatible_roles", "file", subject="user", roles=[])
    assert analyze(m)["model_errors"]


def test_allowed_policy_is_immutable_permission_not_obligation():
    m = fixture()
    permission = {"subject": "user", "object": "file", "operation": "read"}
    m["policy"]["allowed"].append(permission)
    req(m, "required_operation", subject="user", operation="read")
    complete(m, "transitions", ["user", "read", "default", "access"])
    assert status(m) == ["FAIL"]  # permission does not provide the actual operation
    changed = disable_component(m, "guard")
    assert changed["policy"] == m["policy"]
    req(m, "forbidden_operation", subject="user", operation="read")
    assert analyze(m)["model_errors"][0]["code"] == "CONTRADICTORY_POLICY"
    m["requirements"] = []
    m["mutable"].append({"predicate": "policy", "args": ["user", "file", "read"]})
    with pytest.raises(ValueError):
        apply_actions(m, [{"id": "change-policy", "effects": [
            {"predicate": "policy", "args": ["user", "file", "read"], "value": "FALSE"}]}])


def test_allowed_policy_contradicts_explicit_prohibition():
    m = fixture()
    m["policy"]["allowed"].append({"subject": "user", "object": "file", "operation": "read"})
    req(m, "forbidden_operation", subject="user", operation="read")
    assert any(e["code"] == "CONTRADICTORY_POLICY" for e in analyze(m)["model_errors"])


def test_flow_requirement_and_access_prohibition_are_distinct_contexts():
    m = fixture()
    req(m, "forbidden_operation", subject="user", operation="read", kind="access")
    req(m, "required_operation", subject="user", operation="read", kind="flow")
    assert status(m) == ["UNKNOWN", "UNKNOWN"]


def test_conflicting_completeness_is_a_model_error_not_closed_world_win():
    m = fixture()
    complete(m, "cover", ["file", "filtering"])
    m["completeness"].append({"predicate": "cover", "args_prefix": ["file", "filtering"], "complete": False})
    req(m, "protection", control="filtering")
    assert any(e["code"] == "CONFLICTING_COMPLETENESS" for e in analyze(m)["model_errors"])


def test_malformed_effect_and_stale_state_id_rejected_without_snapshot_mutation():
    m = fixture()
    before = copy.deepcopy(m)
    m["mutable"].append({"predicate": "present", "args": ["absent"]})
    with pytest.raises(ValueError):
        apply_actions(m, [{"id": "bad", "effects": [{"predicate": "present", "args": ["absent"], "value": "TRUE"}]}])
    with pytest.raises(ValueError):
        apply_actions(before, [], new_state="baseline")
    assert before["state"] == "baseline"


@pytest.mark.parametrize('bad_value', [None, [], 'text', 12])
def test_malformed_top_level_is_model_error(bad_value):
    assert analyze(bad_value)["summary"] == {"MODEL_ERROR": 1}


@pytest.mark.parametrize('mutate', [
    lambda m: m.update(nodes=[]),
    lambda m: m.update(dependencies={"a": "b"}),
    lambda m: m["facts"].append({"predicate": ["acl"], "args": [], "value": "TRUE"}),
    lambda m: m["facts"].append({"predicate": "acl", "args": [["user"], "file", "read"], "value": "TRUE"}),
    lambda m: m["facts"].append({"predicate": "present", "args": ["file"]}),
    lambda m: m["transitions"].append({"id": "invalid", "source": "user", "target": "file", "subject": "user", "operation": "read", "conditions": ["text"]}),
    lambda m: m["requirements"].append({"id": "invalid", "checker": ["required_function"], "object": "os"}),
    lambda m: m.update(policy={"allowed": "everyone"}),
])
def test_malformed_json_fields_produce_model_error_instead_of_exception(mutate):
    m = fixture()
    mutate(m)
    assert analyze(m)["summary"] == {"MODEL_ERROR": 1}


def test_event_possibility_cannot_be_erased_to_repair_missing_logging():
    m = fixture()
    put(m, "event_possible", ["event"], "TRUE", mutable=True)
    complete(m, "logger", ["event"])
    req(m, "logging", "event")
    assert status(m) == ["FAIL"]
    with pytest.raises(ValueError, match="immutable"):
        apply_actions(m, [{"id": "erase-event", "effects": [
            {"predicate": "event_possible", "args": ["event"], "value": "FALSE"}]}])
    assert status(m) == ["FAIL"]


def test_unknown_failure_behavior_preserves_possible_fail_open_transport():
    m = fixture()
    put(m, "transport_enabled", ["guard"], "TRUE")
    transition(m, "user", "file", via="guard", conditions=[{"predicate": "transport", "args": ["guard"]}])
    complete(m, "transitions", ["user", "read", "default", "access"])
    assert reachability(m, "user", "file", "read")["value"] == TRUE
    put(m, "healthy", ["guard"], "FALSE")
    assert reachability(m, "user", "file", "read")["value"] == UNKNOWN
    put(m, "failure_mode", ["guard"], "UNKNOWN")
    assert reachability(m, "user", "file", "read")["value"] == UNKNOWN
    put(m, "failure_mode", ["guard"], "normal")
    assert reachability(m, "user", "file", "read")["value"] == FALSE
    put(m, "failure_mode", ["guard"], "fail_open")
    assert reachability(m, "user", "file", "read")["value"] == TRUE
    put(m, "healthy", ["guard"], "TRUE")
    put(m, "failure_mode", ["guard"], "fail_closed")
    assert reachability(m, "user", "file", "read")["value"] == FALSE
