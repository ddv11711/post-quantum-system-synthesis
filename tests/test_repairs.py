"""Independent finite-space checks of repair safety and lexicographic optimality."""
from copy import deepcopy
from itertools import combinations
import json
from pathlib import Path
import random

import pytest

from analyzer.engine import analyze
from analyzer.importers import compare_sources, load_html, load_xlsx
from analyzer.model import empty_model, fact
from analyzer.profiles import apply_profile, comparison_model, imported_model
from analyzer.repairs import find_repairs, generate_candidates
from analyzer.transitions import apply_actions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('actions', [{}, ['bad'], [{'id': 'bad', 'effects': [{'args': []}]}]])
def test_malformed_external_actions_have_explicit_status(actions):
    assert find_repairs(access_fixture(), actions)['status'] == 'INVALID_ACTION_SPACE'


def test_malformed_model_never_enters_candidate_generation():
    assert find_repairs(None)['status'] == 'MODEL_ERROR'
    model = access_fixture()
    model['action_catalog'] = [{'targets': ['deny-read'], 'effects': []}]
    assert find_repairs(model)['status'] == 'MODEL_ERROR'


def action(identifier, predicate, args, value, cost=1, **extra):
    return {"id": identifier, "cost": cost, "effects": [{"predicate": predicate, "args": args, "value": value}], **extra}


def working(model, key, types=None):
    model["nodes"][key] = {"types": types or ["component"]}
    model["facts"].extend(fact(predicate, [key]) for predicate in ("present", "enabled", "healthy"))
    model["dependencies"][key] = {"all": []}


def mutate_permission(model, predicate, args):
    model["mutable"].append({"predicate": predicate, "args": args})


def access_fixture(two_paths=False):
    model = empty_model("attack", "isolated-fixture")
    working(model, "attacker", ["subject"])
    working(model, "data", ["data"])
    for index in range(2 if two_paths else 1):
        interface = f"interface-{index}"
        working(model, interface)
        model["facts"].append(fact("acl", ["attacker", interface, "read"]))
        mutate_permission(model, "acl", ["attacker", interface, "read"])
        model["transitions"].extend([
            {"id": f"enter-{index}", "source": "attacker", "target": interface,
             "subject": "attacker", "operation": "read", "conditions": [
                 {"predicate": "acl", "args": ["attacker", interface, "read"]},
                 {"predicate": "available", "args": [interface]}]},
            {"id": f"read-{index}", "source": interface, "target": "data",
             "subject": "attacker", "operation": "read"},
        ])
    model["completeness"].append({"predicate": "transitions", "args_prefix": ["attacker", "read", "default", "access"], "complete": True})
    model["requirements"] = [{"id": "deny-read", "checker": "forbidden_operation", "subject": "attacker", "object": "data", "operation": "read"}]
    return model


def exhaustive_optimum(model, actions):
    """Independent test oracle: enumerate tiny catalogs, inspect statuses directly.

    This deliberately does not call optimizer or validate_repair and does not use
    Z3. Production continues to use iterative exact-combination blocking.
    """
    before = {r["id"]: r["status"] for r in analyze(model)["results"]}
    targets = {rid for rid, status in before.items() if status == "FAIL"}
    valid = []
    for size in range(len(actions) + 1):
        for chosen in combinations(actions, size):
            try:
                changed = apply_actions(model, chosen)
            except (ValueError, TypeError, KeyError):
                continue
            report = analyze(changed)
            after = {r["id"]: r["status"] for r in report["results"]}
            if report["model_errors"] or any(after.get(rid) != "PASS" for rid in targets):
                continue
            if any(after.get(rid) != "PASS" for rid, old in before.items() if old == "PASS"):
                continue
            if any(status == "FAIL" and before.get(rid) != "FAIL" for rid, status in after.items()):
                continue
            valid.append(((size, sum(a["cost"] for a in chosen)), frozenset(a["id"] for a in chosen)))
    return min((objective for objective, _ in valid), default=None), valid


def test_joint_repair_rejects_singletons_but_does_not_block_their_superset():
    model = access_fixture(two_paths=True)
    actions = [action(f"close-{index}", "acl", ["attacker", f"interface-{index}", "read"], "FALSE") for index in range(2)]
    baseline = deepcopy(model)
    result = find_repairs(model, actions)
    expected, valid = exhaustive_optimum(model, actions)
    assert expected == (2, 2)
    assert result["status"] == "OPTIMAL_REPAIR"
    assert result["objective_value"] == list(expected)
    assert set(result["selected"]) == {"close-0", "close-1"}
    rejected = {frozenset(item["actions"]) for item in result["rejected"]}
    assert {frozenset(), frozenset({"close-0"}), frozenset({"close-1"})} <= rejected
    assert result["checked_sets"] == 4
    assert result["verification"]["summary"] == {"PASS": 1}
    assert result["independently_rechecked"] is True
    assert model == baseline


def test_minimization_is_number_of_actions_then_declared_cost():
    model = access_fixture(two_paths=True)
    actions = [action("close-0", "acl", ["attacker", "interface-0", "read"], "FALSE", cost=1),
               action("close-1", "acl", ["attacker", "interface-1", "read"], "FALSE", cost=1)]
    expensive = {"id": "both-expensive", "cost": 50, "effects": actions[0]["effects"] + actions[1]["effects"]}
    cheaper = {"id": "both-cheaper", "cost": 20, "effects": deepcopy(expensive["effects"])}
    actions.extend([expensive, cheaper])
    expected, _ = exhaustive_optimum(model, actions)
    result = find_repairs(model, actions)
    assert expected == (1, 20)
    assert result["objective_value"] == list(expected)
    assert result["selected"] == ["both-cheaper"]


def test_shared_resource_is_fully_rechecked_for_other_pcs():
    model = access_fixture()
    working(model, "nas")
    # The attacked interface depends on NAS; taking NAS down stops this access.
    model["dependencies"]["interface-0"] = {"all": ["nas"]}
    for pc in range(1, 5):
        key = f"pc-{pc}-service"
        working(model, key, ["function"])
        model["dependencies"][key] = {"all": ["nas"]}
        model["requirements"].append({"id": key, "checker": "required_function", "object": key})
    mutate_permission(model, "enabled", ["nas"])
    actions = [action("stop-nas", "enabled", ["nas"], "FALSE", cost=0),
               action("close-interface", "acl", ["attacker", "interface-0", "read"], "FALSE", cost=1)]
    result = find_repairs(model, actions)
    assert result["selected"] == ["close-interface"]
    assert result["verification"]["summary"] == {"PASS": 5}
    rejected = next(entry for entry in result["rejected"] if entry["actions"] == ["stop-nas"])
    assert all(any(f"pc-{pc}-service" in reason for reason in rejected["reasons"]) for pc in range(1, 5))
    expected, _ = exhaustive_optimum(model, actions)
    assert result["objective_value"] == list(expected)


@pytest.mark.parametrize("predicate,args", [
    ("reachable", ["attacker", "data"]),
    ("can_perform", ["attacker", "data", "read"]),
    ("required", ["data"]),
    ("evidence", ["data", "certification"]),
    ("quantum_capable", ["attacker", "horizon"]),
])
def test_optimizer_cannot_mutate_policy_evidence_adversary_or_derived_facts(predicate, args):
    model = access_fixture()
    mutate_permission(model, predicate, args)
    proposed = action("forge", predicate, args, "FALSE")
    with pytest.raises(ValueError, match="Forbidden mutation"):
        apply_actions(model, [proposed])
    result = find_repairs(model, [proposed])
    assert result["status"] == "NO_VALID_REPAIR_IN_ACTION_SPACE"


def test_unknown_facts_and_unconfirmed_preconditions_are_not_repair_resources():
    model = access_fixture()
    model["facts"].append(fact("integrity", ["data"], "UNKNOWN"))
    mutate_permission(model, "integrity", ["data"])
    with pytest.raises(ValueError, match="cannot resolve UNKNOWN"):
        apply_actions(model, [action("pretend-integrity", "integrity", ["data"], "TRUE")])
    proposed = action("conditional-close", "acl", ["attacker", "interface-0", "read"], "FALSE",
                      preconditions=[{"predicate": "integrity", "args": ["data"], "value": "TRUE"}])
    result = find_repairs(model, [proposed])
    assert result["status"] == "NO_VALID_REPAIR_IN_ACTION_SPACE"
    assert any("precondition is not confirmed" in reason for entry in result["rejected"] for reason in entry["reasons"])


def test_conflicting_atomic_effects_and_dependencies_are_enforced():
    model = access_fixture()
    close = action("close", "acl", ["attacker", "interface-0", "read"], "FALSE", requires=["companion"])
    working(model, "audit")
    mutate_permission(model, "enabled", ["audit"])
    companion = action("companion", "enabled", ["audit"], "TRUE")
    reopen = action("reopen", "acl", ["attacker", "interface-0", "read"], "TRUE")
    with pytest.raises(ValueError, match="companion"):
        apply_actions(model, [close])
    with pytest.raises(ValueError, match="Conflicting"):
        apply_actions(model, [close, companion, reopen])
    result = find_repairs(model, [close, companion, reopen])
    assert set(result["selected"]) == {"close", "companion"}
    assert result["objective_value"] == [2, 2]


def test_exhaustion_budget_timeout_unsupported_rule_and_model_error_are_distinct():
    model = access_fixture()
    assert find_repairs(model, [])['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    exhausted = find_repairs(model, [], max_candidates=0)
    assert exhausted['status'] == 'SEARCH_LIMIT' and exhausted['reason'] == 'candidate_budget'
    timed = find_repairs(model, [], timeout_seconds=0)
    assert timed['status'] == 'SEARCH_LIMIT' and timed['reason'] == 'wall_clock_timeout'
    unsupported = deepcopy(model)
    unsupported['requirements'] = [{'id': 'future', 'checker': 'unsupported', 'object': 'data'}]
    assert analyze(unsupported)['summary'] == {'NOT_CHECKED': 1}
    assert find_repairs(unsupported, [])['status'] == 'NO_TARGET_VIOLATIONS'
    conflicting = deepcopy(model)
    conflicting['facts'].append(fact('present', ['data'], 'FALSE'))
    assert find_repairs(conflicting, [])['status'] == 'MODEL_ERROR'
    assert find_repairs(model, [], targets=['nonexistent'])['status'] == 'INVALID_TARGET'


def test_candidate_generation_includes_declared_companions_but_not_unrelated_actions():
    model = access_fixture()
    model['action_catalog'] = [
        action('close', 'acl', ['attacker', 'interface-0', 'read'], 'FALSE', targets=['deny-read'], requires=['companion']),
        action('companion', 'enabled', ['interface-0'], 'TRUE'),
        action('unrelated', 'enabled', ['attacker'], 'FALSE', targets=['other']),
    ]
    assert {a['id'] for a in generate_candidates(model)} == {'close', 'companion'}


def test_catalog_and_fact_permutation_preserve_optimum():
    original = access_fixture(two_paths=True)
    actions = [action(f'close-{i}', 'acl', ['attacker', f'interface-{i}', 'read'], 'FALSE') for i in range(2)]
    shuffled = deepcopy(original)
    random.Random(19).shuffle(shuffled['facts'])
    shuffled['transitions'].reverse()
    shuffled['nodes'] = dict(reversed(list(shuffled['nodes'].items())))
    first = find_repairs(original, actions)
    second = find_repairs(shuffled, list(reversed(actions)))
    assert first['objective_value'] == second['objective_value'] == [2, 2]
    assert set(first['selected']) == set(second['selected'])
    assert first['verification']['summary'] == second['verification']['summary']


def test_real_demo_pipeline_has_verified_joint_repair_and_keeps_baseline_immutable():
    html = load_html(ROOT / 'data/sources/graf-svyazey-pk.html', state='baseline')
    xlsx = load_xlsx(ROOT / 'data/sources/Четыре_конфигурации_ПК_уязвим.xlsx', state='changed')
    comparison = compare_sources(html, xlsx, closed_inventory=True, as_states=True)
    baseline = apply_profile(imported_model(html), ROOT / 'examples/demo_profile.json')
    saved_baseline = deepcopy(baseline)
    changed = comparison_model(baseline, xlsx, comparison)
    experiment = json.loads((ROOT / 'examples/experiment_actions.json').read_text())
    broken = apply_actions(changed, experiment['actions'], 'experiment')
    before = analyze(broken)
    assert before['summary'].get('FAIL') == 3
    result = find_repairs(broken)
    assert result['status'] == 'OPTIMAL_REPAIR'
    assert result['objective_value'] == [4, 4]
    assert result['independently_rechecked']
    assert 'FAIL' not in result['verification']['summary']
    assert baseline == saved_baseline
    assert result['repaired_model']['requirements'] == broken['requirements']
    assert result['repaired_model']['profile'] == broken['profile']
    assert result['repaired_model']['assumptions'] == broken['assumptions']


def test_disappearing_protected_resource_is_not_a_valid_repair():
    model = access_fixture()
    mutate_permission(model, 'present', ['data'])
    result = find_repairs(model, [action('destroy-data', 'present', ['data'], 'FALSE')])
    assert result['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'


def test_deleting_the_attack_subject_does_not_repair_its_forbidden_access():
    model = access_fixture()
    mutate_permission(model, 'present', ['attacker'])
    result = find_repairs(model, [action('erase-attacker', 'present', ['attacker'], 'FALSE')])
    assert result['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'


def test_repair_cannot_delete_another_protected_object_while_fixing_target():
    model = access_fixture()
    working(model, 'other-data', ['data'])
    model['requirements'].append({'id': 'protect-other', 'checker': 'forbidden_operation', 'subject': 'attacker', 'object': 'other-data', 'operation': 'read'})
    mutate_permission(model, 'present', ['other-data'])
    bad = action('close-and-delete-other', 'acl', ['attacker', 'interface-0', 'read'], 'FALSE')
    bad['effects'].append({'predicate': 'present', 'args': ['other-data'], 'value': 'FALSE'})
    result = find_repairs(model, [bad], targets=['deny-read'])
    assert result['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'


def test_consistent_node_key_renaming_preserves_analysis_and_optimum():
    original = access_fixture(two_paths=True)
    actions = [action(f'close-{i}', 'acl', ['attacker', f'interface-{i}', 'read'], 'FALSE') for i in range(2)]
    mapping = {key: f'renamed-{index}' for index, key in enumerate(reversed(list(original['nodes'])))}

    def rename(value):
        if isinstance(value, str):
            return mapping.get(value, value)
        if isinstance(value, list):
            return [rename(item) for item in value]
        if isinstance(value, dict):
            return {mapping.get(key, key): deepcopy(item) if key == 'types' else rename(item) for key, item in value.items()}
        return value

    renamed = rename(original)
    assert analyze(original)['summary'] == analyze(renamed)['summary'] == {'FAIL': 1}
    result = find_repairs(renamed, rename(actions))
    assert result['status'] == 'OPTIMAL_REPAIR'
    assert result['objective_value'] == [2, 2]
    assert set(result['selected']) == {'close-0', 'close-1'}
    assert result['verification']['summary'] == {'PASS': 1}
