"""Portable graph compilation is semantic and independent of legacy PC IDs."""
from copy import deepcopy
import json
from pathlib import Path
import random

import pytest

from analyzer.engine import analyze, reachability
from analyzer.model import FactBase, validate_model
from analyzer.portable import SCHEMA, is_portable, load_portable
from analyzer.remediation import attach_repair_catalog
from analyzer.repairs import find_repairs

ROOT = Path(__file__).resolve().parents[1]


def fixture(name='mixed_security'):
    return json.loads((ROOT / f'examples/portable/{name}.json').read_text())


def simple():
    return {'schema': SCHEMA, 'nodes': {'actor': {'type': 'user'}, 'object': {'type': 'file'}},
        'edges': [{'id': 'interface', 'type': 'access', 'source': 'actor', 'target': 'object',
                   'subject': 'actor', 'operations': ['read'], 'allowed': True, 'enabled': True}],
        'policy': {'denies': [{'subject': 'actor', 'object': 'object', 'operations': ['read']}]}}


def test_complete_arbitrary_graph_compiles_and_repairs_without_legacy_bindings():
    payload = fixture()
    saved = deepcopy(payload)
    model = load_portable(payload, source='fixture.json')
    assert not validate_model(model)
    before = analyze(model)
    assert before['summary'] == {'FAIL': 5, 'PASS': 4}
    actionable = attach_repair_catalog(model, payload['repair_policy'])
    result = find_repairs(actionable)
    assert result['status'] == 'OPTIMAL_REPAIR'
    assert result['objective_value'] == [5, 5]
    assert result['verification']['summary'] == {'PASS': 9}
    assert payload == saved
    assert model['mutable'] == []
    assert {edge['id'] for edge in model['source_graph']['edges']} == {edge['id'] for edge in payload['edges']}


def test_structural_only_gets_unknown_readiness_without_fake_compliance():
    model = load_portable(fixture('structural_only'))
    assert analyze(model)['summary'] == {'UNKNOWN': 1}
    assert model['transitions'] == []
    assert reachability(model, 'sensor-A', 'board/Б', 'read')['value'] == 'UNKNOWN'
    assert model['input_diagnostics'][0]['code'] == 'UNTYPED_EDGE'


def test_missing_label_coordinates_remain_unknown():
    model = load_portable(fixture('labels_unknown'))
    assert analyze(model)['summary'] == {'UNKNOWN': 2}
    assert 'categories' not in model['nodes']['visitor']['security_label']


def test_policy_does_not_filter_actual_forbidden_operation():
    model = load_portable(simple())
    assert analyze(model)['summary'] == {'FAIL': 1}
    assert reachability(model, 'actor', 'object', 'read')['value'] == 'TRUE'
    assert not any(f['predicate'] == 'acl' for f in model['facts'])


def test_parallel_interfaces_have_independent_gates():
    payload = simple()
    payload['edges'].append({**payload['edges'][0], 'id': 'blocked', 'allowed': False})
    model = load_portable(payload)
    assert not validate_model(model)
    assert analyze(model)['summary'] == {'FAIL': 1}
    gates = [f['value'] for f in model['facts'] if f['predicate'] == 'transition_enabled']
    assert sorted(gates) == ['FALSE', 'TRUE']


@pytest.mark.parametrize('missing', ['allowed', 'enabled'])
def test_missing_edge_condition_is_unknown_not_implicitly_enabled(missing):
    payload = simple()
    del payload['edges'][0][missing]
    assert analyze(load_portable(payload))['summary'] == {'UNKNOWN': 1}


def test_explicit_actual_acl_is_separate_and_missing_acl_stays_unknown():
    payload = simple()
    payload['edges'][0]['use_acl'] = True
    assert analyze(load_portable(payload))['summary'] == {'UNKNOWN': 1}
    payload['actual_acl'] = [{'subject': 'actor', 'object': 'object', 'operations': ['read'], 'allowed': True}]
    assert analyze(load_portable(payload))['summary'] == {'FAIL': 1}
    payload['actual_acl'][0]['allowed'] = False
    # No closed transition-domain declaration: absence of this route alone is not proof.
    assert analyze(load_portable(payload))['summary'] == {'UNKNOWN': 1}
    payload['completeness'] = [{'predicate': 'transitions', 'args_prefix': ['actor', 'read', 'default', 'access'], 'complete': True}]
    assert analyze(load_portable(payload))['summary'] == {'PASS': 1}


def test_default_deny_requires_explicit_policy_completeness():
    payload = simple()
    payload['policy'] = {'default': 'deny', 'scope': {'subjects': ['actor'], 'objects': ['object'], 'operations': ['read']}}
    model = load_portable(payload)
    assert analyze(model)['summary'] == {'UNKNOWN': 1}
    assert model['requirements'][0]['checker'] == 'semantic_readiness'
    payload['policy']['complete'] = True
    assert analyze(load_portable(payload))['summary'] == {'FAIL': 1}
    payload['policy']['grants'] = [{'subject': 'actor', 'object': 'object', 'operations': ['read']}]
    model = load_portable(payload)
    assert not any(r['checker'] == 'forbidden_operation' for r in model['requirements'])
    assert model['policy']['allowed'][0]['subject'] == 'actor'


def test_roles_expand_only_confirmed_membership_and_uncertain_roles_do_not_create_denials():
    payload = simple()
    payload['nodes']['reader-role'] = {'type': 'role'}
    payload['policy'] = {'default': 'deny', 'complete': True,
        'scope': {'subjects': ['actor'], 'objects': ['object'], 'operations': ['read']},
        'grants': [{'role': 'reader-role', 'object': 'object', 'operations': ['read']}]}
    model = load_portable(payload)
    assert model['policy']['allowed'][0]['applicable'] == 'UNKNOWN'
    assert analyze(model)['summary'] == {'UNKNOWN': 1}
    payload['nodes']['actor']['roles_complete'] = True
    assert analyze(load_portable(payload))['summary'] == {'FAIL': 1}
    payload['nodes']['actor']['roles'] = ['reader-role']
    model = load_portable(payload)
    assert model['policy']['allowed'][0]['applicable'] == 'TRUE'
    assert not any(r['checker'] == 'forbidden_operation' for r in model['requirements'])


def test_dependency_edges_need_completeness_but_known_failure_wins():
    payload = {'schema': SCHEMA, 'nodes': {
        'app': {'type': 'service', 'enabled': True, 'healthy': True, 'required': True},
        'power': {'type': 'component', 'enabled': True, 'healthy': True, 'dependencies': {'all': []}}},
        'edges': [{'id': 'needs-power', 'type': 'dependency', 'source': 'app', 'target': 'power'}]}
    assert analyze(load_portable(payload))['summary'] == {'UNKNOWN': 1}
    payload['nodes']['power']['healthy'] = False
    assert analyze(load_portable(payload))['summary'] == {'FAIL': 1}
    payload['nodes']['power']['healthy'] = True
    payload['nodes']['app']['dependencies_complete'] = True
    assert analyze(load_portable(payload))['summary'] == {'PASS': 1}


def test_intent_attributes_generate_existing_checkers_with_complete_recovery_keys():
    payload = {'schema': SCHEMA, 'nodes': {
        'original': {'type': 'file', 'backup_required': True, 'expected_parameters': {'mode': 'safe'}, 'parameters': {'mode': 'safe'}},
        'replica': {'type': 'storage', 'enabled': True, 'healthy': True, 'dependencies': {'all': []}, 'readable': True},
        'restore-key': {'type': 'key', 'key_accessible': False},
        'boot': {'type': 'host', 'trusted_boot_required': True, 'trusted_boot': False,
                 'known_vulnerabilities': [{'id': 'LOCAL-001', 'patched': False}]},
    }, 'edges': [
        {'type': 'backup', 'source': 'original', 'target': 'replica'},
        {'type': 'key_required', 'source': 'replica', 'target': 'restore-key'},
    ], 'completeness': [
        {'predicate': 'backup', 'args_prefix': ['original'], 'complete': True},
        {'predicate': 'key_required', 'args_prefix': ['replica'], 'complete': True},
    ]}
    model = load_portable(payload)
    assert analyze(model)['summary'] == {'FAIL': 3, 'PASS': 1}
    assert {r['checker'] for r in model['requirements']} == {'configuration', 'recovery'}
    assert all(f['provenance'] for f in model['facts'])


def test_conflicting_actual_declarations_are_model_error():
    payload = simple()
    payload['actual_acl'] = [
        {'subject': 'actor', 'object': 'object', 'operations': ['read'], 'allowed': value}
        for value in [True, False]]
    assert analyze(load_portable(payload))['summary'] == {'MODEL_ERROR': 1}


def test_arbitrary_key_rename_and_permutation_preserve_semantic_results():
    payload = fixture()
    keys = {key: 'renamed/' + str(i) for i,key in enumerate(payload['nodes'])}
    def rename(value):
        if isinstance(value, str): return keys.get(value, value)
        if isinstance(value, list): return [rename(v) for v in value]
        if isinstance(value, dict): return {keys.get(k,k):rename(v) for k,v in value.items()}
        return value
    changed = rename(payload)
    changed['nodes'] = dict(reversed(list(changed['nodes'].items())))
    random.Random(4).shuffle(changed['edges'])
    a, b = analyze(load_portable(payload)), analyze(load_portable(changed))
    assert a['summary'] == b['summary']
    assert sorted((r['checker'],r['status']) for r in a['results']) == sorted((r['checker'],r['status']) for r in b['results'])
    model = load_portable(changed)
    model = attach_repair_catalog(model, changed['repair_policy'])
    assert find_repairs(model)['objective_value'] == [5,5]


@pytest.mark.parametrize('mutate', [
    lambda p: p['edges'][0].update(target='absent'),
    lambda p: p['nodes'].update(actor={'type':'inferred-from-name'}),
    lambda p: p['edges'][0].update(operations=['steal']),
    lambda p: p['edges'][0].update(allowed=1),
    lambda p: p['edges'].append(deepcopy(p['edges'][0])),
    lambda p: p['nodes']['actor'].update(parameters=[]),
])
def test_malformed_portable_inputs_are_diagnosed_with_paths(mutate):
    payload = simple()
    mutate(payload)
    with pytest.raises(ValueError, match=r'\$\.'):
        load_portable(payload)


def test_shape_detection_does_not_steal_canonical_models():
    assert is_portable(simple())
    assert is_portable({'nodes': {}, 'edges': []})
    assert not is_portable({'nodes': {}, 'facts': [], 'requirements': []})


def test_mac_checks_are_generated_even_without_declared_access_edges():
    payload = fixture('labels_unknown')
    payload['edges'] = []
    payload['nodes']['visitor']['security_label'] = {'level': 'public', 'categories': []}
    model = load_portable(payload)
    checks = [r for r in model['requirements'] if r['checker'] == 'mandatory_access']
    assert {r['operation'] for r in checks} == {'read', 'write'}
    report = analyze(model)
    read = next(r for r in report['results'] if r['operation'] == 'read')
    assert read['status'] == 'UNKNOWN'  # forbidden label, unknown actual graph
    assert report['summary'] == {'UNKNOWN': 1, 'PASS': 1}


def test_native_explicit_action_catalog_is_preserved_without_autogenerated_authority():
    payload = simple()
    payload['mutable'] = [{'predicate': 'enabled', 'args': ['object']}]
    payload['action_catalog'] = [{'id': 'explicit', 'effects': [{'predicate': 'enabled', 'args': ['object'], 'value': 'TRUE'}]}]
    model = load_portable(payload)
    assert model['mutable'] == payload['mutable']
    assert model['action_catalog'] == payload['action_catalog']
    assert model['action_catalog'] is not payload['action_catalog']


def test_declared_numeric_and_boolean_parameter_expectations_match_actual_values():
    payload = {'schema': SCHEMA, 'nodes': {'device': {'type': 'host',
        'parameters': {'attempt_limit': 5, 'secure': True},
        'expected_parameters': {'attempt_limit': 5, 'secure': True}}}, 'edges': []}
    assert analyze(load_portable(payload))['summary'] == {'PASS': 2}


def test_mandatory_access_checks_labeled_components_and_explicit_nondata_targets():
    payload = simple()
    payload['policy'] = {}
    payload['nodes']['actor']['security_label'] = {'level': 'public', 'categories': []}
    payload['nodes']['actor']['clearance'] = {'level': 'restricted', 'categories': []}
    payload['nodes']['object'].update(type='service', security_label={'level': 'restricted', 'categories': []})
    payload['security_policy'] = {'enabled': True, 'confidentiality_levels': ['public', 'restricted']}
    report = analyze(load_portable(payload))
    read = next(r for r in report['results'] if r.get('operation') == 'read')
    assert read['checker'] == 'mandatory_access' and read['status'] == 'FAIL'
    # The object's explicit access-target role also creates checks without a type or label.
    payload['nodes']['object'] = {'type': 'unknown'}
    report = analyze(load_portable(payload))
    assert next(r for r in report['results'] if r.get('operation') == 'read')['status'] == 'UNKNOWN'


def test_native_facts_and_requirements_are_not_silently_discarded():
    payload = simple()
    payload['policy'] = {}
    payload['facts'] = [{'predicate': 'integrity', 'args': ['object'], 'value': 'FALSE',
        'provenance': [{'file': 'measurement', 'kind': 'imported'}]}]
    payload['requirements'] = [{'id': 'explicit-integrity', 'checker': 'configuration', 'object': 'object',
        'predicate': 'integrity', 'expected': 'TRUE', 'provenance': [{'file': 'local-policy', 'kind': 'declared'}]}]
    model = load_portable(payload)
    assert analyze(model)['summary'] == {'FAIL': 1}
    requirement = next(r for r in model['requirements'] if r['id'] == 'explicit-integrity')
    assert requirement['provenance'][0]['file'] == 'local-policy'
    measured = next(f for f in model['facts'] if f['predicate'] == 'integrity')
    assert measured['provenance'][0]['file'] == 'measurement'
    assert measured['provenance'][-1]['json_key'] == '$.facts[0]'


@pytest.mark.parametrize('flag', ['required', 'authentication_required', 'logging_required', 'backup_required',
                                 'integrity_required', 'trusted_boot_required', 'dependencies_complete', 'roles_complete',
                                 'crypto_required', 'redundancy_required', 'replicas_complete'])
def test_malformed_intent_flags_are_rejected_instead_of_dropping_checks(flag):
    payload = simple()
    payload['nodes']['object'][flag] = 'TRUE'
    with pytest.raises(ValueError, match=flag):
        load_portable(payload)


def test_malformed_edge_and_policy_flags_are_not_ignored():
    payload = simple()
    payload['edges'][0]['use_acl'] = 'TRUE'
    with pytest.raises(ValueError, match='use_acl'):
        load_portable(payload)
    payload['edges'][0]['use_acl'] = True
    payload['policy']['complete'] = 'TRUE'
    with pytest.raises(ValueError, match='complete'):
        load_portable(payload)


def test_declared_crypto_and_redundancy_intent_compile_to_existing_checkers():
    payload = {'schema': SCHEMA, 'nodes': {
        'link': {'type': 'channel', 'crypto_required': True, 'crypto_protected': False},
        'service': {'type': 'component', 'redundancy_required': True, 'replicas': [], 'replicas_complete': True}
    }, 'edges': []}
    model = load_portable(payload)
    assert {r['checker'] for r in model['requirements']} == {'crypto', 'redundancy'}
    assert analyze(model)['summary'] == {'FAIL': 2}


def test_complete_default_deny_protects_keys_unknown_nodes_and_accessed_accounts():
    for kind in ['key', 'event', 'change', 'unknown', 'subject', 'role']:
        payload = simple()
        payload['nodes']['object']['type'] = kind
        payload['policy'] = {'default': 'deny', 'complete': True}
        report = analyze(load_portable(payload))
        assert any(r.get('subject') == 'actor' and r.get('object') == 'object'
                   and r.get('operation') == 'read' and r['status'] == 'FAIL' for r in report['results'])
