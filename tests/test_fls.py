"""FLS representation and actual access are separate finite relations."""
from copy import deepcopy
from itertools import product
import json
from pathlib import Path

import pytest

from analyzer.engine import Engine, analyze, reachability
from analyzer.fls import FLSEvaluator, LAYERS, evaluate_channel, evaluate_channels
from analyzer.logic import TRUE, FALSE, UNKNOWN, conjunction
from analyzer.model import empty_model, fact, validate_model
from analyzer.portable import load_portable
from analyzer.transitions import apply_actions


def payload(*, bidirectional=False, protected=False):
    return {
        'schema': 'component-security-graph/v1',
        'nodes': {
            'person': {'type': 'subject'}, 'resource': {'type': 'data'},
            'guard': {'type': 'firewall', 'enabled': True, 'healthy': True,
                      'transport_enabled': True, 'failure_mode': 'normal', 'dependencies': {'all': []}},
        },
        'edges': [
            {'id': 'wire', 'type': 'interaction', 'source': 'person', 'target': 'resource',
             'layers': {name: True for name in LAYERS}, 'bidirectional': bidirectional,
             'protection_via': ['guard'] if protected else []},
            {'id': 'read-route', 'type': 'access', 'source': 'person', 'target': 'resource', 'subject': 'person',
             'operations': ['read'], 'allowed': True, 'enabled': True, 'channel': 'wire'},
        ],
        'policy': {'denies': [{'subject': 'person', 'object': 'resource', 'operations': ['read']}]},
        'completeness': [{'predicate': 'transitions', 'args_prefix': ['person', 'read', 'default', 'access'], 'complete': True}],
    }


def result(model):
    report = analyze(model)
    assert not report['model_errors'], report['model_errors']
    return report['results'][0]


def replace(model, predicate, node, value):
    for entry in model['facts']:
        if entry['predicate'] == predicate and entry['args'] == [node]:
            entry['value'] = value
            return
    model['facts'].append(fact(predicate, [node], value))


def test_bidirectional_declares_two_independent_directions_and_six_layers():
    m = load_portable(payload(bidirectional=True))
    channels = evaluate_channels(m)
    assert [(c['id'], c['source'], c['target']) for c in channels] == [
        ('wire', 'person', 'resource'), ('wire::reverse', 'resource', 'person')]
    assert sum(len(c['effective_layers']) for c in channels) == 6
    assert all(c['value'] == TRUE for c in channels)
    assert len(m['transitions']) == 1  # two channels never synthesize reverse access


def test_fls_channel_alone_never_grants_an_operation():
    p = payload(bidirectional=True)
    p['edges'] = p['edges'][:1]
    m = load_portable(p)
    assert result(m)['status'] == 'PASS'  # explicit complete absence of access transitions
    assert all(c['value'] == TRUE for c in evaluate_channels(m))
    assert reachability(m, 'person', 'resource', 'read')['value'] == FALSE


def test_all_three_layer_combinations_use_conservative_conjunction():
    for values in product(('TRUE', 'FALSE', 'UNKNOWN'), repeat=3):
        p = payload()
        p['edges'][0]['layers'] = dict(zip(LAYERS, values))
        m = load_portable(p)
        expected = conjunction(values)
        assert evaluate_channel(m, 'wire')['value'] == expected
        assert reachability(m, 'person', 'resource', 'read')['value'] == expected
        assert result(m)['status'] == {TRUE: 'FAIL', FALSE: 'PASS', UNKNOWN: 'UNKNOWN'}[expected]


def test_missing_layer_unknown_and_known_false_is_sufficient():
    p = payload()
    del p['edges'][0]['layers']['semantic']
    m = load_portable(p)
    assert evaluate_channel(m, 'wire')['effective_layers']['semantic'] == UNKNOWN
    assert result(m)['status'] == 'UNKNOWN'
    p['edges'][0]['layers']['physical'] = False
    assert result(load_portable(p))['status'] == 'PASS'


def test_bound_channel_cannot_mask_actual_acl_or_policy_forbidden_path():
    p = payload()
    p['edges'][1]['use_acl'] = True
    p['actual_acl'] = [{'subject': 'person', 'object': 'resource', 'operations': ['read'], 'allowed': True}]
    m = load_portable(p)
    r = result(m)
    assert r['status'] == 'FAIL'
    assert r['witness']['edges'][0]['fls_channel']['value'] == TRUE
    assert any(e['predicate'] == 'fls_layer' for e in r['evidence'])
    p['actual_acl'][0]['allowed'] = False
    m = load_portable(p)
    assert result(m)['status'] == 'PASS'
    assert evaluate_channel(m, 'wire')['value'] == TRUE


def test_reverse_binding_is_direction_exact_and_input_order_independent():
    p = payload(bidirectional=True)
    p['edges'][1].update(source='resource', target='person')
    m = load_portable(p)
    assert m['transitions'][0]['channel'] == 'wire::reverse'
    p['edges'].reverse()
    assert load_portable(p)['transitions'][0]['channel'] == 'wire::reverse'
    p = payload()
    p['edges'][1].update(source='resource', target='person')
    with pytest.raises(ValueError, match='направлению'):
        load_portable(p)


def test_protected_route_has_ordered_real_references_reversed_for_reverse_channel():
    p = payload(bidirectional=True, protected=True)
    p['nodes']['guard2'] = deepcopy(p['nodes']['guard'])
    p['edges'][0]['protection_via'] = ['guard', 'guard2']
    m = load_portable(p)
    assert evaluate_channel(m, 'wire')['route'] == ['person', 'guard', 'guard2', 'resource']
    assert evaluate_channel(m, 'wire::reverse')['route'] == ['resource', 'guard2', 'guard', 'person']
    assert result(m)['witness']['edges'][0]['fls_channel']['transport_conditions'][0]['args'] == ['guard']


def test_protective_enabled_state_is_separate_from_physical_transport():
    m = load_portable(payload(protected=True))
    replace(m, 'enabled', 'guard', 'FALSE')
    assert evaluate_channel(m, 'wire')['value'] == TRUE
    assert result(m)['status'] == 'FAIL'
    replace(m, 'transport_enabled', 'guard', 'FALSE')
    assert evaluate_channel(m, 'wire')['effective_layers']['physical'] == FALSE
    assert result(m)['status'] == 'PASS'


def test_channel_transport_matches_existing_engine_failure_semantics():
    for health, mode, transport in product(('TRUE', 'FALSE', 'UNKNOWN'), ('normal', 'fail_open', 'fail_closed', 'UNKNOWN'), ('TRUE', 'FALSE', 'UNKNOWN')):
        m = load_portable(payload(protected=True))
        replace(m, 'healthy', 'guard', health)
        replace(m, 'failure_mode', 'guard', mode)
        replace(m, 'transport_enabled', 'guard', transport)
        assert evaluate_channel(m, 'wire')['effective_layers']['physical'] == Engine(m).transport('guard')


def test_unknown_failed_route_does_not_assert_blocking_and_removal_does():
    m = load_portable(payload(protected=True))
    replace(m, 'healthy', 'guard', 'FALSE')
    replace(m, 'failure_mode', 'guard', 'UNKNOWN')
    assert result(m)['status'] == 'UNKNOWN'
    replace(m, 'present', 'guard', 'FALSE')
    assert result(m)['status'] == 'PASS'
    assert evaluate_channel(m, 'wire')['effective_layers']['physical'] == FALSE


def test_channel_recomputed_on_new_snapshot_without_relabeling_layers():
    m = load_portable(payload(protected=True))
    m['mutable'].append({'predicate': 'transport_enabled', 'args': ['guard']})
    before = deepcopy(m)
    changed = apply_actions(m, [{'id': 'close-transport', 'effects': [{'predicate': 'transport_enabled', 'args': ['guard'], 'value': 'FALSE'}]}])
    assert result(m)['status'] == 'FAIL'
    assert result(changed)['status'] == 'PASS'
    assert m == before
    assert changed['fls_channels'] == m['fls_channels']


@pytest.mark.parametrize('change', [
    lambda p: p['edges'][0].update(layers={'physical': 1}),
    lambda p: p['edges'][0].update(layers={'syntax': True}),
    lambda p: p['edges'][0].update(layers=[]),
    lambda p: p['edges'][0].update(bidirectional='true'),
    lambda p: p['edges'][0].update(protection_via=['missing']),
    lambda p: p['edges'][0].update(protection_via=['guard', 'guard']),
    lambda p: p['edges'][0].update(protection_via=['resource']),
    lambda p: p['edges'][1].update(channel='missing'),
    lambda p: p['edges'][1].update(layers={'physical': True}),
])
def test_invalid_fls_declarations_are_diagnosed(change):
    p = payload()
    change(p)
    with pytest.raises(ValueError):
        load_portable(p)


def test_native_unknown_channel_and_wrong_direction_are_model_errors():
    m = load_portable(payload())
    m['transitions'][0]['channel'] = 'missing'
    assert any(e['code'] == 'UNKNOWN_TRANSITION_CHANNEL' for e in validate_model(m))
    m = load_portable(payload())
    m['transitions'][0]['source'] = 'resource'
    assert any(e['code'] == 'FLS_DIRECTION_MISMATCH' for e in validate_model(m))
    m = load_portable(payload())
    m['fls_channels'] = 'bad'
    assert analyze(m)['summary'] == {'MODEL_ERROR': 1}


def test_legacy_untyped_graph_is_not_fabricated_into_fls_or_access():
    p = {'nodes': {'a': {'type': 'subject'}, 'b': {'type': 'data'}}, 'edges': [{'source': 'a', 'target': 'b'}]}
    m = load_portable(p)
    assert m['fls_channels'] == []
    assert evaluate_channels(m) == []
    assert result(m)['status'] == 'UNKNOWN'
    assert not m['transitions']
    p = payload()
    p['edges'] = [p['edges'][1]]
    del p['edges'][0]['channel']
    assert result(load_portable(p))['status'] == 'FAIL'  # legacy explicitly typed access is unchanged


def test_schemas_accept_explicit_portable_and_normalized_native_fls():
    root = Path(__file__).resolve().parents[1]
    p = payload(bidirectional=True, protected=True)
    validations = [
        {'schema': json.loads((root / 'schemas/portable_graph.schema.json').read_text(encoding="utf-8")), 'data': p},
        {'schema': json.loads((root / 'schemas/model.schema.json').read_text(encoding="utf-8")), 'data': load_portable(p)},
    ]
    try:
        import jsonschema
    except ImportError:
        # Debian supplies a maintained validator to the system interpreter;
        # actually execute both schemas there rather than hiding the assertion.
        import shutil
        import subprocess
        candidates = [shutil.which('python3'), '/usr/bin/python3']
        code = ("import json,sys\ntry:\n import jsonschema\nexcept ImportError:\n sys.exit(77)\n"
                "for item in json.load(sys.stdin):\n jsonschema.validate(item['data'],item['schema'])\n")
        for executable in dict.fromkeys(c for c in candidates if c and Path(c).is_file()):
            check = subprocess.run([executable, '-c', code], input=json.dumps(validations), text=True, capture_output=True)
            if check.returncode == 77:
                continue
            assert check.returncode == 0, check.stderr
            return
        pytest.skip('jsonschema unavailable in both current and system interpreters')
    else:
        for item in validations:
            jsonschema.validate(item['data'], item['schema'])


def test_repair_effects_cannot_rewrite_channels_layers_or_protective_route():
    from analyzer.repairs import find_repairs
    m = load_portable(payload(protected=True))
    original_channels = deepcopy(m['fls_channels'])
    forged = []
    for predicate in ('fls_layer', 'fls_channel', 'fls_channels', 'protection_via'):
        args = ['wire', 'physical'] if predicate == 'fls_layer' else ['wire']
        m['mutable'].append({'predicate': predicate, 'args': args})
        candidate = {'id': 'fake:' + predicate, 'effects': [{'predicate': predicate, 'args': args, 'value': 'FALSE'}]}
        forged.append(candidate)
        with pytest.raises(ValueError, match='immutable or derived'):
            apply_actions(m, [candidate])
    assert find_repairs(m, forged)['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    assert m['fls_channels'] == original_channels
    transition = m['transitions'][0]['id']
    m['mutable'].append({'predicate': 'transition_enabled', 'args': [transition]})
    valid = {'id': 'close-real-gate', 'effects': [{'predicate': 'transition_enabled', 'args': [transition], 'value': 'FALSE'}]}
    fixed = find_repairs(m, [valid])
    assert fixed['status'] == 'OPTIMAL_REPAIR'
    assert fixed['repaired_model']['fls_channels'] == original_channels
    assert fixed['verification']['summary'] == {'PASS': 1}


@pytest.mark.parametrize('mode', ['typo', 1, True, 'fail_secure'])
def test_undefined_transport_mode_is_model_error_instead_of_healthy_fallback(mode):
    p = payload(protected=True)
    p['nodes']['guard']['failure_mode'] = mode
    m = load_portable(p)
    assert any(e['code'] == 'UNSUPPORTED_FAILURE_MODE' for e in validate_model(m))
    assert analyze(m)['summary'] == {'MODEL_ERROR': 1}


def test_native_malformed_protection_references_return_diagnostics_not_exceptions():
    for route in ('guard', [None], [{}], ['missing'], ['guard', 'guard'], ['resource']):
        m = load_portable(payload())
        m['fls_channels'][0]['protection_via'] = route
        assert analyze(m)['summary'] == {'MODEL_ERROR': 1}
    m = load_portable(payload())
    m['fls_channels'].append(deepcopy(m['fls_channels'][0]))
    assert any(e['code'] == 'INVALID_FLS_CHANNEL_ID' for e in validate_model(m))


def test_channel_evaluation_observes_current_snapshot_missing_facts_without_stale_evidence():
    m = load_portable(payload(protected=True))
    assert evaluate_channel(m, 'wire')['value'] == TRUE
    incomplete = deepcopy(m)
    incomplete['facts'] = [f for f in incomplete['facts'] if not (f['predicate'] == 'transport_enabled' and f['args'] == ['guard'])]
    evaluation = evaluate_channel(incomplete, 'wire')
    assert evaluation['value'] == UNKNOWN
    assert any(u['predicate'] == 'transport_enabled' for u in evaluation['unknowns'])
    assert not any(e.get('predicate') == 'transport_enabled' for e in evaluation['evidence'])
    incomplete['completeness'].append({'predicate': 'transport_enabled', 'args_prefix': ['guard'], 'complete': True})
    assert evaluate_channel(incomplete, 'wire')['value'] == FALSE
    assert evaluate_channel(m, 'wire')['value'] == TRUE


def test_batch_fls_and_engine_index_ten_thousand_facts_once_per_snapshot():
    class CountingFacts(list):
        iterations = 0
        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    m = load_portable(payload(protected=True))
    prototype = deepcopy(m['fls_channels'][0])
    m['fls_channels'] = [dict(deepcopy(prototype), id=f'channel-{index}') for index in range(40)]
    m['transitions'] = [dict(m['transitions'][0], id=f'access-{index}', channel=f'channel-{index}') for index in range(40)]
    m['facts'] = CountingFacts(m['facts'] + [fact('parameter', ['guard', f'p{index}'], 'value') for index in range(10000)])
    assert all(channel['value'] == TRUE for channel in evaluate_channels(m))
    assert m['facts'].iterations == 1
    m['facts'].iterations = 0
    engine = Engine(m)
    assert engine.reachability('person', 'resource', 'read')['value'] == TRUE
    assert len(engine.channel_cache) == 40
    assert m['facts'].iterations == 1  # FLS borrows FactBase.index; no second scan


def test_reused_channel_evaluator_isolates_unknowns_and_evidence_between_channels():
    m = load_portable(payload(protected=True))
    direct = dict(deepcopy(m['fls_channels'][0]), id='direct', protection_via=[])
    m['fls_channels'].append(direct)
    m['facts'] = [f for f in m['facts'] if not (f['predicate'] == 'transport_enabled' and f['args'] == ['guard'])]
    evaluator = FLSEvaluator(m)
    incomplete = evaluator.evaluate('wire')
    assert incomplete['value'] == UNKNOWN
    assert any(u['predicate'] == 'transport_enabled' for u in incomplete['unknowns'])
    certain = evaluator.evaluate('direct')
    assert certain['value'] == TRUE
    assert not certain['unknowns']
    assert not any('guard' in e.get('args', []) for e in certain['evidence'])
    assert all(e['args'][0] == 'direct' for e in certain['evidence'] if e['predicate'] == 'fls_layer')
    assert incomplete['unknowns']  # resetting the reader did not mutate earlier proofs
    assert evaluator.evaluate('wire')['value'] == UNKNOWN
