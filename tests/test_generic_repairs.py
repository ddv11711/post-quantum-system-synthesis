"""Policy-authorized repair of arbitrary identifiers, users and path counts."""
from copy import deepcopy

import pytest

from analyzer.engine import analyze
from analyzer.model import FactBase, empty_model, fact
from analyzer.remediation import attach_repair_catalog
from analyzer.repairs import find_repairs, generate_candidates
from analyzer.transitions import apply_actions
from analyzer.visualization import build_graph


def node(model, key, types, level='open'):
    model['nodes'][key] = {'name': key, 'types': types, 'security_label': {'level': level, 'categories': []}}
    model['facts'].extend(fact(predicate, [key]) for predicate in ('present', 'enabled', 'healthy'))
    model['dependencies'][key] = {'all': []}


def replace_fact(model, predicate, args, value):
    model['facts'] = [entry for entry in model['facts'] if (entry['predicate'], entry['args']) != (predicate, args)]
    model['facts'].append(fact(predicate, args, value))


def gated_edge(model, identifier, subject, source, target, *, operation='read', kind='access'):
    model['facts'].append(fact('transition_enabled', [identifier]))
    model['transitions'].append({'id': identifier, 'portable_edge_id': identifier,
                                'subject': subject, 'source': source, 'target': target,
                                'operation': operation, 'kind': kind,
                                'conditions': [{'predicate': 'transition_enabled', 'args': [identifier]}]})


def access_model(paths=2, offenders=2):
    model = empty_model('arbitrary input', 'portable-test')
    model['security_policy'] = {'enabled': True, 'confidentiality_levels': ['open', 'restricted'], 'integrity_enabled': False}
    node(model, 'vault:α/秘密', ['data'], 'restricted')
    node(model, 'legitimate reader', ['subject'], 'restricted')
    authorized_edges = []
    for person_index in range(offenders):
        subject = f'operator/{person_index}:ω'
        node(model, subject, ['subject'])
        for path in range(paths):
            interface = f'port:{person_index}:{path}'
            node(model, interface, ['component'])
            identifier = f'entry/{person_index}/{path}'
            gated_edge(model, identifier, subject, subject, interface)
            authorized_edges.append(identifier)
            model['transitions'].append({'id': f'tail/{person_index}/{path}', 'subject': subject,
                                         'source': interface, 'target': 'vault:α/秘密', 'operation': 'read'})
        model['requirements'].append({'id': f'mac-{person_index}', 'checker': 'mandatory_access',
                                      'subject': subject, 'object': 'vault:α/秘密', 'operation': 'read'})
        model['completeness'].append({'predicate': 'transitions', 'args_prefix': [subject, 'read', 'default', 'access'], 'complete': True})
    gated_edge(model, 'valid/read', 'legitimate reader', 'legitimate reader', 'vault:α/秘密')
    authorized_edges.append('valid/read')
    model['requirements'].extend([
        {'id': 'keep-legitimate-read', 'checker': 'required_operation', 'subject': 'legitimate reader', 'object': 'vault:α/秘密', 'operation': 'read'},
        {'id': 'legitimate-mac', 'checker': 'mandatory_access', 'subject': 'legitimate reader', 'object': 'vault:α/秘密', 'operation': 'read'},
    ])
    model['completeness'].append({'predicate': 'transitions', 'args_prefix': ['legitimate reader', 'read', 'default', 'access'], 'complete': True})
    model['source_graph'] = {'edges': [{'source': edge['source'], 'target': edge['target']} for edge in model['transitions']]}
    policy = {'allowed_operations': [{'operation': 'revoke_access', 'edges': authorized_edges}]}
    return model, policy


def test_multiple_offenders_all_alternatives_close_while_valid_read_and_labels_remain():
    original, policy = access_model()
    saved = deepcopy(original)
    model = attach_repair_catalog(original, policy)
    assert original == saved
    assert len(model['action_catalog']) == 5
    assert len(generate_candidates(model)) == 4  # the other user's valid path is irrelevant
    before = analyze(model)
    assert before['summary'] == {'FAIL': 2, 'PASS': 2}
    graph = build_graph(model, before)
    assert graph['summary']['violators'] == ['operator/0:ω', 'operator/1:ω']
    assert all('читать' in finding['message'] for finding in graph['findings'] if finding['status'] == 'FAIL')
    repair = find_repairs(model)
    assert repair['status'] == 'OPTIMAL_REPAIR'
    assert repair['objective_value'] == [4, 4]
    assert repair['verification']['summary'] == {'PASS': 4}
    after = repair['repaired_model']
    assert after['nodes'] == model['nodes']
    assert after['security_policy'] == model['security_policy']
    assert after['requirements'] == model['requirements']
    assert FactBase(after).get('transition_enabled', ['valid/read']) == 'TRUE'
    after_graph = build_graph(after, repair['verification'])
    assert after_graph['summary']['violators'] == []
    assert len(after_graph['nodes']) == len(graph['nodes'])
    assert after_graph['summary']['structural_edges'] == graph['summary']['structural_edges']
    assert sum(edge['kind'] == 'access' and edge['blocked'] and edge['changed'] for edge in after_graph['edges']) == 4


def test_twelve_joint_closures_survive_small_search_budget_without_claiming_optimality():
    original, policy = access_model(paths=12, offenders=1)
    model = attach_repair_catalog(original, policy)
    result = find_repairs(model, max_candidates=16, timeout_seconds=10)
    assert result['status'] == 'VERIFIED_CANDIDATE'
    assert result['optimality_proven'] is False
    assert result['independently_rechecked'] is True
    assert result['reason'] == 'candidate_budget'
    assert result['objective_value'] == [12, 12]
    assert result['checked_sets'] == 16
    assert result['verification']['summary'] == {'PASS': 3}


def test_generic_acl_authorization_is_exact_and_does_not_infer_acl_from_structure():
    original, _ = access_model(paths=1, offenders=1)
    edge = original['transitions'][0]
    args = [edge['subject'], edge['target'], 'read']
    original['facts'].append(fact('acl', args))
    edge['conditions'].append({'predicate': 'acl', 'args': args})
    policy = {'allowed_operations': [{'operation': 'revoke_access', 'acl': [dict(zip(('subject', 'object', 'operation'), args))]}]}
    model = attach_repair_catalog(original, policy)
    assert model['action_catalog'][0]['effects'] == [{'predicate': 'acl', 'args': args, 'value': 'FALSE'}]
    assert find_repairs(model)['verification']['summary'] == {'PASS': 3}
    assert FactBase(original).get('acl', args) == 'TRUE'


def test_one_authorized_edge_cannot_hide_an_unauthorized_remaining_bypass():
    model, _ = access_model(paths=2, offenders=1)
    authorized = attach_repair_catalog(model, {'allowed_operations': [{'operation': 'revoke_access', 'edges': ['entry/0/0']}]})
    assert len(authorized['action_catalog']) == 1
    assert find_repairs(authorized)['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    assert FactBase(authorized).get('transition_enabled', ['entry/0/1']) == 'TRUE'


def test_restore_and_enable_require_exact_explicit_authorization_and_known_facts():
    model = empty_model('broken control')
    node(model, 'control chosen by owner', ['component'])
    replace_fact(model, 'present', ['control chosen by owner'], 'FALSE')
    replace_fact(model, 'enabled', ['control chosen by owner'], 'FALSE')
    model['requirements'] = [{'id': 'control-required', 'checker': 'required_function', 'object': 'control chosen by owner'}]
    policy = {'allowed_operations': [
        {'operation': 'restore_component', 'nodes': ['control chosen by owner']},
        {'operation': 'enable_control', 'nodes': ['control chosen by owner']},
    ]}
    without_permission = attach_repair_catalog(model, {})
    assert without_permission['action_catalog'] == []
    assert find_repairs(without_permission)['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    authorized = attach_repair_catalog(model, policy)
    repaired = find_repairs(authorized)
    assert repaired['objective_value'] == [2, 2]
    assert repaired['verification']['summary'] == {'PASS': 1}
    replace_fact(model, 'enabled', ['control chosen by owner'], 'UNKNOWN')
    uncertain = attach_repair_catalog(model, policy)
    assert len(uncertain['action_catalog']) == 1
    assert uncertain['repair_generation']['skipped'][0]['reason'] == 'unknown_fact'
    assert find_repairs(uncertain)['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'


def test_unknown_actual_access_is_neither_an_offender_nor_a_repair_resource():
    model, policy = access_model(paths=1, offenders=1)
    replace_fact(model, 'transition_enabled', ['entry/0/0'], 'UNKNOWN')
    authorized = attach_repair_catalog(model, policy)
    assert analyze(authorized)['summary'] == {'UNKNOWN': 1, 'PASS': 2}
    assert build_graph(authorized)['summary']['violators'] == []
    assert generate_candidates(authorized) == []
    assert find_repairs(authorized)['status'] == 'NO_TARGET_VIOLATIONS'
    assert any(item['reason'] == 'unknown_fact' for item in authorized['repair_generation']['skipped'])


def test_unknown_label_does_not_authorize_fixing_the_security_classification():
    model, policy = access_model(paths=1, offenders=1)
    del model['nodes']['operator/0:ω']['security_label']['level']
    authorized = attach_repair_catalog(model, policy)
    assert analyze(authorized)['summary'] == {'UNKNOWN': 1, 'PASS': 2}
    assert build_graph(authorized)['summary']['violators'] == []
    assert find_repairs(authorized)['status'] == 'NO_TARGET_VIOLATIONS'
    assert 'level' not in authorized['nodes']['operator/0:ω']['security_label']


@pytest.mark.parametrize('operation', ['lower_label', 'raise_clearance', 'disable_security_policy'])
def test_repair_policy_cannot_authorize_changes_to_labels_clearance_or_policy(operation):
    model, _ = access_model()
    with pytest.raises(ValueError, match='cannot be changed'):
        attach_repair_catalog(model, {'allowed_operations': [{'operation': operation, 'nodes': ['operator/0:ω']}]})


def test_clearance_problem_remains_orange_and_cannot_be_repaired_by_removing_access():
    model, policy = access_model(paths=1, offenders=1)
    user = 'operator/0:ω'
    model['nodes'][user]['security_label']['level'] = 'restricted'
    model['nodes'][user]['clearance'] = {'level': 'open', 'categories': []}
    model['requirements'].append({'id': 'declared-ceiling', 'checker': 'clearance', 'subject': user, 'object': user})
    authorized = attach_repair_catalog(model, policy)
    result = find_repairs(authorized)
    assert result['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    changed = apply_actions(authorized, generate_candidates(authorized))
    graph = build_graph(changed)
    subject = next(n for n in graph['nodes'] if n['key'] == user)
    assert not subject['is_violator']
    assert 'declared-ceiling' in subject['affected']
    finding = next(f for f in graph['findings'] if f['id'] == 'declared-ceiling')
    assert finding['status'] == 'FAIL' and finding['offender'] is None
    assert 'допуск' in finding['message']


def test_label_flow_repair_keeps_both_labels_and_never_accuses_active_user():
    model = empty_model('copy-flow')
    model['security_policy'] = {'enabled': True, 'confidentiality_levels': ['open', 'restricted'], 'integrity_enabled': False}
    node(model, 'operator', ['subject'], 'restricted')
    node(model, 'original', ['data'], 'restricted')
    node(model, 'copy', ['data'], 'open')
    gated_edge(model, 'copy-edge', 'operator', 'original', 'copy', operation='write', kind='flow')
    model['completeness'] = [{'predicate': 'transitions', 'args_prefix': ['operator', 'write', 'default', 'flow'], 'complete': True}]
    model['requirements'] = [{'id': 'copy-labels', 'checker': 'label_flow', 'subject': 'operator', 'source': 'original', 'object': 'copy', 'operation': 'write'}]
    authorized = attach_repair_catalog(model, {'allowed_operations': [{'operation': 'revoke_access', 'edges': ['copy-edge']}]})
    graph = build_graph(authorized)
    assert graph['summary']['violators'] == []
    assert graph['findings'][0]['status'] == 'FAIL'
    assert 'Передача данных' in graph['findings'][0]['message']
    assert all('copy-labels' in n['affected'] for n in graph['nodes'] if n['key'] in {'original', 'copy'})
    repaired = find_repairs(authorized)
    assert repaired['status'] == 'OPTIMAL_REPAIR'
    assert repaired['repaired_model']['nodes'] == model['nodes']
    assert repaired['verification']['summary'] == {'PASS': 1}
    # An external native catalogue cannot call deleting the original a repair.
    model['mutable'] = [{'predicate': 'present', 'args': ['original']}]
    erase_source = {'id': 'erase-original', 'effects': [{'predicate': 'present', 'args': ['original'], 'value': 'FALSE'}]}
    assert find_repairs(model, [erase_source])['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
