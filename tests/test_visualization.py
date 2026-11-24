"""The display graph is complete and does not invent security conclusions."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from analyzer.engine import analyze
from analyzer.importers import compare_sources, load_html, load_xlsx
from analyzer.model import fact
from analyzer.profiles import apply_profile, comparison_model, imported_model
from analyzer.repairs import find_repairs
from analyzer.scenarios import run_scenario
from analyzer.transitions import apply_actions, remove_component
from analyzer.visualization import build_graph

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def models():
    html = load_html(ROOT/'data/sources/graf-svyazey-pk.html', 'baseline')
    xlsx = load_xlsx(ROOT/'data/sources/Четыре_конфигурации_ПК_уязвим.xlsx', 'changed')
    baseline = apply_profile(imported_model(html), ROOT/'examples/demo_profile.json')
    changed = comparison_model(baseline, xlsx, compare_sources(html, xlsx, True, as_states=True))
    actions = json.loads((ROOT/'examples/experiment_actions.json').read_text(encoding="utf-8"))['actions']
    experiment = apply_actions(changed, actions, new_state='experiment')
    return baseline, changed, experiment


def test_full_raw_graph_and_composite_keys_are_retained(models):
    baseline, _, _ = models
    snapshot = deepcopy(baseline)
    graph = build_graph(baseline)
    assert baseline == snapshot
    assert len(graph['nodes']) == 231
    assert len({n['key'] for n in graph['nodes']}) == 231
    assert all(f'{pc}:83' in {n['key'] for n in graph['nodes']} for pc in range(1, 5))
    structural = [e for e in graph['edges'] if e['kind'] == 'structural']
    assert len(structural) == graph['summary']['structural_edges'] == 1100
    assert {(e['source'], e['target']) for e in structural} == {(e['source'], e['target']) for e in baseline['source_graph']['edges']}
    assert not any(e['witness'] for e in structural)
    assert all(e['origin'] == ['imported'] for e in structural)
    assert len([e for e in graph['edges'] if e['kind'] == 'access']) == len(baseline['transitions'])
    assert not graph['summary']['violators']


def test_only_proven_offender_is_red_then_both_acl_bypasses_are_blocked(models):
    _, _, experiment = models
    before = build_graph(experiment)
    forbidden = next(r for r in experiment['requirements'] if r['checker'] == 'forbidden_operation')
    offender = forbidden['subject']
    assert before['summary']['violators'] == [offender]
    assert [n['key'] for n in before['nodes'] if n['is_violator']] == [offender]
    witness = next(f for f in before['findings'] if f['id'] == forbidden['id'])
    assert witness['offender'] == offender and witness['path_is_violation']
    assert witness['path'][0] == offender and witness['path'][-1] == forbidden['object']
    assert any(e['witness'] and e['kind'] == 'access' for e in before['edges'])
    assert not any(e['witness'] and e['kind'] == 'structural' for e in before['edges'])

    repair = find_repairs(experiment)
    assert repair['status'] == 'OPTIMAL_REPAIR'
    repaired = repair['repaired_model']
    after = build_graph(repaired)
    assert len(after['nodes']) == len(before['nodes']) == 231
    assert after['summary']['structural_edges'] == before['summary']['structural_edges'] == 1088
    assert not after['summary']['violators']
    assert not any(n['is_violator'] for n in after['nodes'])
    assert not any(e['witness'] for e in after['edges'])
    blocked = [e for e in after['edges'] if e.get('subject') == offender and e['blocked']]
    assert len(blocked) == 2
    assert all(e['changed'] and e['value'] == 'FALSE' for e in blocked)
    assert all(any(c['predicate'] == 'acl' and c['result'] == 'FALSE' for c in e['conditions']) for e in blocked)
    assert next(n for n in after['nodes'] if n['key'] == offender)['changed']


def test_missing_nodes_remain_visible_as_tombstones_without_invented_edges(models):
    baseline, changed, _ = models
    actual = build_graph(changed)
    assert len(actual['nodes']) == 231
    absent = [n for n in actual['nodes'] if n['present'] == 'FALSE']
    assert {n['key'] for n in absent} == {'1:59', '2:90'}
    assert actual['summary']['structural_edges'] == 1088
    assert all(not (e['source'] in {'1:59', '2:90'} or e['target'] in {'1:59', '2:90'}) for e in actual['edges'] if e['kind'] == 'structural')
    baseline_ids = {(e['source'], e['target']): e['id'] for e in build_graph(baseline)['edges'] if e['kind'] == 'structural'}
    assert all(e['id'] == baseline_ids[(e['source'], e['target'])] for e in actual['edges'] if e['kind'] == 'structural')
    removed = build_graph(remove_component(baseline, '1:59'))
    assert removed['summary']['structural_edges'] == 1100
    incident = [e for e in removed['edges'] if e['kind'] == 'structural' and '1:59' in (e['source'], e['target'])]
    assert incident and all(e['blocked'] and e['value'] == 'FALSE' for e in incident)


def test_control_and_logger_relations_show_effective_working_state(models):
    baseline, _, experiment = models
    working = build_graph(baseline)
    broken = build_graph(experiment)
    logger_before = next(e for e in working['edges'] if e['kind'] == 'logger')
    logger_after = next(e for e in broken['edges'] if e['kind'] == 'logger')
    assert logger_before['value'] == 'TRUE'
    assert logger_after['declared_value'] == 'TRUE'
    assert logger_after['value'] == 'FALSE' and logger_after['blocked'] and logger_after['changed']
    filtering = next(e for e in broken['edges'] if e['kind'] == 'cover' and e['relation_args'][1] == 'filtering')
    assert filtering['value'] == 'FALSE' and filtering['blocked']


def test_loss_of_required_read_does_not_accuse_legitimate_user(models):
    model = deepcopy(models[0])
    requirement = next(r for r in model['requirements'] if r['checker'] == 'required_operation')
    for entry in model['facts']:
        if entry['predicate'] == 'acl' and entry['args'] == [requirement['subject'], requirement['object'], requirement['operation']]:
            entry['value'] = 'FALSE'
    graph = build_graph(model)
    result = next(f for f in graph['findings'] if f['id'] == requirement['id'])
    assert result['status'] == 'FAIL'
    assert result['offender'] is None
    assert not graph['summary']['violators']
    assert not any(n['is_violator'] for n in graph['nodes'])


def test_unknown_acl_is_uncertain_not_red_or_blocked(models):
    model = deepcopy(models[2])
    offender = next(r['subject'] for r in model['requirements'] if r['checker'] == 'forbidden_operation')
    for entry in model['facts']:
        if entry['predicate'] == 'acl' and entry['args'][0] == offender:
            entry['value'] = 'UNKNOWN'
    graph = build_graph(model)
    assert not graph['summary']['violators']
    branch_entries = [e for e in graph['edges'] if e.get('subject') == offender and e['source'] == offender]
    assert len(branch_entries) == 2
    assert all(e['value'] == 'UNKNOWN' and not e['blocked'] for e in branch_entries)


def test_passive_quantum_exposure_does_not_create_red_active_user():
    response = run_scenario('quantum')
    graph = response['report']['states']['quantum']['graph']
    assert graph['summary']['fail_count'] == 2
    assert graph['summary']['violators'] == []
    assert not any(e['kind'] in {'access', 'flow'} for e in graph['edges'])
    quantum = next(f for f in graph['findings'] if f['checker'] == 'quantum')
    assert quantum['offender'] is None and 'пассивное' in quantum['message']


@pytest.mark.parametrize('scenario,kind', [('dependency_cycle', 'dependency'), ('keyed_backup', 'backup'), ('common_dependency', 'dependency'), ('configuration_and_duties', 'has_role')])
def test_isolated_fixtures_show_all_nodes_and_actual_relations(scenario, kind):
    result = run_scenario(scenario)['report']['states']['fixture']
    graph = result['graph']
    assert len(graph['nodes']) == len(result['model']['nodes'])
    assert any(e['kind'] == kind for e in graph['edges'])
    assert graph['summary']['structural_edges'] == 0
    assert not graph['summary']['violators']


def test_inconsistent_input_does_not_present_old_report_as_confirmed_graph(models):
    model = deepcopy(models[2])
    previous = analyze(model)
    model['facts'].append(fact('present', ['g:104'], 'FALSE'))
    graph = build_graph(model, previous)
    assert any(d['code'] == 'MODEL_ERROR' for d in graph['diagnostics'])
    assert graph['summary']['violators'] == []
    assert all(e['value'] == 'UNKNOWN' for e in graph['edges'] if e['kind'] == 'access')


def test_build_graph_is_a_serializable_read_only_projection(models):
    model = deepcopy(models[2])
    snapshot = json.dumps(model, sort_keys=True, ensure_ascii=False)
    result = build_graph(model)
    assert json.loads(json.dumps(result))['summary']['node_count'] == 231
    assert json.dumps(model, sort_keys=True, ensure_ascii=False) == snapshot
