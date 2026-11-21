"""Sparse F/L/S display is a faithful projection, not inferred access rights."""
from copy import deepcopy
import json
from pathlib import Path

from analyzer.fls import evaluate_channels
from analyzer.importers import load_html
from analyzer.model import empty_model, fact
from analyzer.portable import load_portable
from analyzer.profiles import imported_model
from analyzer.transitions import apply_actions
from analyzer.visualization import build_graph

ROOT = Path(__file__).resolve().parents[1]
LAYERS = ('physical', 'syntactic', 'semantic')


def fixture(*, bidirectional=False, protected=False):
    model = empty_model('before', 'declared-fls')
    model['nodes'] = {
        'device/А': {'name': 'Рабочая станция', 'types': ['component'], 'pc': 'ПК А'},
        'service:Б': {'name': 'Сервис', 'types': ['component'], 'pc': 'ПК Б'},
    }
    if protected:
        model['nodes']['guard:shared'] = {'name': 'Защитный шлюз', 'types': ['component']}
    for key in model['nodes']:
        model['facts'].extend(fact(p, [key]) for p in ('present', 'enabled', 'healthy'))
        model['dependencies'][key] = {'all': []}
    if protected:
        model['facts'].extend([fact('transport_enabled', ['guard:shared']), fact('failure_mode', ['guard:shared'], 'normal')])
    route = ['guard:shared'] if protected else []
    model['fls_channels'] = [{
        'id': 'interaction/1', 'source': 'device/А', 'target': 'service:Б',
        'layers': {layer: 'TRUE' for layer in LAYERS}, 'protection_via': route,
        'original_channel_id': 'interaction/1', 'direction': 'forward',
        'provenance': [{'kind': 'declared', 'file': 'fixture', 'json_key': '$.interaction'}],
    }]
    if bidirectional:
        reverse = deepcopy(model['fls_channels'][0])
        reverse.update(id='interaction/1::reverse', source='service:Б', target='device/А',
                       direction='reverse', protection_via=list(reversed(route)))
        model['fls_channels'].append(reverse)
    model['source_graph'] = {'nodes': deepcopy(model['nodes']), 'edges': [
        {'source': channel['source'], 'target': channel['target']} for channel in model['fls_channels']]}
    return model


def update_fact(model, predicate, node, value):
    entry = next(f for f in model['facts'] if f['predicate'] == predicate and f['args'] == [node])
    entry['value'] = value


def test_bidirectional_channel_has_six_arrows_without_changing_structural_edges():
    graph = build_graph(fixture(bidirectional=True))
    assert len(graph['layer_edges']) == 6
    assert graph['summary']['channel_count'] == 2
    assert graph['summary']['layer_edge_count'] == 6
    assert graph['summary']['layer_counts'] == {layer: 2 for layer in LAYERS}
    assert graph['summary']['structural_edges'] == len(graph['edges']) == 2
    assert len({edge['id'] for edge in graph['layer_edges']}) == 6
    for source, target in [('device/А', 'service:Б'), ('service:Б', 'device/А')]:
        directional = [e for e in graph['layer_edges'] if (e['source'],e['target']) == (source,target)]
        assert {e['layer'] for e in directional} == set(LAYERS)
        assert all(e['value'] == e['effective_value'] == e['declared_value'] == 'TRUE' for e in directional)
    assert len({item['color'] for item in graph['layer_legend'].values()}) == 3


def test_directional_layer_values_remain_independent_and_missing_stays_unknown():
    model = fixture(bidirectional=True)
    model['fls_channels'][0]['layers'] = {'physical': True, 'syntactic': False}
    graph = build_graph(model)
    forward = {e['layer']:e for e in graph['layer_edges'] if e['direction'] == 'forward'}
    assert {k:v['value'] for k,v in forward.items()} == {'physical':'TRUE','syntactic':'FALSE','semantic':'UNKNOWN'}
    assert all(e['value'] == 'TRUE' for e in graph['layer_edges'] if e['direction'] == 'reverse')
    assert forward['syntactic']['blocked'] is True
    assert forward['semantic']['blocked'] is False
    assert graph['summary']['layer_values']['semantic'] == {'TRUE':1,'FALSE':0,'UNKNOWN':1}


def test_explicit_protection_route_controls_dash_metadata_and_keeps_exact_order():
    model = fixture(bidirectional=True, protected=True)
    model['nodes']['guard:second'] = {'types':['component'], 'cluster':'Zone 2'}
    model['facts'].extend([fact('present',['guard:second']), fact('healthy',['guard:second']),
                           fact('transport_enabled',['guard:second']), fact('failure_mode',['guard:second'],'normal')])
    model['fls_channels'][0]['protection_via'] = ['guard:shared','guard:second']
    model['fls_channels'][1]['protection_via'] = ['guard:second','guard:shared']
    graph = build_graph(model)
    assert all(e['via_protection'] for e in graph['layer_edges'])
    for edge in graph['layer_edges']:
        via = ['guard:shared','guard:second'] if edge['direction'] == 'forward' else ['guard:second','guard:shared']
        assert edge['protection_via'] == via
        assert edge['route'] == [edge['source'],*via,edge['target']]
        assert edge['origin'] == ['declared']


def test_disabling_protection_function_does_not_fabricate_a_transport_failure():
    model = fixture(protected=True)
    update_fact(model, 'enabled', 'guard:shared', 'FALSE')
    graph = build_graph(model)
    assert all(edge['value'] == 'TRUE' and edge['via_protection'] for edge in graph['layer_edges'])
    guard = next(n for n in graph['nodes'] if n['key'] == 'guard:shared')
    assert guard['enabled'] == guard['available'] == 'FALSE'


def test_repaired_transport_recomputes_effective_physical_without_changing_declarations():
    model = fixture(protected=True)
    update_fact(model, 'healthy', 'guard:shared', 'FALSE')
    model['mutable'] = [{'predicate':'healthy','args':['guard:shared']}]
    before = build_graph(model)
    prior = deepcopy(model)
    repaired = apply_actions(model, [{'id':'repair-guard','effects':[{'predicate':'healthy','args':['guard:shared'],'value':'TRUE'}]}], 'repaired')
    after = build_graph(repaired)
    first = next(e for e in before['layer_edges'] if e['layer'] == 'physical')
    second = next(e for e in after['layer_edges'] if e['layer'] == 'physical')
    assert first['value'] == 'FALSE' and first['declared_value'] == 'TRUE'
    assert second['value'] == second['declared_value'] == 'TRUE' and second['changed']
    assert first['id'] == second['id']
    assert repaired['fls_channels'] == model['fls_channels']
    assert model == prior
    assert all(not edge['changed'] for edge in after['layer_edges'] if edge['layer'] != 'physical')


def test_projection_matches_core_fls_evaluator_in_fail_open_and_unknown_modes():
    for mode in ['fail_open','fail_closed','UNKNOWN']:
        model = fixture(protected=True)
        update_fact(model,'healthy','guard:shared','FALSE')
        update_fact(model,'failure_mode','guard:shared',mode)
        expected = evaluate_channels(model)[0]['effective_layers']
        graph = build_graph(model)
        assert {e['layer']:e['effective_value'] for e in graph['layer_edges']} == expected


def test_direct_channel_is_not_marked_protected_from_an_unrelated_cover_fact():
    model = fixture(protected=True)
    model['fls_channels'][0]['protection_via'] = []
    model['facts'].append(fact('cover',['service:Б','filter','guard:shared']))
    graph = build_graph(model)
    assert any(e['kind'] == 'cover' for e in graph['edges'])
    assert all(not e['via_protection'] and e['protection_via'] == [] for e in graph['layer_edges'])


def test_cluster_metadata_uses_explicit_grouping_and_includes_shared_resources():
    model = fixture(protected=True)
    model['nodes']['device/А']['cluster'] = 'Explicit zone'
    model['nodes']['device/А']['group'] = 'Ignored group'
    model['nodes']['guard:shared']['group'] = 'Shared services'
    model['nodes']['loose'] = {'types':['unknown']}
    graph = build_graph(model)
    clusters = {c['id']:c for c in graph['clusters']}
    assert clusters['Explicit zone']['node_keys'] == ['device/А']
    assert clusters['ПК Б']['node_keys'] == ['service:Б']
    assert clusters['Shared services']['node_keys'] == ['guard:shared']
    assert clusters['shared'] == {'id':'shared','name':'Общие ресурсы','node_keys':['loose']}
    assert graph['summary']['cluster_count'] == 4
    assert {n['key']:n['cluster'] for n in graph['nodes']} == {
        'device/А':'Explicit zone','service:Б':'ПК Б','guard:shared':'Shared services','loose':'shared'}


def test_legacy_html_has_clusters_but_no_invented_fls_levels():
    model = imported_model(load_html(ROOT/'data/sources/graf-svyazey-pk.html'))
    graph = build_graph(model)
    assert len(graph['nodes']) == 231
    assert graph['summary']['structural_edges'] == 1100
    assert graph['layer_edges'] == []
    assert graph['summary']['channel_count'] == graph['summary']['layer_edge_count'] == 0
    counts = {c['id']:len(c['node_keys']) for c in graph['clusters']}
    assert counts == {'ПК 1':53,'ПК 2':57,'ПК 3':59,'ПК 4':56,'shared':6}


def test_invalid_model_does_not_display_declared_layers_as_effective_truth():
    model = fixture()
    model['facts'].append(fact('present',['device/А'],'FALSE'))
    graph = build_graph(model)
    assert any(d['code'] == 'MODEL_ERROR' for d in graph['diagnostics'])
    assert all(e['effective_value'] == 'UNKNOWN' and e['declared_value'] == 'TRUE' for e in graph['layer_edges'])


def test_layer_payload_is_sparse_serializable_and_invariant_to_record_order():
    model = fixture(bidirectional=True, protected=True)
    saved = deepcopy(model)
    first = build_graph(model)
    changed = deepcopy(model)
    changed['nodes'] = dict(reversed(list(changed['nodes'].items())))
    changed['fls_channels'].reverse()
    changed['facts'].reverse()
    second = build_graph(changed)
    assert first['layer_edges'] == second['layer_edges']
    assert first['clusters'] == second['clusters']
    assert model == saved
    assert json.loads(json.dumps(first))['layer_edges'] == first['layer_edges']
    assert 'matrix' not in first and 'matrices' not in first
    # Matrix consumers get one arrow per declared channel/layer, not fabricated
    # zero cells or all N² ordered pairs.
    assert len(first['layer_edges']) == 3 * len(model['fls_channels'])


def test_portable_bidirectional_interaction_reaches_the_graph_as_six_explicit_layers():
    payload = {'schema':'component-security-graph/v1', 'nodes':{
        'left':{'type':'component','cluster':'ПК 1'},
        'right':{'type':'component','cluster':'ПК 2'},
        'guard':{'type':'component','healthy':True,'transport_enabled':True,'failure_mode':'normal'},
    },'edges':[{'id':'link','type':'interaction','source':'left','target':'right',
                'bidirectional':True,'layers':{'physical':True,'syntactic':True,'semantic':True},
                'protection_via':['guard']}]}
    model = load_portable(payload)
    graph = build_graph(model)
    assert len(graph['layer_edges']) == 6
    assert graph['summary']['structural_edges'] == 1
    assert all(e['via_protection'] and e['effective_value'] == 'TRUE' for e in graph['layer_edges'])
    assert {e['channel_id'] for e in graph['layer_edges']} == {'link','link::reverse'}
    assert model['transitions'] == []  # F/L/S compatibility is not an operation grant.


def test_access_overlay_recomputes_channel_conditions_and_marks_transport_changes():
    model = fixture(protected=True)
    model['nodes']['device/А']['types'] = ['subject']
    update_fact(model, 'healthy','guard:shared','FALSE')
    model['transitions'] = [{'id':'read-through-channel','source':'device/А','target':'service:Б',
        'subject':'device/А','operation':'read','channel':'interaction/1','conditions':[]}]
    model['mutable'] = [{'predicate':'healthy','args':['guard:shared']}]
    before = build_graph(model)
    changed = apply_actions(model,[{'id':'restore','effects':[{'predicate':'healthy','args':['guard:shared'],'value':'TRUE'}]}])
    after = build_graph(changed)
    original = next(e for e in before['edges'] if e['kind'] == 'access')
    updated = next(e for e in after['edges'] if e['kind'] == 'access')
    assert original['value'] == 'FALSE' and updated['value'] == 'TRUE'
    assert updated['channel_id'] == 'interaction/1' and updated['changed']
    assert next(c for c in updated['conditions'] if c['predicate'] == 'fls_channel')['layers']['physical'] == 'TRUE'


def test_malformed_cluster_metadata_falls_back_to_string_group_names():
    model = fixture(protected=True)
    model['nodes']['device/А'].update(cluster={'id':'not-a-string'}, pc='ПК fallback', group='Ignored')
    model['nodes']['service:Б'].update(cluster=[], pc={}, group='Declared group')
    model['nodes']['guard:shared'].update(cluster=None, pc=False, group=19)
    graph = build_graph(model)
    assert {node['key']:node['cluster'] for node in graph['nodes']} == {
        'device/А':'ПК fallback','service:Б':'Declared group','guard:shared':'shared'}
    assert all(isinstance(c['id'],str) and isinstance(c['name'],str) for c in graph['clusters'])


def test_corrupted_model_keeps_diagnostic_graph_without_truth_or_crashes():
    mutations = [
        lambda model:model.update(requirements=[{'id':[],'checker':'configuration'}]),
        lambda model:model.update(dependencies={'device/А':{'all':[[]]}}),
        lambda model:model.update(transitions=[{'id':'bad','source':{},'target':'service:Б','subject':'device/А','operation':'read'}]),
        lambda model:model['fls_channels'][0].update(layers=None),
        lambda model:model['fls_channels'][0].update(protection_via={}),
        lambda model:model['fls_channels'].append(deepcopy(model['fls_channels'][0])),
    ]
    for mutate in mutations:
        model = fixture()
        mutate(model)
        graph = build_graph(model)
        assert any(d['code'] == 'MODEL_ERROR' for d in graph['diagnostics'])
        assert all(edge['effective_value'] == 'UNKNOWN' for edge in graph['layer_edges'])
        assert len({edge['id'] for edge in graph['layer_edges']}) == len(graph['layer_edges'])
        assert not graph['summary']['violators']


def test_malformed_saved_findings_are_diagnosed_without_inventing_offenders():
    model = fixture()
    for bad_fields in [{'witness':['bad']}, {'id':[]}, {'object':{}}, {'cause_components':[{}]},
                       {'mandatory':{'confidentiality':[]}}, {'common_dependencies':[None]}, {'evidence':[None]}]:
        report = {'results':[{'id':'saved-check','checker':'forbidden_operation','status':'FAIL',
                             'subject':'device/А','object':'service:Б',**bad_fields}]}
        graph = build_graph(model, report)
        assert any(d['code'] == 'INVALID_DISPLAY_FINDING' for d in graph['diagnostics'])
        assert graph['summary']['unresolved_count'] == 1
        assert graph['summary']['violators'] == []


def test_only_channel_bound_to_confirmed_forbidden_path_gets_layer_witness_highlights():
    model = fixture(bidirectional=True)
    model['nodes']['device/А']['types'] = ['subject']
    model['transitions'] = [{'id':'read','source':'device/А','target':'service:Б','subject':'device/А',
                            'operation':'read','channel':'interaction/1',
                            'conditions':[{'predicate':'transition_enabled','args':['read']}]}]
    model['facts'].append(fact('transition_enabled',['read']))
    model['mutable'] = [{'predicate':'transition_enabled','args':['read']}]
    model['requirements'] = [{'id':'forbid','checker':'forbidden_operation','subject':'device/А','object':'service:Б','operation':'read'}]
    model['completeness'] = [{'predicate':'transitions','args_prefix':['device/А','read','default','access'],'complete':True}]
    before = build_graph(model)
    highlights = [e for e in before['layer_edges'] if e['witness']]
    assert len(highlights) == 3 and {e['channel_id'] for e in highlights} == {'interaction/1'}
    assert all(e['violations'] == ['forbid'] for e in highlights)
    changed = apply_actions(model,[{'id':'close','effects':[{'predicate':'transition_enabled','args':['read'],'value':'FALSE'}]}])
    after = build_graph(changed)
    assert not any(e['witness'] for e in after['layer_edges'])
    # Revoking access changes permissions, not the declared compatibility of channels.
    assert all(e['effective_value'] == 'TRUE' for e in before['layer_edges'] + after['layer_edges'])
