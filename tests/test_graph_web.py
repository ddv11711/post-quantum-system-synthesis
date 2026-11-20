"""HTTP graph view and verified repair snapshots, using the real engine."""
from copy import deepcopy
import json
import os
from pathlib import Path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
import pytest

from analyzer.engine import analyze
from analyzer.model import empty_model, fact
from analyzer.visualization import build_graph


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        yield Client(enforce_csrf_checks=True)


def post(client, endpoint, payload, *, file=False):
    client.get('/')
    token = client.cookies['csrftoken'].value
    if file:
        return client.post(endpoint, {'file': SimpleUploadedFile('model.json', json.dumps(payload).encode())}, HTTP_X_CSRFTOKEN=token)
    return client.post(endpoint, json.dumps(payload), content_type='application/json', HTTP_X_CSRFTOKEN=token)


def model():
    m = empty_model('before', 'explicit-test')
    m['nodes'] = {'bad': {'name': 'Пользователь с запрещённым доступом', 'types': ['subject']},
                  'good': {'name': 'Разрешённый пользователь', 'types': ['subject']},
                  'data': {'name': 'Общий файл', 'types': ['data']}}
    m['facts'] = [fact('present', [k]) for k in m['nodes']]
    m['facts'] += [fact('acl', [s, 'data', 'read']) for s in ('bad', 'good')]
    m['transitions'] = [{'id': s + '-read', 'subject': s, 'source': s, 'target': 'data', 'operation': 'read',
                         'conditions': [{'predicate': 'acl', 'args': [s, 'data', 'read']}]} for s in ('bad', 'good')]
    m['completeness'] = [{'predicate': 'transitions', 'args_prefix': [s, 'read', 'default', 'access'], 'complete': True} for s in ('bad', 'good')]
    m['requirements'] = [{'id': 'deny', 'checker': 'forbidden_operation', 'subject': 'bad', 'object': 'data', 'operation': 'read'},
                         {'id': 'keep', 'checker': 'required_operation', 'subject': 'good', 'object': 'data', 'operation': 'read'}]
    m['mutable'] = [{'predicate': 'acl', 'args': ['bad', 'data', 'read']}]
    m['action_catalog'] = [{'id': 'close', 'cost': 1, 'targets': ['deny'],
                            'effects': [{'predicate': 'acl', 'args': ['bad', 'data', 'read'], 'value': 'FALSE'}]}]
    m['source_graph'] = {'nodes': m['nodes'], 'edges': [{'source': 'bad', 'target': 'data'}, {'source': 'good', 'target': 'data'}]}
    return m


def test_upload_full_html_graph_preserves_all_nodes_and_structural_links(client):
    path = Path(__file__).resolve().parents[1]/'data/sources/graf-svyazey-pk.html'
    client.get('/')
    response = client.post('/api/analyze/', {'file': SimpleUploadedFile(path.name, path.read_bytes())}, HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert response.status_code == 200
    graph = response.json()['states']['imported']['graph']
    assert len(graph['nodes']) == 231
    assert sum(e['kind'] == 'structural' for e in graph['edges']) == 1100
    assert not any(n['is_violator'] for n in graph['nodes'])


@pytest.mark.parametrize('file', [False, True])
def test_repair_returns_two_real_graphs_and_revokes_only_prohibited_access(client, file):
    original = model()
    snapshot = deepcopy(original)
    response = post(client, '/api/repair/', {'model': original}, file=file)
    assert response.status_code == 200, response.content[:1000]
    report = response.json()
    assert set(report['states']) == {'before', 'repaired'}
    before, after = report['states']['before'], report['states']['repaired']
    assert before['model'] == snapshot == original
    assert before['analysis']['summary'] == {'FAIL': 1, 'PASS': 1}
    assert after['analysis']['summary'] == {'PASS': 2}
    assert analyze(after['model'])['summary'] == {'PASS': 2}
    assert [n['key'] for n in before['graph']['nodes'] if n['is_violator']] == ['bad']
    assert not any(n['is_violator'] for n in after['graph']['nodes'])
    assert before['graph']['summary']['structural_edges'] == after['graph']['summary']['structural_edges'] == 2
    assert report['repair']['status'] == 'OPTIMAL_REPAIR'


def test_no_verified_repair_does_not_fabricate_an_after_graph(client):
    m = model()
    m['action_catalog'] = []
    response = post(client, '/api/repair/', {'model': m})
    assert response.status_code == 200
    report = response.json()
    assert set(report['states']) == {'before'}
    assert report['repair']['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    assert report['states']['before']['graph']['summary']['violators'] == ['bad']


def test_unknown_access_has_no_red_user_and_no_false_fixed_graph(client):
    m = model()
    next(f for f in m['facts'] if f['predicate'] == 'acl' and f['args'][0] == 'bad')['value'] = 'UNKNOWN'
    report = post(client, '/api/repair/', {'model': m}).json()
    assert set(report['states']) == {'before'}
    assert report['repair']['status'] == 'NO_TARGET_VIOLATIONS'
    assert not report['states']['before']['graph']['summary']['violators']


def test_saved_report_graph_is_presentation_not_a_reanalysis(client):
    m = model()
    analysis = analyze(m)
    bundle = {'kind': 'analysis_bundle', 'states': {'before': {'model': m, 'analysis': analysis}}}
    response = post(client, '/api/analyze/', bundle)
    assert response.status_code == 200
    result = response.json()
    assert result['display_mode'] == 'saved_report'
    assert result['states']['before']['analysis'] == analysis
    assert result['states']['before']['model'] == m
    assert len(result['states']['before']['graph']['nodes']) == 3


def test_saved_slim_model_keeps_its_full_separate_display_graph(client):
    m = model()
    analysis = analyze(m)
    graph = build_graph(m, analysis)
    del m['source_graph']
    bundle = {'kind': 'analysis_bundle', 'states': {'before': {'model': m, 'analysis': analysis, 'graph': graph}}}
    response = post(client, '/api/analyze/', bundle)
    assert response.status_code == 200
    state = response.json()['states']['before']
    assert state['graph'] == graph
    assert state['graph']['summary']['structural_edges'] == 2
    assert state['model'] == m and 'source_graph' not in state['model']
    assert state['analysis'] == analysis


def test_repair_endpoint_enforces_csrf_method_and_request_shape(client):
    assert client.get('/api/repair/').status_code == 405
    assert client.post('/api/repair/', '{}', content_type='application/json').status_code == 403
    assert post(client, '/api/repair/', {'model': model(), 'command': 'anything'}).status_code == 400
    assert post(client, '/api/repair/', {'model': []}).status_code == 400


def test_page_loads_graph_renderer_and_no_longer_offers_json_as_result(client):
    page = client.get('/').content.decode()
    assert 'graph_view.js' in page and 'graph_view.css' in page
    assert page.index('graph_view.js') < page.index('main.js')
    assert 'id="security-graph"' in page
    assert 'id="download-report"' not in page
