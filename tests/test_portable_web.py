"""General JSON/XLSX integration: same engine, arbitrary keys, no fixed demo policy."""
from copy import deepcopy
from io import BytesIO
import json
import os
from pathlib import Path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.test import Client, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from openpyxl import load_workbook
import pytest
from analyzer.engine import analyze
from analyzer.portable import load_portable
from analyzer.portable_files import portable_workbook, load_portable_workbook

ROOT = Path(__file__).resolve().parents[1]


def example(name='mixed_security'):
    return json.loads((ROOT / 'examples/portable' / (name + '.json')).read_text())


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/analysis/')
        yield client


def upload(client, name, content):
    return client.post('/api/analyze/', {'file': SimpleUploadedFile(name, content)}, HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)


def post(client, path, payload):
    return client.post(path, json.dumps(payload), content_type='application/json', HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)


def test_example_has_no_privileged_analysis_path_and_repair_preserves_labels(client):
    response = post(client, '/api/graph-example/', {})
    assert response.status_code == 200
    before = response.json()['states']['uploaded']
    from_upload = upload(client, 'any-graph.json', json.dumps(example()).encode()).json()['states']['uploaded']
    assert before['analysis']['summary'] == from_upload['analysis']['summary'] == {'FAIL': 5, 'PASS': 4}
    assert before['scope']['conclusion'] == 'VIOLATIONS'
    assert len(before['graph']['nodes']) == 6
    assert before['graph']['summary']['violators'] == ['analyst:Елена']
    original = deepcopy(before['model'])
    repaired = post(client, '/api/repair/', {'model': original}).json()
    after = repaired['states']['repaired']
    assert after['analysis']['summary'] == {'PASS': 9}
    assert analyze(after['model'])['summary'] == after['analysis']['summary']
    assert after['scope']['conclusion'] == 'PASS'
    assert after['graph']['summary']['violators'] == []
    assert original['nodes'] == after['model']['nodes']
    assert original['security_policy'] == after['model']['security_policy']
    assert original['requirements'] == after['model']['requirements']
    assert repaired['repair']['objective_value'] == [5, 5]


@pytest.mark.parametrize('name', ['labels_unknown', 'structural_only'])
def test_partial_semantic_data_never_produces_safe_conclusion_or_fake_repair(client, name):
    before = upload(client, name+'.json', json.dumps(example(name)).encode()).json()['states']['uploaded']
    assert before['scope']['conclusion'] == 'INCOMPLETE'
    assert before['analysis']['summary'].get('UNKNOWN', 0) > 0
    assert before['graph']['summary']['violators'] == []
    response = post(client, '/api/repair/', {'model': before['model']}).json()
    assert 'repaired' not in response['states']
    assert response['states']['before']['scope']['conclusion'] == 'INCOMPLETE'


def test_typed_workbook_template_roundtrip_preserves_every_security_fact(client, tmp_path):
    response = client.get('/api/graph-example/file/?format=xlsx')
    assert response.status_code == 200
    path = tmp_path/'graph.xlsx'; path.write_bytes(response.content)
    actual = load_portable_workbook(path)
    expected = example()
    expected_model, actual_model = load_portable(expected), load_portable(actual)
    assert analyze(expected_model)['summary'] == analyze(actual_model)['summary']
    for key in expected_model['nodes']:
        assert actual_model['nodes'][key]['types'] == expected_model['nodes'][key]['types']
        for field in ('security_label', 'clearance', 'integrity_label'):
            assert actual_model['nodes'][key].get(field) == expected_model['nodes'][key].get(field)
    actual_state = upload(client, 'new-organization.xlsx', response.content).json()['states']['uploaded']
    assert actual_state['analysis']['summary'] == {'FAIL': 5, 'PASS': 4}
    fixed = post(client, '/api/repair/', {'model': actual_state['model']}).json()
    assert fixed['states']['repaired']['analysis']['summary'] == {'PASS': 9}


def test_missing_label_categories_stay_unknown_after_workbook_roundtrip(tmp_path):
    payload = example('labels_unknown')
    path = tmp_path/'unknown.xlsx'; path.write_bytes(portable_workbook(payload))
    original = analyze(load_portable(payload))
    actual = analyze(load_portable(load_portable_workbook(path)))
    assert actual['summary'] == original['summary']
    assert 'UNKNOWN' in actual['summary']


def test_workbook_rejects_formulas_and_duplicate_policy_sources(client):
    book = load_workbook(BytesIO(portable_workbook(example())))
    book['Nodes']['B2'] = '=WEBSERVICE("https://example.invalid")'
    stream = BytesIO(); book.save(stream)
    response = upload(client, 'formula.xlsx', stream.getvalue())
    assert response.status_code == 400
    assert 'формул' in response.json()['error']


def test_bad_labels_are_reported_as_model_errors_not_as_failed_server(client):
    payload = example(); payload['nodes']['analyst:Елена']['security_label']['level'] = 'not-defined'
    response = upload(client, 'invalid-label.json', json.dumps(payload).encode())
    assert response.status_code == 200
    state = response.json()['states']['uploaded']
    assert state['scope']['conclusion'] == 'MODEL_ERROR'
    assert state['analysis']['model_errors']
    assert not state['graph']['summary']['violators']


def test_invalid_repair_authorization_does_not_create_permissions(client):
    payload = example(); payload['repair_policy']['allowed_operations'].append({'operation': 'raise_clearance', 'nodes': ['analyst:Елена']})
    response = upload(client, 'invalid-actions.json', json.dumps(payload).encode())
    assert response.status_code == 400


def test_example_post_requires_csrf_and_download_requires_get(client):
    assert client.post('/api/graph-example/', '{}', content_type='application/json').status_code == 403
    assert client.get('/api/graph-example/').status_code == 405
    response = client.get('/api/graph-example/file/')
    assert response.status_code == 200
    assert response.json()['schema'] == 'component-security-graph/v1'
