"""The uploaded graph acquires mandate semantics only after explicit selection."""
from copy import deepcopy
from io import BytesIO
import json
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
import pytest
from openpyxl import Workbook

from analyzer.engine import analyze
from test_structural_profiles import graph


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/')
        yield client


def request_profile(client, payload, *, multipart=False):
    token = client.cookies['csrftoken'].value
    if multipart:
        return client.post('/api/analyze/', {'file': SimpleUploadedFile('profile.json', json.dumps(payload).encode())},
                           HTTP_X_CSRFTOKEN=token)
    return client.post('/api/analyze/', json.dumps(payload), content_type='application/json', HTTP_X_CSRFTOKEN=token)


@pytest.mark.parametrize('multipart', [False, True])
def test_explicit_profile_uses_original_graph_and_filename(client, multipart):
    source = graph()
    source['metadata'] = {'uploaded_filename': 'Мои компоненты.xlsx'}
    before = deepcopy(source)
    response = request_profile(client, {'kind': 'structural_profile', 'profile': 'mandate-flows-v1', 'graph': source}, multipart=multipart)
    assert response.status_code == 200, response.content[:1000]
    report = response.json()
    assert report['filename'] == 'Мои компоненты.xlsx'
    state = report['states']['imported']
    assert state['model']['source_graph'] == source == before
    assert state['analysis']['summary'] == {'FAIL': 1, 'PASS': 1, 'UNKNOWN': 1}
    assert analyze(state['model'])['summary'] == state['analysis']['summary']
    assert state['graph']['summary']['node_count'] == len(source['nodes'])
    assert state['graph']['summary']['structural_edges'] == len(source['edges'])
    assert not state['graph']['summary']['violators']  # No human author was declared.
    assert not report.get('available_profiles')
    assert report['assumptions'] and report['profile']['id'] == 'mandate-flows-v1'
    assert not state['model']['mutable']


def test_confirmed_cluster_workbook_applies_profile_and_keeps_missing_labels_unknown(client):
    from test_cluster_workbook_web import clustered_workbook
    response = client.post('/api/analyze/', {'file': SimpleUploadedFile('clusters.xlsx', clustered_workbook())},
                           HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    report = response.json()
    state = report['states']['imported']
    assert state['analysis']['summary'] == {'UNKNOWN': 1}
    assert state['scope']['conclusion'] == 'INCOMPLETE'
    assert state['model']['profile'] == 'mandate-flows-v1'
    assert not state['model']['transitions']  # Targets have no assigned labels.
    assert state['model']['security_policy']['enabled']
    assert report['profile_applied'] == 'automatic' and report['assumptions']


def test_other_structural_formats_only_offer_profile():
    from core.views import _structural_input
    source = graph()
    source.update(format='html', metadata={}, issues=[])
    report = _structural_input(source)
    state = report['states']['imported']
    assert state['model']['profile'] == 'strict'
    assert not state['model']['transitions'] and not state['model'].get('security_policy')
    assert state['analysis']['summary'] == {'UNKNOWN': 1}
    assert report['available_profiles'][0]['id'] == 'mandate-flows-v1'
    assert not report['assumptions']


@pytest.mark.parametrize('endpoint', ['/api/analyze/', '/analysis/'])
def test_cluster_excel_checks_downward_flow_on_upload_without_second_action(client, endpoint):
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet('Конфигурации ПК')
    for row in [
        ['Кластер', 'ID', 'Сущность', 'Вход', 'Выход'],
        ['Мандаты', 90, 'Мандат 2 — Общий', None, 'ПК 7 / Приёмник'],
        ['Мандаты', 91, 'Мандат 9 — Закрытый', None, 'ПК 7 / Источник'],
        ['ПК 7', 1, 'Источник', 'Мандат 9 — Закрытый', 'Приёмник'],
        ['ПК 7', 2, 'Приёмник', 'Мандат 2 — Общий, Источник', None],
    ]:
        sheet.append(row)
    file = BytesIO(); workbook.save(file); workbook.close()
    response = client.post(endpoint, {'file': SimpleUploadedFile('Произвольные узлы.xlsx', file.getvalue())},
                           HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert response.status_code == 200
    if endpoint == '/analysis/':
        from test_landing_upload import Page
        report = Page(response.content.decode()).reports()[0]
    else:
        report = response.json()
    state = report['states']['imported']
    assert state['analysis']['summary'] == {'FAIL': 1}
    assert state['analysis']['results'][0]['witness']['nodes'] == ['7:1', '7:2']
    assert report['profile_applied'] == 'automatic' and not report.get('available_profiles')
    assert state['graph']['summary']['node_count'] == 4
    assert state['graph']['summary']['structural_edges'] == 3
    assert not state['model']['completeness'] and not state['model']['mutable']


@pytest.mark.parametrize('change', [
    {'profile': 'unknown'}, {'graph': []}, {'graph': {'nodes': [], 'edges': []}},
    {'graph': {'nodes': {}, 'edges': [{'source': 'missing', 'target': 'missing'}]}},
    {'unrequested_option': True},
])
def test_profile_rejects_malformed_selection_and_keeps_csrf(client, change):
    payload = {'kind': 'structural_profile', 'profile': 'mandate-flows-v1', 'graph': graph(), **change}
    response = request_profile(client, payload)
    assert response.status_code == 400
    assert isinstance(response.json()['error'], str)
    assert client.post('/api/analyze/', json.dumps(payload), content_type='application/json').status_code == 403
