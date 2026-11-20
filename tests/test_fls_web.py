"""FLS examples and editable Excel use the public analysis/repair path."""
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
from analyzer.visualization import build_graph

ROOT = Path(__file__).resolve().parents[1]


def example():
    return json.loads((ROOT / 'examples/portable/fls_clusters.json').read_text())


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/analysis/')
        yield client


def post(client, path, payload):
    return client.post(path, json.dumps(payload), content_type='application/json',
                       HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)


def test_public_fls_example_has_directed_layers_clusters_and_verified_repair(client):
    response = post(client, '/api/graph-example/', {'example': 'fls'})
    assert response.status_code == 200
    before = response.json()['states']['uploaded']
    assert before['analysis']['summary'] == {'FAIL': 5, 'PASS': 4}
    graph = before['graph']
    assert len(graph['layer_edges']) == 12
    assert [c['name'] for c in graph['clusters']] == ['ПК1', 'ПК2']
    assert all(len(c['node_keys']) == 3 for c in graph['clusters'])
    protected = [edge for edge in graph['layer_edges'] if edge['via_protection']]
    assert len(protected) == 6
    assert {(e['source'], e['target']) for e in protected} == {
        ('analyst:Елена', 'vault/research'), ('vault/research', 'analyst:Елена')}
    assert all(e['protection_via'] == ['guard-alpha'] for e in protected)
    fixed = post(client, '/api/repair/', {'model': before['model']}).json()['states']['repaired']
    assert fixed['analysis']['summary'] == {'PASS': 9}
    assert fixed['model']['fls_channels'] == before['model']['fls_channels']
    assert fixed['graph']['summary']['violators'] == []
    # Revoking an operation does not pretend that physical/protocol channels vanished.
    assert [e['value'] for e in fixed['graph']['layer_edges']] == ['TRUE'] * 12


def test_fls_workbook_exposes_three_levels_as_editable_columns_and_roundtrips(client, tmp_path):
    response = client.get('/api/graph-example/file/?example=fls&format=xlsx')
    assert response.status_code == 200
    book = load_workbook(BytesIO(response.content), data_only=False)
    header = [c.value for c in book['Edges'][1]]
    assert {'physical', 'syntactic', 'semantic', 'bidirectional', 'protection_via', 'channel'} <= set(header)
    assert 'cluster' in [c.value for c in book['Nodes'][1]]
    book.close()
    path = tmp_path / 'fls.xlsx'; path.write_bytes(response.content)
    model = load_portable(load_portable_workbook(path))
    original = load_portable(example())
    assert analyze(model)['summary'] == analyze(original)['summary']
    assert [(c['source'], c['target'], c['layers'], c['protection_via']) for c in model['fls_channels']] == [
        (c['source'], c['target'], c['layers'], c['protection_via']) for c in original['fls_channels']]
    assert [n['cluster'] for n in model['nodes'].values()] == [n['cluster'] for n in original['nodes'].values()]
    upload = client.post('/api/analyze/', {'file': SimpleUploadedFile('fls.xlsx', response.content)},
                         HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert upload.status_code == 200
    assert len(upload.json()['states']['uploaded']['graph']['layer_edges']) == 12


def test_workbook_does_not_turn_missing_or_false_layer_into_true(tmp_path):
    payload = example()
    channel = next(e for e in payload['edges'] if e['id'] == 'workstation-link')
    del channel['layers']['syntactic']
    channel['layers']['semantic'] = False
    channel['bidirectional'] = False
    path = tmp_path / 'partial.xlsx'; path.write_bytes(portable_workbook(payload))
    model = load_portable(load_portable_workbook(path))
    layers = [e for e in build_graph(model)['layer_edges'] if e['channel_id'] == 'workstation-link']
    assert {e['layer']: e['value'] for e in layers} == {'physical': 'TRUE', 'syntactic': 'UNKNOWN', 'semantic': 'FALSE'}
    assert not any(c['id'] == 'workstation-link::reverse' for c in model['fls_channels'])


def test_workbook_rejects_duplicate_layers_in_columns_and_attributes(tmp_path):
    book = load_workbook(BytesIO(portable_workbook(example())))
    sheet = book['Edges']; columns = {c.value: i for i, c in enumerate(sheet[1], 1)}
    row = next(i for i in range(2, sheet.max_row + 1) if sheet.cell(i, columns['id']).value == 'workstation-link')
    sheet.cell(row, columns['attributes'], json.dumps({'layers': {'physical': True}}))
    path = tmp_path / 'duplicates.xlsx'; book.save(path); book.close()
    with pytest.raises(ValueError, match='дважды'):
        load_portable_workbook(path)


@pytest.mark.parametrize('payload', [{'example': '../secrets'}, {'example': []}, [], {'command': 'anything'}])
def test_example_selector_is_closed_and_cannot_load_arbitrary_files(client, payload):
    assert post(client, '/api/graph-example/', payload).status_code == 400


def test_fls_example_json_download_is_the_original_portable_document(client):
    response = client.get('/api/graph-example/file/?example=fls')
    assert response.status_code == 200
    assert response.json() == example()
    assert client.get('/api/graph-example/file/?example=missing').status_code == 400
