"""Regressions: five-column compatibility and exact semantic replay for all sizes."""
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from openpyxl import load_workbook
import pytest
from django.test import Client, override_settings

from analyzer.engine import analyze
from analyzer.importers import load_xlsx
from analyzer.model import FactBase
from analyzer.profiles import imported_model
from analyzer.security_workbook import (
    EXTENSION_SHEETS, add_security_extension, read_security_extension,
)


@pytest.fixture
def client():
    # The Django test client uses testserver, which is not a production host.
    with override_settings(ALLOWED_HOSTS=['testserver']):
        yield Client()


def test_generic_security_extension_keeps_the_five_columns(tmp_path):
    from openpyxl import Workbook
    source = tmp_path / 'graph.xlsx'
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(['ПК', 'ID', 'Сущность', 'Вход', 'Выход'])
    sheet.append(['ПК 1', 1, 'Компонент 1', None, None])
    original = imported_model(load_xlsx_data(workbook, tmp_path))
    add_security_extension(workbook, original, changes=[{
        'kind': 'Изменён параметр безопасности', 'object': '1:1',
        'before': 'FALSE', 'after': 'TRUE', 'action': 'fixture',
    }])
    workbook.save(source)
    workbook.close()
    graph = load_xlsx(source)
    replay = read_security_extension(source, imported_graph=graph)
    assert list(graph['nodes']) == ['1:1']
    assert replay['nodes']['1:1']['name'] == 'Компонент 1'
    book = load_workbook(source, read_only=True)
    try:
        assert book.sheetnames[1:] == list(EXTENSION_SHEETS)
    finally:
        book.close()


def load_xlsx_data(workbook, folder):
    source = folder / '_original.xlsx'
    workbook.save(source)
    return load_xlsx(source)


def test_both_structural_and_semantic_edits_are_detected(tmp_path):
    from openpyxl import Workbook
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(['ПК', 'ID', 'Сущность', 'Вход', 'Выход'])
    sheet.append(['ПК 1', 1, 'Компонент', None, None])
    graph = load_xlsx_data(workbook, tmp_path)
    add_security_extension(workbook, imported_model(graph), changes=[])
    output = tmp_path / 'extended.xlsx'
    workbook.save(output)
    workbook.close()
    modified = load_workbook(output)
    modified.active['C2'] = 'Изменённый компонент'
    modified.save(output)
    modified.close()
    with pytest.raises(ValueError, match='Основная таблица была изменена'):
        read_security_extension(output)
    modified = load_workbook(output)
    modified.active['C2'] = 'Компонент'
    modified['Параметры безопасности']['B2'] = 'Фальшивые исправления'
    modified.save(output)
    modified.close()
    with pytest.raises(ValueError, match='Листы параметров или изменений'):
        read_security_extension(output)


def test_four_pc_exported_xlsx_reimports_with_restored_firewall(client, tmp_path):
    response = client.post('/api/export-repaired-xlsx/', {'template': 'Шаблон №1'})
    assert response.status_code == 200, getattr(response, 'content', b'')[:400]
    assert response['X-Export-Mode'] == 'verified_roundtrip'
    assert int(response['X-Export-Added-Rows']) >= 1
    output = tmp_path / 'fixed4.xlsx'
    output.write_bytes(b''.join(response.streaming_content))
    graph = load_xlsx(output)
    assert '1:59' in graph['nodes']
    # Restoring a component must also reconstruct its declared historical
    # topology; a bare green row without incoming/outgoing links is insufficient.
    restored_links = {(edge['source'], edge['target']) for edge in graph['edges']
                      if '1:59' in (edge['source'], edge['target'])}
    assert restored_links == {
        ('1:55', '1:59'), ('1:57', '1:59'), ('1:62', '1:59'),
        ('1:98', '1:59'), ('g:2', '1:59'),
        ('1:59', '1:55'), ('1:59', '1:57'),
        ('1:59', '1:62'), ('1:59', '1:98'),
    }
    book = load_workbook(output, read_only=True)
    try:
        row = next(row for row in book.active.iter_rows(min_row=2, values_only=True)
                   if row[0] == 'ПК 1' and row[1] == 59)
        assert row[3] and row[4] and 'Администратор' in row[3]
    finally:
        book.close()
    model = read_security_extension(output, imported_graph=graph)
    assert FactBase(model).get('present', ['1:59']) == 'TRUE'
    results = analyze(model)['results']
    assert results and not any(row['status'] == 'FAIL' for row in results)
    filedata = output.read_bytes()
    from django.core.files.uploadedfile import SimpleUploadedFile
    uploaded = client.post('/api/analyze/', {'file': SimpleUploadedFile('new4.xlsx', filedata)})
    assert uploaded.status_code == 200, getattr(uploaded, 'content', b'')[:400]
    statuses = [x['status'] for x in uploaded.json()['states']['uploaded']['analysis']['results']]
    assert statuses and 'FAIL' not in statuses


def test_twenty_pc_export_roundtrip_replays_identical_checked_outcome(client, tmp_path):
    response = client.post('/api/export-repaired-xlsx/', {'template': 'Шаблон №2'})
    assert response.status_code == 200, getattr(response, 'content', b'')[:400]
    output = tmp_path / 'fixed20.xlsx'
    output.write_bytes(b''.join(response.streaming_content))
    graph = load_xlsx(output)
    model = read_security_extension(output, imported_graph=graph)
    statuses = [row['status'] for row in analyze(model)['results']]
    assert statuses.count('FAIL') == 0
    assert statuses.count('UNKNOWN') == 1
    assert statuses.count('PASS') == 1051
    assert len(graph['nodes']) == 1214
    assert len(graph['edges']) == 6595 - 73
