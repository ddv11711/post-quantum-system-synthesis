"""Export round-trip guarantees: editable five-column workbook and no fake policy edits."""
from io import BytesIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
from openpyxl import load_workbook

from analyzer.importers import load_xlsx
from analyzer.xlsx_repair_export import export_mandate_workbook
from analyzer.security_workbook import EXTENSION_SHEETS, read_security_extension
from core.template_registry import resolve_template, template_files


def _client():
    client = Client(enforce_csrf_checks=True)
    client.get('/analysis/')
    return client


def _post(client, fields):
    return client.post('/api/export-repaired-xlsx/', fields,
                       HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)


def test_small_mandate_upload_returns_corrected_importable_xlsx():
    # Independent minimal fixture; no reliance on client-selected target IDs.
    from test_scaled_mandate_repairs import sample_workbook
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = _client()
        source = sample_workbook()
        response = _post(client, {'source_file': SimpleUploadedFile('small.xlsx', source)})
        assert response.status_code == 200, getattr(response, 'content', b'')[:300]
        assert response['X-Export-Mode'] == 'verified_roundtrip'
        content = b''.join(response.streaming_content)
        wb = load_workbook(BytesIO(content))
        try:
            assert wb.sheetnames[1:] == list(EXTENSION_SHEETS)
            sheet = wb.active
            assert [c.value for c in sheet[1]] == ['Кластер', 'ID', 'Сущность', 'Вход', 'Выход']
            marked = [cell for row in sheet for cell in row if cell.fill.fgColor.rgb == '00DDF5E7']
            assert marked and all(cell.comment for cell in marked)
            assert sheet['E4'].value is None  # forbidden high-to-low transfer removed
            assert sheet['D5'].value == 'Мандат 1 — Общий'
        finally:
            wb.close()
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'fixed.xlsx'
            path.write_bytes(content)
            graph = load_xlsx(path)
            assert len(graph['nodes']) == 4
            assert not any(e['source'] == '42:1' and e['target'] == '42:2' for e in graph['edges'])


def test_template_twenty_pc_export_replays_the_same_verified_repair():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = _client()
        response = _post(client, {'template': 'Шаблон №2'})
        assert response.status_code == 200, getattr(response, 'content', b'')[:400]
        assert response['X-Export-Mode'] == 'verified_roundtrip'
        assert int(response['X-Export-Changed-Cells']) >= 73
        data = b''.join(response.streaming_content)
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'output.xlsx'
            path.write_bytes(data)
            original = load_xlsx(template_files(resolve_template('Шаблон №2'))['.xlsx'])
            edited = load_xlsx(path)
            assert len(edited['nodes']) == len(original['nodes']) == 1214
            assert len(edited['edges']) == len(original['edges']) - 73


def test_four_pc_export_restores_component_and_roundtrips_security_facts():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = _client()
        response = _post(client, {'template': 'Шаблон №1'})
        assert response.status_code == 200, getattr(response, 'content', b'')[:300]
        assert response['X-Export-Mode'] == 'verified_roundtrip'
        data = b''.join(response.streaming_content)
        wb = load_workbook(BytesIO(data))
        try:
            assert wb.sheetnames[1:] == list(EXTENSION_SHEETS)
            assert any(row[1].value == 59 and row[0].value == 'ПК 1' for row in wb.active.iter_rows(min_row=2, max_col=2))
            assert any(row[0].value == '["1:59"]' and row[1].value == 'present'
                       and row[3].value == 'TRUE'
                       for row in wb['Параметры безопасности'].iter_rows(min_row=2, max_col=4))
        finally:
            wb.close()
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'notes.xlsx'
            path.write_bytes(data)
            original = load_xlsx(template_files(resolve_template('Шаблон №1'))['.xlsx'])
            exported = load_xlsx(path)
            assert '1:59' not in original['nodes']
            assert '1:59' in exported['nodes']
            restored = read_security_extension(path, imported_graph=exported)
            from analyzer.engine import analyze
            results = analyze(restored)['results']
            assert results and not any(item['status'] == 'FAIL' for item in results)


def test_invalid_export_cannot_forge_repair_or_read_unlisted_source():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = _client()
        assert _post(client, {'template': 'missing folder'}).status_code == 400
        assert _post(client, {'source_file': SimpleUploadedFile('data.xlsx', b'bad')}).status_code == 400
        assert _post(client, {}).status_code == 400
        html = client.get('/analysis/').content.decode('utf-8')
        assert 'export-repaired-button' in html
        assert 'export-repaired-xlsx' in html
