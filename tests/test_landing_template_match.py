"""Landing imports may reuse a *known identical* installed template only."""
from io import BytesIO
from pathlib import Path

from django.test import Client, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from openpyxl import load_workbook

from core.template_registry import TEMPLATE_ROOT, find_matching_template_for_workbook, template_files


def _primary_xlsx():
    return template_files(TEMPLATE_ROOT / 'Шаблон №1')['.xlsx']


def test_exact_workbook_uses_existing_template_analysis():
    original = _primary_xlsx()
    upload = SimpleUploadedFile(original.name, original.read_bytes())
    match = find_matching_template_for_workbook(upload)
    assert match is not None and match.name == 'Шаблон №1'
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/')
        response = client.post('/analysis/', {
            'match_existing_template': '1',
            'file': SimpleUploadedFile(original.name, original.read_bytes()),
        }, HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert response.status_code == 200
    assert 'data-template="Шаблон №1"' in response.content.decode()
    assert 'id="initial-report"' not in response.content.decode()


def test_additional_documents_have_no_effect_on_template_matching():
    original = _primary_xlsx()
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/')
        response = client.post('/analysis/', {
            'match_existing_template': '1',
            'file': SimpleUploadedFile(original.name, original.read_bytes()),
            'additional_requirements': SimpleUploadedFile('rules.txt', b'any text'),
        }, HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert response.status_code == 200
    assert 'data-template="Шаблон №1"' in response.content.decode()


def test_altered_workbook_does_not_inherit_template_rules():
    original = _primary_xlsx()
    book = load_workbook(BytesIO(original.read_bytes()))
    sheet = book.active
    sheet.cell(row=2, column=3).value = 'Несовпадающий компонент'
    content = BytesIO()
    book.save(content)
    book.close()
    modified = SimpleUploadedFile('changed.xlsx', content.getvalue())
    assert find_matching_template_for_workbook(modified) is None
