"""Optional requirements accompany the main upload only for the current request."""
import json
import re
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    from core import views
    stored = tmp_path / 'imported'
    monkeypatch.setattr(views, 'IMPORTED_DOCUMENTS_DIR', stored)
    normative = tmp_path / 'normative'
    normative.mkdir()
    monkeypatch.setattr(views, 'DOCUMENTS_DIR', normative)
    with override_settings(ALLOWED_HOSTS=['testserver']):
        yield Client(enforce_csrf_checks=True), stored


def _main_graph():
    model = {'schema': 'component-security-graph/v1',
             'nodes': {'device': {'name': 'Тестовый компонент', 'type': 'component'}},
             'edges': []}
    return SimpleUploadedFile('graph.json', json.dumps(model, ensure_ascii=False).encode('utf-8'),
                              content_type='application/json')


def _requirements():
    return SimpleUploadedFile('Требования.pdf', b'%PDF-1.7\nText\n%%EOF', content_type='application/pdf')


def _token(client):
    response = client.get('/')
    assert response.status_code == 200
    return client.cookies['csrftoken'].value


def test_requirements_dialog_is_attached_to_main_upload_form(isolated):
    client, _ = isolated
    content = client.get('/').content.decode('utf-8')
    assert 'id="requirements-modal"' in content
    assert 'aria-modal="true"' in content
    assert 'name="additional_requirements" form="upload-form"' in content
    assert 'Продолжить без документов' in content
    assert 'Продолжить с документами' in content
    assert 'id="upload-form"' in content


def test_without_optional_documents_existing_upload_behavior_is_unchanged(isolated):
    client, stored = isolated
    token = _token(client)
    response = client.post('/api/analyze/', {'file': _main_graph()}, HTTP_X_CSRFTOKEN=token)
    assert response.status_code == 200, response.content
    assert 'additional_requirements' not in response.json()
    assert not stored.exists()


def test_optional_pdf_is_transient_and_explicitly_not_applied(isolated):
    client, stored = isolated
    token = _token(client)
    response = client.post('/api/analyze/', {
        'file': _main_graph(), 'additional_requirements': [_requirements()]},
        HTTP_X_CSRFTOKEN=token)
    assert response.status_code == 200, response.content
    result = response.json()
    assert result['additional_requirements']['persisted'] is False
    assert result['additional_requirements']['applied_to_automatic_checks'] is False
    assert result['additional_requirements']['documents'][0]['filename'] == 'Требования.pdf'
    assert not stored.exists()


def test_invalid_extra_document_does_not_get_saved(isolated):
    client, stored = isolated
    token = _token(client)
    response = client.post('/api/analyze/', {'file': _main_graph(),
        'additional_requirements': [SimpleUploadedFile('fake.pdf', b'NOT-PDF')]},
        HTTP_X_CSRFTOKEN=token)
    assert response.status_code == 400
    assert not stored.exists()


def test_main_page_receives_transient_document_metadata_without_storing(isolated):
    client, stored = isolated
    token = _token(client)
    response = client.post('/analysis/', {'file': _main_graph(),
        'additional_requirements': [_requirements()]}, HTTP_X_CSRFTOKEN=token)
    assert response.status_code == 200
    html = response.content.decode('utf-8')
    report_tag = re.search(r'<script id="initial-report" type="application/json">(.*?)</script>', html, re.S)
    assert report_tag is not None
    report = json.loads(report_tag.group(1))
    assert report['additional_requirements']['documents'][0]['filename'] == 'Требования.pdf'
    assert report['additional_requirements']['persisted'] is False
    assert report['additional_requirements']['applied_to_automatic_checks'] is False
    assert 'Дополнительные документы получены только для текущего запроса' in report['notice']
    assert not stored.exists()
