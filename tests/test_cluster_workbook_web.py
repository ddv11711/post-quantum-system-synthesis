"""Dimensionless cluster workbooks pass through both public upload entry points."""
from collections import Counter
from io import BytesIO
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
from openpyxl import Workbook
import pytest


def clustered_workbook():
    book = Workbook(write_only=True)
    sheet = book.create_sheet('Конфигурации ПК')
    sheet.append(['Кластер', 'ID', 'Сущность', 'Вход', 'Выход'])
    for pc in range(1, 21):
        sheet.append([f'ПК {pc}', 1, 'Пользователь 1', 'Мандат 2 — Служебный', 'Файл пользователя'])
        sheet.append([f'ПК {pc}', 2, 'Файл пользователя', 'Пользователь 1', None])
    sheet.append(['Мандаты', 105, 'Мандат 2 — Служебный', None, None])
    sheet.append(['Общая сеть', 61, 'Интернет', None, None])
    sheet.append(['Администрирование', 2, 'Администратор', None, None])
    output = BytesIO(); book.save(output); book.close()
    return output.getvalue()


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/')
        yield client


@pytest.mark.parametrize('endpoint', ['/api/analyze/', '/analysis/'])
def test_twenty_pc_dimensionless_upload_keeps_groups_and_source_references(client, endpoint):
    filename = 'Конфигурация_20_ПК_уяз_мандат.xlsx'
    response = client.post(endpoint, {'file': SimpleUploadedFile(filename, clustered_workbook())},
                           HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert response.status_code == 200
    if endpoint == '/analysis/':
        from test_landing_upload import Page
        reports = Page(response.content.decode()).reports()
        assert len(reports) == 1
        report = reports[0]
    else:
        report = response.json()
    assert report['filename'] == filename
    state = report['states']['imported']
    assert len(state['graph']['nodes']) == 43
    assert state['graph']['summary']['structural_edges'] == 40
    groups = Counter(n['cluster'] for n in state['graph']['nodes'])
    assert all(groups[f'ПК {pc}'] == 2 for pc in range(1, 21))
    assert groups['Мандаты'] == groups['Общая сеть'] == groups['Администрирование'] == 1
    assert state['graph']['summary']['cluster_count'] == 23
    assert report['import_metadata']['row_count'] == 44
    assert report['import_metadata']['scope_column'] == 'Кластер'
    # The confirmed cluster-workbook format interprets mandate assignments and
    # data transfers, while absent destination labels remain unknown.
    assert state['model']['security_policy']['confidentiality_levels'] == ['Служебный']
    assert state['analysis']['summary'] == {'UNKNOWN': 1}
    assert report['profile_applied'] == 'automatic'
    assert not state['graph']['layer_edges']
    assert not state['graph']['summary']['violators']
