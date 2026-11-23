"""Template navigation keeps each inventory and its actual analysis semantics."""
import json
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.test import Client, override_settings
from openpyxl import Workbook
import pytest

from core import template_registry


def make_template(root, name, rows):
    folder = root / name
    folder.mkdir()
    # Registry discovery requires these resources but does not execute them.
    (folder / 'diagram.html').write_text('<!doctype html>')
    (folder / 'catalog.docx').write_bytes(b'placeholder for discovery')
    book = Workbook(write_only=True)
    sheet = book.create_sheet('Объекты')
    sheet.append(['Кластер', 'ID', 'Сущность', 'Вход', 'Выход'])
    for row in rows:
        sheet.append(row)
    book.save(folder / 'system.xlsx')
    book.close()
    return folder


def test_template_summary_counts_computers_separately_and_reads_dimensionless_workbook(tmp_path, monkeypatch):
    monkeypatch.setattr(template_registry, 'TEMPLATE_ROOT', tmp_path)
    rows = [[f'ПК {n}', 1, f'Компонент {n}', None, None] for n in range(1, 21)]
    rows.extend([[group, 1, group, None, None] for group in ('Мандаты', 'Общая сеть', 'Администрирование')])
    make_template(tmp_path, 'Моя система', rows)
    template = template_registry.list_templates()[0]
    assert template['valid'] is True
    assert template['pc_count'] == 20
    assert template['pcs'] == [f'ПК {n}' for n in range(1, 21)]
    assert template['entity_count'] == 23
    assert 'Общая сеть' in template['unique_entities']


def test_formula_or_corrupt_template_is_unavailable_in_selector(tmp_path, monkeypatch):
    monkeypatch.setattr(template_registry, 'TEMPLATE_ROOT', tmp_path)
    make_template(tmp_path, 'Формула', [['ПК 1', 1, 'A', None, '=1+1']])
    corrupt = make_template(tmp_path, 'Повреждён', [['ПК 1', 1, 'A', None, None]])
    (corrupt / 'system.xlsx').write_bytes(b'not an XLSX archive')
    assert len(template_registry.list_templates()) == 2
    assert all(not template['valid'] for template in template_registry.list_templates())


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/analysis/')
        yield client


def post(client, payload):
    return client.post('/api/scenario/', json.dumps(payload), content_type='application/json',
                       HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)


def test_custom_template_analyzes_its_own_graph_without_four_pc_demo(client, tmp_path, monkeypatch):
    monkeypatch.setattr(template_registry, 'TEMPLATE_ROOT', tmp_path)
    rows = [
        ['Мандаты', 99, 'Мандат 1 — Открытый', None, 'ПК 37 / Приёмник'],
        ['Мандаты', 100, 'Мандат 3 — Закрытый', None, 'ПК 37 / Источник'],
        ['ПК 37', 7, 'Источник', 'Мандат 3 — Закрытый', 'Приёмник'],
        ['ПК 37', 20, 'Приёмник', 'Мандат 1 — Открытый, Источник', None],
    ]
    make_template(tmp_path, 'Произвольная система', rows)
    from core import test_views
    def unexpected_demo(*args, **kwargs):
        raise AssertionError('Unrelated template must not run the four-PC demo')
    monkeypatch.setattr(test_views, 'execute_scenario', unexpected_demo)
    response = post(client, {'template': 'Произвольная система'})
    assert response.status_code == 200
    report = response.json()
    assert not report.get('scenario') and not report.get('repair')
    assert report['template'] == 'Произвольная система'
    assert report['filename'] == 'Произвольная система · system.xlsx'
    state = report['states']['imported']
    assert state['analysis']['summary'] == {'FAIL': 1}
    assert state['analysis']['results'][0]['witness']['nodes'] == ['37:7', '37:20']
    assert len(state['graph']['nodes']) == 4
    assert not state['model']['mutable']
    assert post(client, {'template': 'Произвольная система', 'repair': True}).status_code == 400


def test_shipped_twenty_pc_template_is_not_replaced_by_four_pc_experiment(client):
    response = post(client, {'template': 'Шаблон №2'})
    assert response.status_code == 200
    report = response.json()
    state = report['states']['imported']
    assert state['analysis']['summary'] == {'PASS': 978, 'FAIL': 73, 'UNKNOWN': 1}
    assert state['graph']['summary']['node_count'] == 1214
    assert state['graph']['summary']['structural_edges'] == 6595
    assert state['graph']['summary']['cluster_count'] == 25
    assert not report.get('scenario') and not report.get('repair')
    assert report['profile_applied'] == 'automatic'


@pytest.mark.parametrize('name', ['../Шаблон №1', '/tmp', '..', '', 42, None])
def test_template_name_does_not_resolve_an_arbitrary_path(client, name):
    assert post(client, {'template': name}).status_code == 400
