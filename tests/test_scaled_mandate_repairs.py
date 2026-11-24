"""Scalable, independently verified repairs never alter the submitted source."""
from copy import deepcopy
from io import BytesIO
import json
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
from openpyxl import Workbook

from analyzer.engine import analyze
from analyzer.mandate_repairs import repair_mandate_flows
from analyzer.structural_profiles import compile_mandate_flows
from test_structural_profiles import graph


def sample_workbook():
    workbook = Workbook(write_only=True)
    worksheet = workbook.create_sheet('Конфигурации ПК')
    for row in (
        ['Кластер', 'ID', 'Сущность', 'Вход', 'Выход'],
        ['Мандаты', 90, 'Мандат 1 — Общий', None, 'ПК 42 / Цель'],
        ['Мандаты', 91, 'Мандат 3 — Секретный', None, 'ПК 42 / Источник'],
        ['ПК 42', 1, 'Источник', 'Мандат 3 — Секретный', 'Цель'],
        ['ПК 42', 2, 'Цель', 'Мандат 1 — Общий, Источник', None],
    ):
        worksheet.append(row)
    output = BytesIO()
    workbook.save(output)
    workbook.close()
    return output.getvalue()


def test_one_flow_changes_only_its_enabled_fact_and_remains_fully_verified():
    original_graph = graph()
    model = compile_mandate_flows(original_graph)
    original = deepcopy(model)
    before = analyze(model)
    assert before['summary'] == {'FAIL': 1, 'PASS': 1, 'UNKNOWN': 1}
    outcome = repair_mandate_flows(model, before)
    assert outcome['status'] == 'VERIFIED_CANDIDATE'
    assert outcome['checked_sets'] == 1
    assert outcome['independently_rechecked']
    assert outcome['verification']['summary'] == {'PASS': 2, 'UNKNOWN': 1}
    assert len(outcome['repaired_model']['diff']) == 1
    assert outcome['repaired_model']['diff'][0]['predicate'] == 'transition_enabled'
    assert model == original and original_graph == model['source_graph']
    assert not model['mutable']


def test_repair_fails_closed_when_flow_domain_not_proven_complete():
    model = compile_mandate_flows(graph())
    model['completeness'] = []
    original = deepcopy(model)
    outcome = repair_mandate_flows(model)
    assert outcome['status'] == 'NO_VALID_REPAIR_IN_ACTION_SPACE'
    assert 'repaired_model' not in outcome
    assert model == original


def test_source_workbook_repairs_from_small_upload_not_expanded_json():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/')
        source = sample_workbook()
        response = client.post('/api/analyze/', {
            'file': SimpleUploadedFile('network.xlsx', source)},
            HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
        assert response.status_code == 200
        original = response.json()
        assert original['repair_capability']['type'] == 'mandate_flow'
        assert original['states']['imported']['analysis']['summary'] == {'FAIL': 1}

        response = client.post('/api/repair/', {
            'source_file': SimpleUploadedFile('network.xlsx', source)},
            HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
        assert response.status_code == 200, response.content[:400]
        outcome = response.json()
        assert outcome['repair']['status'] == 'VERIFIED_CANDIDATE'
        assert outcome['states']['repaired']['analysis']['summary'] == {'PASS': 1}
        assert outcome['states']['before']['graph']['summary']['node_count'] == 4
        assert outcome['states']['repaired']['graph']['summary']['structural_edges'] == 3
        assert 'source_graph' not in outcome['states']['repaired'].get('model', {})


def test_unrelated_models_are_not_auto_repaired():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        client = Client(enforce_csrf_checks=True)
        client.get('/')
        response = client.post('/api/repair/', {'source_file': SimpleUploadedFile('other.txt', b'x')},
                               HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
        assert response.status_code == 400
