"""The single-page scenario runs real analysis and never fabricates a repair."""
import json
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from django.test import Client, override_settings
import pytest


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        yield Client(enforce_csrf_checks=True)


def post(client, payload):
    client.get('/')
    return client.post('/api/scenario/', json.dumps(payload), content_type='application/json',
                       HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)


def test_old_test_page_redirects_to_the_single_page(client):
    response = client.get('/tests/')
    assert response.status_code == 302
    assert response['Location'] == '/'


def test_single_scenario_requires_post_and_csrf(client):
    assert client.get('/api/scenario/').status_code == 405
    assert client.post('/api/scenario/', '{}', content_type='application/json').status_code == 403


@pytest.mark.parametrize('payload', [[], {'repair': 'true'}, {'repair': 1}, {'scenario': 'baseline'},
                                     {'closed_inventory': False}, {'path': '/etc/passwd'}])
def test_only_an_explicit_boolean_repair_option_is_accepted(client, payload):
    assert post(client, payload).status_code == 400


def test_initial_view_is_the_complete_declared_experiment(client):
    response = post(client, {})
    assert response.status_code == 200
    report = response.json()
    assert report['kind'] == 'analysis_bundle'
    assert report['scenario'] == {'id': 'experiment', 'title': 'Четыре ПК и общий сетевой диск',
                                   'closed_inventory': True, 'educational': True}
    assert set(report['states']) == {'before'}
    state = report['states']['before']
    assert state['analysis']['summary'] == {'PASS': 9, 'FAIL': 3}
    assert len(state['graph']['nodes']) == 231
    assert state['graph']['summary']['structural_edges'] == 1088
    assert state['graph']['summary']['violators'] == ['2:99']
    assert state['graph']['summary']['fail_count'] == 3
    assert 'model' not in state
    assert all('evidence' not in result for result in state['analysis']['results'])
    assert 'полным перечнем' in report['notice']
    assert 'repair' not in report


def test_repair_view_returns_only_the_original_and_actually_verified_graphs(client):
    response = post(client, {'repair': True})
    assert response.status_code == 200
    report = response.json()
    assert set(report['states']) == {'before', 'repaired'}
    assert report['states']['before']['analysis']['summary'] == {'PASS': 9, 'FAIL': 3}
    after = report['states']['repaired']
    assert after['analysis']['summary'] == {'PASS': 12}
    assert len(after['graph']['nodes']) == 231
    assert after['graph']['summary']['structural_edges'] == 1088
    assert after['graph']['summary']['violators'] == []
    assert report['repair']['status'] == 'OPTIMAL_REPAIR'
    assert report['repair']['objective_value'] == [4, 4]
    assert report['repair']['independently_rechecked'] is True
    assert not {'model', 'baseline', 'changed', 'experiment'} & set(report['states'])


def test_a_failed_search_does_not_produce_an_after_picture(client, monkeypatch):
    from core import test_views
    real = test_views.execute_scenario
    def no_repair(*args, **kwargs):
        result = real('experiment', repair=False, closed_inventory=True)
        result['report']['repair'] = {'status': 'SEARCH_LIMIT', 'reason': 'candidate_budget', 'targets': ['nas_forbidden']}
        return result
    monkeypatch.setattr(test_views, 'execute_scenario', no_repair)
    report = post(client, {'repair': True}).json()
    assert report['repair']['status'] == 'SEARCH_LIMIT'
    assert set(report['states']) == {'before'}
    assert report['states']['before']['graph']['summary']['violators'] == ['2:99']


def test_unverified_after_state_is_not_presented_as_a_fixed_graph(client, monkeypatch):
    from core import test_views
    real = test_views.execute_scenario
    def invalid_repair(*args, **kwargs):
        result = real('experiment', repair=False, closed_inventory=True)
        result['report']['repair'] = {'status': 'OPTIMAL_REPAIR', 'targets': ['nas_forbidden'],
                                      'independently_rechecked': True}
        result['report']['states']['repaired'] = result['report']['states']['experiment']
        return result
    monkeypatch.setattr(test_views, 'execute_scenario', invalid_repair)
    report = post(client, {'repair': True}).json()
    assert report['repair']['status'] == 'VERIFICATION_FAILED'
    assert set(report['states']) == {'before'}


@pytest.mark.parametrize('incomplete', ['UNKNOWN', 'missing'])
def test_repair_cannot_drop_or_lose_confirmation_of_an_original_requirement(client, monkeypatch, incomplete):
    from copy import deepcopy
    from core import test_views
    real = test_views.execute_scenario
    def incomplete_repair(*args, **kwargs):
        result = real('experiment', repair=False, closed_inventory=True)
        result['report']['repair'] = {'status': 'OPTIMAL_REPAIR', 'targets': ['nas_forbidden'],
                                      'independently_rechecked': True}
        after = deepcopy(result['report']['states']['experiment'])
        for finding in after['analysis']['results']:
            finding['status'] = 'PASS'
        if incomplete == 'missing':
            after['analysis']['results'] = [finding for finding in after['analysis']['results']
                                            if finding['id'] != 'pc1_nas_required']
        else:
            next(finding for finding in after['analysis']['results']
                 if finding['id'] == 'pc1_nas_required')['status'] = incomplete
        result['report']['states']['repaired'] = after
        return result
    monkeypatch.setattr(test_views, 'execute_scenario', incomplete_repair)
    report = post(client, {'repair': True}).json()
    assert report['repair']['status'] == 'VERIFICATION_FAILED'
    assert set(report['states']) == {'before'}
