"""The landing-page upload must survive navigation into the analysis page."""
from collections import Counter
from html.parser import HTMLParser
import json
import os
from pathlib import Path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
import pytest

SOURCES = Path(__file__).resolve().parents[1] / 'data' / 'sources'
WORKBOOK = SOURCES / 'Четыре_конфигурации_ПК_уязвим.xlsx'


class Page(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.script = None
        self.scripts = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current_form = {'attrs': attrs, 'inputs': [], 'buttons': []}
            self.forms.append(self.current_form)
        elif tag in {'input', 'button'} and self.current_form is not None:
            self.current_form['inputs' if tag == 'input' else 'buttons'].append(attrs)
        elif tag == 'script' and attrs.get('type') == 'application/json':
            self.script = {'attrs': attrs, 'parts': []}

    def handle_data(self, data):
        if self.script is not None:
            self.script['parts'].append(data)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None
        elif tag == 'script' and self.script is not None:
            self.scripts.append(self.script)
            self.script = None

    def reports(self):
        payloads = [json.loads(''.join(script['parts'])) for script in self.scripts]
        return [payload for payload in payloads if isinstance(payload, dict) and payload.get('kind') == 'analysis_bundle']


@pytest.fixture
def client():
    with override_settings(ALLOWED_HOSTS=['testserver']):
        yield Client(enforce_csrf_checks=True)


def token_from_landing(client):
    response = client.get('/')
    assert response.status_code == 200
    assert 'csrftoken' in client.cookies
    return client.cookies['csrftoken'].value


def posted_file(client, endpoint, name=WORKBOOK.name, data=None):
    token = token_from_landing(client)
    return client.post(endpoint, {'file': SimpleUploadedFile(name, WORKBOOK.read_bytes() if data is None else data)}, HTTP_X_CSRFTOKEN=token)


def assert_actual_workbook(report):
    assert report['filename'] == WORKBOOK.name
    assert list(report['states']) == ['imported']
    state = report['states']['imported']
    assert state['model']['profile'] == 'strict'
    assert len(state['model']['nodes']) == 229
    assert '1:59' not in state['model']['nodes'] and '2:90' not in state['model']['nodes']
    graph = state['graph']
    assert graph['summary']['node_count'] == 229
    assert graph['summary']['structural_edges'] == 1088
    assert {c['id']: len(c['node_keys']) for c in graph['clusters']} == {
        'ПК 1': 52, 'ПК 2': 56, 'ПК 3': 59, 'ПК 4': 56, 'shared': 6}
    assert not any('Елена' in str(node.get('name', '')) for node in graph['nodes'])
    assert graph['layer_edges'] == []
    assert [r['checker'] for r in state['model']['requirements']] == ['semantic_readiness']
    assert state['analysis']['summary'] == {'UNKNOWN': 1}  # Structural import is not a security PASS.
    assert Counter(issue['kind'] for issue in report['import_issues']) == {
        'ambiguous_reference': 61, 'asymmetric_declaration': 223, 'unresolved_reference': 10}


def test_landing_has_real_multipart_file_submission_and_csrf(client):
    response = client.get('/')
    page = Page(response.content.decode())
    forms = [form for form in page.forms if form['attrs'].get('action') == '/analysis/']
    assert len(forms) == 1
    form = forms[0]
    assert form['attrs'].get('method', '').lower() == 'post'
    assert form['attrs'].get('enctype') == 'multipart/form-data'
    assert any(i.get('type') == 'file' and i.get('name') == 'file' and 'required' in i for i in form['inputs'])
    assert any(i.get('name') == 'csrfmiddlewaretoken' and i.get('value') for i in form['inputs'])
    assert any(b.get('type', 'submit') == 'submit' for b in form['buttons'])


def test_public_api_receives_the_attached_workbook_instead_of_demo(client):
    response = posted_file(client, '/api/analyze/')
    assert response.status_code == 200
    assert_actual_workbook(response.json())


def test_landing_post_embeds_actual_workbook_report_for_bootstrap(client):
    response = posted_file(client, '/analysis/')
    assert response.status_code == 200
    assert response['Content-Type'].startswith('text/html')
    page = Page(response.content.decode())
    assert any(script['attrs'].get('id') == 'initial-report' for script in page.scripts)
    assert not any(script['attrs'].get('id') == 'initial-error' for script in page.scripts)
    reports = page.reports()
    assert len(reports) == 1
    assert_actual_workbook(reports[0])


def test_analysis_post_rejects_missing_csrf_before_processing_upload(client):
    response = client.post('/analysis/', {'file': SimpleUploadedFile(WORKBOOK.name, WORKBOOK.read_bytes())})
    assert response.status_code == 403


@pytest.mark.parametrize('payload', [None, ('invalid.xlsx', b'not an Excel ZIP archive'), ('unsupported.zip', b'not supported')])
def test_missing_or_invalid_landing_upload_shows_error_without_demo_report(client, payload):
    token = token_from_landing(client)
    data = {} if payload is None else {'file': SimpleUploadedFile(*payload)}
    response = client.post('/analysis/', data, HTTP_X_CSRFTOKEN=token)
    assert response.status_code == 400
    assert response['Content-Type'].startswith('text/html')
    content = response.content.decode()
    page = Page(content)
    assert page.reports() == []
    assert not any(script['attrs'].get('id') == 'initial-report' for script in page.scripts)
    error_scripts = [script for script in page.scripts if script['attrs'].get('id') == 'initial-error']
    assert len(error_scripts) == 1
    error = json.loads(''.join(error_scripts[0]['parts']))
    assert error
    assert 'Елена' not in content
    assert ('Выберите' in error or 'Поддерживаются' in error or 'zip' in error.lower())


def test_direct_analysis_get_remains_available_without_upload_error(client):
    response = client.get('/analysis/')
    assert response.status_code == 200
    page = Page(response.content.decode())
    assert not any(script['attrs'].get('id') == 'initial-error' for script in page.scripts)
    assert 'id="security-graph"' in response.content.decode()


def test_embedded_report_preserves_unicode_and_escapes_script_terminators(client):
    name = 'Объект №1 </script><script>alert("upload")</script>'
    payload = {'schema':'component-security-graph/v1','nodes':{'arbitrary-key':{'name':name,'type':'component'}},'edges':[]}
    response = posted_file(client, '/analysis/', 'own-model.json', json.dumps(payload, ensure_ascii=False).encode())
    assert response.status_code == 200
    content = response.content.decode()
    assert '</script><script>alert' not in content
    reports = Page(content).reports()
    assert len(reports) == 1
    assert reports[0]['states']['uploaded']['model']['nodes']['arbitrary-key']['name'] == name
