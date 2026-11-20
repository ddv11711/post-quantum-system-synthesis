"""Browser QA for portable graphs, honest unknowns, and verified repairs.

Optional dependencies: Playwright and a Chromium-compatible browser.
Run against an already running Django server; no server is started here.
"""
import argparse
import asyncio
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright, expect


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_API = '/api/graph-example/'
UPLOAD_API = '/api/analyze/'
REPAIR_API = '/api/repair/'
API_PATHS = {EXAMPLE_API, UPLOAD_API, REPAIR_API}
POSITIONS = '(nodes) => Object.fromEntries(nodes.map(n => [n.dataset.nodeKey, n.getAttribute("transform")]))'
NODE_KEYS = '(nodes) => nodes.map(n => n.dataset.nodeKey).sort()'


def api_response(path):
    return lambda response: urlparse(response.url).path == path and response.request.method == 'POST'


def initial_state(report):
    states = report['states']
    key = next((key for key in ('before', 'experiment', 'uploaded', 'imported', 'changed', 'baseline')
                if key in states), next(iter(states)))
    return states[key]


def node_locator(pane, key):
    return pane.locator('[data-node-key=' + json.dumps(key, ensure_ascii=False) + ']')


def renamed_graph(payload):
    """Rename identifiers everywhere, preserving the declared semantics."""
    mapping = {key: f'new-site/узел-{i}' for i, key in enumerate(payload['nodes'], 1)}
    def replace(value):
        if isinstance(value, str):
            return mapping.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {mapping.get(key, key): replace(item) for key, item in value.items()}
        return value
    changed = replace(payload)
    for i, node in enumerate(changed['nodes'].values(), 1):
        node['name'] = f'Новый компонент {i}'
    changed['state'] = 'renamed-independent-model'
    return changed, mapping


async def graph_is_complete(pane, snapshot):
    graph = snapshot['graph']
    await expect(pane).to_be_visible()
    await expect(pane.locator('.sg-node')).to_have_count(len(graph['nodes']))
    if graph.get('layer_edges'):
        await expect(pane.locator('.sg-layer-edge')).to_have_count(len(graph['layer_edges']))
        await expect(pane.locator('[data-edge-kind="structural"]')).to_have_count(0)
    else:
        await expect(pane.locator('[data-edge-kind="structural"]')).to_have_count(graph['summary']['structural_edges'])
    assert await pane.locator('.sg-node').evaluate_all(NODE_KEYS) == sorted(node['key'] for node in graph['nodes'])
    await expect(pane.locator('[data-violator="true"]')).to_have_count(len(graph['summary']['violators']))


async def graph_summary_matches(page, snapshot):
    results = snapshot['analysis']['results']
    passed = sum(item['status'] == 'PASS' for item in results)
    substantive = any(item.get('checker') != 'semantic_readiness' and item['status'] != 'NOT_APPLICABLE' for item in results)
    if snapshot['analysis'].get('model_errors'):
        await expect(page.locator('#check-count')).to_have_text('Проверка заблокирована')
    elif not substantive:
        await expect(page.locator('#check-count')).to_have_text('Проверка не выполнена')
        await expect(page.locator('#check-icon')).to_have_text('—')
        await expect(page.locator('#finding-count')).to_be_hidden()
        await expect(page.locator('#unknown-details')).to_be_visible()
        await expect(page.locator('#unknown-summary')).to_have_text('Не хватает условий проверки')
    else:
        await expect(page.locator('#check-count')).to_have_text(f'{passed} из {len(results)} проверок пройдено')
    await expect(page.locator('#node-count')).to_have_text(str(len(snapshot['graph']['nodes'])))
    assert ''.join((await page.locator('#edge-count').inner_text()).split()) == str(snapshot['graph']['summary']['structural_edges'])
    await expect(page.locator('#system-status')).not_to_have_attribute('data-state', 'loading')


async def upload(page, file, *, status=200):
    async with page.expect_response(api_response(UPLOAD_API)) as pending:
        await page.locator('#graph-file').set_input_files(file)
    response = await pending.value
    assert response.status == status, await response.text()
    payload = await response.json()
    if status == 200:
        await expect(page.locator('#file-name')).to_have_text(payload['filename'])
        await graph_summary_matches(page, initial_state(payload))
    else:
        await expect(page.locator('#page-feedback')).to_be_visible()
    return payload


async def no_false_success(page):
    await expect(page.locator('#system-status')).to_have_attribute('data-state', 'warning')
    await expect(page.locator('#check-icon')).not_to_have_class('is-complete')
    await expect(page.locator('#repair-button')).to_be_disabled()
    await expect(page.locator('#after-tab')).to_be_disabled()
    await expect(page.locator('#security-graph section[data-graph-phase="after"]')).to_have_count(0)


async def check(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    checks, errors, requests = [], [], []
    base_url = args.url.rstrip('/')
    fixture = json.loads((ROOT / 'examples/portable/mixed_security.json').read_text())
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            executable_path=args.chrome, headless=True, args=['--no-sandbox'])
        context = await browser.new_context(viewport={'width': 1440, 'height': 1080}, reduced_motion='reduce')
        page = await context.new_page()
        page.set_default_timeout(30000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: requests.append(urlparse(request.url).path)
                if urlparse(request.url).path in API_PATHS and request.method == 'POST' else None)
        before = page.locator('#security-graph section.sg-pane[data-graph-phase="before"]')
        after = page.locator('#security-graph section.sg-pane[data-graph-phase="after"]')
        repair = page.locator('#repair-button')

        await page.goto(base_url + '/')
        await expect(page.locator('#home-screen')).to_be_visible()
        await expect(page.locator('#security-app')).to_have_count(0)
        await expect(page.locator('a.demo-link')).to_have_attribute('href', '/analysis/')
        async with page.expect_response(api_response(EXAMPLE_API)) as pending:
            await page.locator('a.demo-link').click()
        assert urlparse(page.url).path == '/analysis/'
        response = await pending.value
        assert response.status == 200
        default_example = await response.json()
        assert requests == [EXAMPLE_API], requests
        assert response.request.post_data_json == {'example': 'fls'}
        default_state = initial_state(default_example)
        assert len(default_state['graph']['layer_edges']) == 12
        assert default_state['graph']['summary']['structural_edges'] == 7
        await graph_is_complete(before, default_state)
        await expect(page.locator('.sg-view-tabs [role="tab"]')).to_have_count(5)
        await expect(page.locator('.sg-view-tabs [data-view="clusters"]')).to_have_text('Между ПК')
        checks.append('The explicit landing demo link opens the F/L/S example with actual PC tabs and 12 declared layer arrows')
        original = await upload(page, ROOT / 'examples/portable/mixed_security.json')
        snapshot = initial_state(original)
        assert len(snapshot['graph']['nodes']) == 6
        assert snapshot['graph']['summary']['structural_edges'] == 5
        assert snapshot['analysis']['summary'] == {'FAIL': 5, 'PASS': 4}
        assert 'repaired' not in original['states']
        await graph_is_complete(before, snapshot)
        await graph_summary_matches(page, snapshot)
        await expect(after).to_have_count(0)
        await expect(page.locator('#after-tab')).to_be_disabled()
        await expect(repair).to_be_enabled()
        await expect(page.locator('#findings-list > .finding-card')).to_have_count(5)
        await expect(page.locator('#coverage-details')).to_be_visible()
        offender_key = snapshot['graph']['summary']['violators'][0]
        offender = node_locator(before, offender_key)
        await expect(offender).to_have_attribute('data-violator', 'true')
        assert await offender.locator('.sg-node-shape').evaluate('(node) => getComputedStyle(node).fill') == 'rgb(213, 45, 66)'
        graph_nodes = {node['key']: node for node in snapshot['graph']['nodes']}
        assert graph_nodes['analyst:Елена']['security_label']['level'] == 'public'
        assert graph_nodes['analyst:Елена']['clearance']['level'] == 'restricted'
        assert graph_nodes['vault/research']['security_label']['categories'] == ['research']
        original_positions = await before.locator('.sg-node').evaluate_all(POSITIONS)
        await page.get_by_role('searchbox', name='Найти узел графа').fill(offender_key)
        await page.get_by_role('searchbox', name='Найти узел графа').press('Enter')
        await expect(page.locator('.sg-inspector')).to_be_visible()
        await expect(page.locator('.sg-inspector')).to_contain_text(graph_nodes[offender_key]['name'])
        await expect(page.locator('.sg-inspector')).to_contain_text('public')
        await expect(page.locator('.sg-inspector')).to_contain_text('restricted')
        await expect(offender).to_have_class(re.compile(r'\bsg-selected\b'))
        await page.get_by_role('button', name='Вписать', exact=True).click()
        await expect(page.locator('pre:visible, .scenario-card')).to_have_count(0)
        await page.screenshot(path=str(out / 'before-repair.png'), full_page=True)
        checks.append('Portable example loads through the public API: 6 nodes, 5 source edges, 5 failures; graph search and inspected identity match real data')

        async def repair_failure(route):
            await route.fulfill(status=503, content_type='application/json',
                                body=json.dumps({'error': 'Проверочная ошибка исправления'}, ensure_ascii=False))
        await page.route('**' + REPAIR_API, repair_failure)
        async with page.expect_response(api_response(REPAIR_API)) as pending:
            await repair.click()
        assert (await pending.value).status == 503
        await expect(page.locator('#page-feedback')).to_have_text('Проверочная ошибка исправления')
        await expect(repair).to_be_enabled()
        await graph_is_complete(before, snapshot)
        await expect(after).to_have_count(0)
        await expect(page.locator('#after-tab')).to_be_disabled()
        await page.unroute('**' + REPAIR_API, repair_failure)
        checks.append('Repair HTTP failure preserves the original graph and allows retry without inventing an after state')

        intercepted, release = asyncio.Event(), asyncio.Event()
        repair_requests = []
        async def delayed_repair(route):
            repair_requests.append(route.request.url)
            assert 'multipart/form-data' in route.request.headers['content-type']
            intercepted.set()
            await release.wait()
            await route.continue_()
        await page.route('**' + REPAIR_API, delayed_repair)
        async with page.expect_response(api_response(REPAIR_API), timeout=60000) as pending:
            await repair.click()
            try:
                await asyncio.wait_for(intercepted.wait(), timeout=10)
                await expect(repair).to_be_disabled()
                await repair.evaluate('(button) => button.dispatchEvent(new MouseEvent("click", {bubbles: true}))')
                await graph_is_complete(before, snapshot)
                await expect(after).to_have_count(0)
            finally:
                release.set()
        response = await pending.value
        assert response.status == 200, await response.text()
        repaired = await response.json()
        fixed = repaired['states']['repaired']
        assert len(repair_requests) == 1, repair_requests
        await page.unroute('**' + REPAIR_API, delayed_repair)
        assert repaired['repair']['status'] in {'OPTIMAL_REPAIR', 'VERIFIED_CANDIDATE'}
        assert len(repaired['repair']['selected']) == 5
        assert fixed['analysis']['summary'] == {'PASS': 9}
        await graph_is_complete(after, fixed)
        await graph_summary_matches(page, fixed)
        await expect(before).to_be_hidden()
        await expect(after.locator('[data-violator="true"]')).to_have_count(0)
        await expect(node_locator(after, offender_key)).to_have_attribute('data-fixed', 'true')
        assert await after.locator('.sg-node').evaluate_all(POSITIONS) == original_positions
        await expect(repair).to_be_disabled()
        await expect(repair).to_have_text('Исправления проверены')
        await expect(page.locator('#system-status')).to_have_attribute('data-state', 'success')
        await expect(page.locator('#after-tab')).to_be_enabled()
        await expect(page.locator('#findings-list > .finding-card.is-fixed')).to_have_count(5)
        await expect(page.locator('#page-feedback')).to_be_hidden()
        await page.screenshot(path=str(out / 'after-repair.png'), full_page=True)
        checks.append('One multipart repair request applies five permitted actions; all actual requirements pass and the offending user loses red marking')

        request_count = len(requests)
        await page.locator('#before-tab').click()
        await graph_is_complete(before, snapshot)
        await expect(after).to_be_hidden()
        await expect(page.locator('#findings-list > .finding-card.is-fixed')).to_have_count(0)
        await page.locator('#after-tab').click()
        await graph_is_complete(after, fixed)
        await expect(before).to_be_hidden()
        assert len(requests) == request_count
        checks.append('Before/after tabs preserve positions and history without additional requests')
        await page.set_viewport_size({'width': 390, 'height': 844})
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile page overflows horizontally'
        await graph_is_complete(after, fixed)
        await expect(page.locator('#before-tab')).to_be_visible()
        await expect(page.locator('#after-tab')).to_be_visible()
        await page.screenshot(path=str(out / 'mobile.png'), full_page=True)
        checks.append('390px mobile layout retains the full graph and controls without horizontal overflow')
        await page.set_viewport_size({'width': 1440, 'height': 1080})

        unknown_report = await upload(page, ROOT / 'examples/portable/labels_unknown.json')
        unknown = initial_state(unknown_report)
        assert unknown['analysis']['summary'].get('UNKNOWN', 0) > 0
        await graph_is_complete(before, unknown)
        await no_false_success(page)
        await expect(page.locator('#unknown-details')).to_be_visible()
        await page.locator('#unknown-summary').click()
        await expect(page.locator('#unknown-list .finding-card').first).to_be_visible()
        await page.screenshot(path=str(out / 'unknown-labels.png'), full_page=True)
        checks.append('Real unknown-label JSON upload exposes incomplete checks and never claims safety or offers a fabricated repair')

        structural_report = await upload(page, ROOT / 'examples/portable/structural_only.json')
        structural = initial_state(structural_report)
        assert structural['graph']['summary']['structural_edges'] == 1
        assert not structural['analysis']['summary'].get('FAIL')
        await graph_is_complete(before, structural)
        await no_false_success(page)
        checks.append('Portable structure-only JSON renders its full graph without interpreting absent security data as PASS')

        changed, mapping = renamed_graph(fixture)
        renamed_report = await upload(page, {'name': 'renamed-model.json', 'mimeType': 'application/json',
                                             'buffer': json.dumps(changed, ensure_ascii=False).encode()})
        renamed = initial_state(renamed_report)
        assert renamed['analysis']['summary'] == snapshot['analysis']['summary']
        assert set(node['key'] for node in renamed['graph']['nodes']) == set(mapping.values())
        assert set(renamed['graph']['summary']['violators']) == {mapping[key] for key in snapshot['graph']['summary']['violators']}
        await graph_is_complete(before, renamed)
        await expect(page.locator('#repair-button')).to_be_enabled()
        assert 'Елена' not in await page.locator('#findings-list').inner_text()
        search_key = mapping[offender_key]
        await page.get_by_role('searchbox', name='Найти узел графа').fill(search_key)
        await page.get_by_role('searchbox', name='Найти узел графа').press('Enter')
        await expect(page.locator('.sg-inspector')).to_contain_text('Новый компонент')
        checks.append('Renamed Unicode identifiers and component names preserve outcomes; the page uses uploaded identities instead of fixed scenario text')

        download = await page.request.get(base_url + '/api/graph-example/file/?format=xlsx')
        assert download.status == 200
        xlsx = await download.body()
        assert xlsx.startswith(b'PK')
        xlsx_report = await upload(page, {'name': 'downloaded-example.xlsx',
                                          'mimeType': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                          'buffer': xlsx})
        xlsx_state = initial_state(xlsx_report)
        assert xlsx_state['analysis']['summary'] == snapshot['analysis']['summary']
        assert {node['key'] for node in xlsx_state['graph']['nodes']} == set(fixture['nodes'])
        await graph_is_complete(before, xlsx_state)
        await expect(repair).to_be_enabled()
        checks.append('Downloaded semantic XLSX is uploaded unchanged and reproduces the actual JSON example analysis and graph')

        saved = {'kind': 'analysis_bundle', 'states': {'before': structural},
                 'available_profiles': [None, {'id': 'incomplete'},
                    {'id': 'unavailable', 'name': 'Недоступный профиль',
                     'description': 'Для этого профиля не хватает данных.',
                     'can_apply': False, 'diagnostics': 'not-an-array'}]}
        saved_report = await upload(page, {'name': 'saved-with-incomplete-profiles.json', 'mimeType': 'application/json',
                                          'buffer': json.dumps(saved, ensure_ascii=False).encode()})
        assert saved_report['display_mode'] == 'saved_report'
        await graph_is_complete(before, initial_state(saved_report))
        await expect(page.locator('.profile-choice')).to_have_count(1)
        await expect(page.get_by_role('button', name='Проверить по профилю', exact=True)).to_be_disabled()
        await expect(page.locator('#page-feedback')).to_be_hidden()
        checks.append('A saved report ignores malformed optional profile entries, handles invalid diagnostics safely and keeps unavailable profiles disabled without losing its graph')

        legacy_report = await upload(page, ROOT / 'data/sources/graf-svyazey-pk.html')
        legacy = initial_state(legacy_report)
        assert len(legacy['graph']['nodes']) == 231
        assert legacy['graph']['summary']['structural_edges'] == 1100
        assert all(result.get('checker') == 'semantic_readiness' and result['status'] == 'UNKNOWN'
                   for result in legacy['analysis']['results'])
        await graph_is_complete(before, legacy)
        await no_false_success(page)
        await expect(page.locator('#status-title')).to_have_text('Проверка безопасности не выполнена')
        await page.get_by_role('button', name='Как добавить условия проверки').click()
        assert await page.locator('#format-help').evaluate('(details) => details.open')
        await expect(page.locator('#format-help')).to_contain_text('требования безопасности')
        await page.locator('#format-help summary').click()
        checks.append('Legacy HTML retains all 231 nodes and 1100 edges; missing substantive requirements show an unperformed check without a zero-violations badge or 0-of-0 success, with working data-format guidance')

        preserved_positions = await before.locator('.sg-node').evaluate_all(POSITIONS)
        error = await upload(page, {'name': 'broken.json', 'mimeType': 'application/json', 'buffer': b'{broken'}, status=400)
        assert error.get('error')
        await expect(page.locator('#page-feedback')).to_contain_text(error['error'])
        await expect(page.locator('#page-feedback')).to_contain_text('broken.json')
        await expect(page.locator('#page-feedback')).to_contain_text('предыдущий граф')
        await graph_is_complete(before, legacy)
        assert await before.locator('.sg-node').evaluate_all(POSITIONS) == preserved_positions
        await no_false_success(page)
        checks.append('Malformed uploaded JSON returns HTTP400 while preserving the previously displayed complete graph')

        retry_page = await context.new_page()
        retry_page.set_default_timeout(30000)
        retry_page.on('pageerror', lambda error: errors.append(str(error)))
        async def initial_failure(route):
            await route.abort('failed')
        await retry_page.route('**' + EXAMPLE_API, initial_failure)
        await retry_page.goto(base_url + '/tests/')
        await expect(retry_page.locator('#retry-button')).to_be_visible()
        await expect(retry_page.locator('#repair-button')).to_be_disabled()
        await expect(retry_page.locator('#security-graph .sg-node')).to_have_count(0)
        assert urlparse(retry_page.url).path == '/analysis/'
        await retry_page.unroute('**' + EXAMPLE_API, initial_failure)
        async with retry_page.expect_response(api_response(EXAMPLE_API)) as pending:
            await retry_page.locator('#retry-button').click()
        response = await pending.value
        assert response.status == 200
        retry_state = initial_state(await response.json())
        await graph_is_complete(retry_page.locator('#security-graph section.sg-pane[data-graph-phase="before"]'), retry_state)
        await expect(retry_page.locator('#retry-button')).to_have_count(0)
        await expect(retry_page.locator('#repair-button')).to_be_enabled()
        checks.append('Legacy URL redirects to /analysis/; initial network failure has a working retry and no invented graph')
        assert not errors, errors
        await browser.close()

    report = {'status': 'PASS', 'checks': checks, 'javascript_errors': errors}
    (out / 'browser-check.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:8012')
    parser.add_argument('--chrome', default='/usr/bin/google-chrome')
    parser.add_argument('--out', default='results/graph-ui')
    asyncio.run(check(parser.parse_args()))
