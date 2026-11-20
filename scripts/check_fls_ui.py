"""Integrated browser regression for declared F/L/S channels and cluster views.

Uses the running Django API and uploaded fixtures, without mocked analysis.
Requires the optional Playwright browser environment used by check_test_ui.py.
"""
import argparse
import asyncio
from collections import Counter
from copy import deepcopy
import csv
import io
import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright, expect

from check_test_ui import (
    ROOT, EXAMPLE_API, UPLOAD_API, REPAIR_API, API_PATHS,
    api_response, initial_state, graph_is_complete, graph_summary_matches, upload,
)

LAYERS = ('physical', 'syntactic', 'semantic')


def signatures(snapshot):
    return sorted((edge['source'], edge['target'], edge['layer'], edge['value'],
                   edge.get('declared_value'), bool(edge.get('via_protection')),
                   tuple(edge.get('protection_via', []))) for edge in snapshot['graph'].get('layer_edges', []))


def values(snapshot, layer):
    pairs = {}
    for edge in snapshot['graph'].get('layer_edges', []):
        if edge['layer'] == layer:
            pairs.setdefault((edge['source'], edge['target']), []).append(edge)
    result = {}
    for source in snapshot['graph']['nodes']:
        for target in snapshot['graph']['nodes']:
            edges = pairs.get((source['key'], target['key']), [])
            value = ('UNDECLARED' if not edges else 'TRUE' if any(edge['value'] == 'TRUE' for edge in edges)
                     else 'UNKNOWN' if any(edge['value'] != 'FALSE' for edge in edges) else 'FALSE')
            result[(source['key'], target['key'])] = (value, any(edge.get('via_protection') for edge in edges))
    return result


async def matrix_matches(page, snapshot, layer):
    await page.locator('.sg-matrix-tabs [data-layer=' + layer + ']').click()
    await expect(page.locator('.sg-matrix')).to_have_attribute('data-matrix-layer', layer)
    actual = await page.locator('.sg-matrix td').evaluate_all(
        '(cells)=>cells.map(c=>[c.dataset.source,c.dataset.target,c.dataset.value,c.dataset.viaProtection==="true",c.textContent.trim()])')
    assert {(source, target): (value, protection) for source, target, value, protection, _ in actual} == values(snapshot, layer)
    for _, _, value, protection, label in actual:
        assert label == {'TRUE': '1', 'FALSE': '0', 'UNKNOWN': '?', 'UNDECLARED': '—'}[value] + (' ↝' if protection else '')


async def assert_layer_drawing(pane, snapshot):
    await graph_is_complete(pane, snapshot)
    expected = {edge['id']: edge for edge in snapshot['graph']['layer_edges']}
    drawn = await pane.locator('.sg-layer-edge').evaluate_all('''edges => edges.map(edge => ({
        id: edge.dataset.edgeId, source: edge.dataset.source, target: edge.dataset.target,
        layer: edge.dataset.layer, value: edge.dataset.value, protection: edge.dataset.viaProtection === 'true',
        stroke: getComputedStyle(edge).stroke, dashed: getComputedStyle(edge).strokeDasharray !== 'none',
        start: edge.getAttribute('marker-start'), end: edge.getAttribute('marker-end'), d: edge.getAttribute('d')
    }))''')
    assert len(drawn) == len(expected)
    colors = {}
    for item in drawn:
        edge = expected[item['id']]
        assert (item['source'], item['target'], item['layer'], item['value']) == (edge['source'], edge['target'], edge['layer'], edge['value'])
        assert item['protection'] == bool(edge['via_protection'])
        assert item['dashed'] == bool(edge['via_protection'])
        assert item['start'] is None and item['end'], item
        colors.setdefault(item['layer'], set()).add(item['stroke'])
    assert all(len(colors[layer]) == 1 for layer in LAYERS)
    assert len({next(iter(colors[layer])) for layer in LAYERS}) == 3
    assert len({item['d'] for item in drawn}) == len(drawn), 'Layer or directional lanes overlap exactly'


async def check(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    fixture = json.loads((ROOT / 'examples/portable/fls_clusters.json').read_text())
    errors, requests, checks = [], [], []
    base = args.url.rstrip('/')
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=args.chrome, headless=True, args=['--no-sandbox'])
        page = await browser.new_page(viewport={'width': 1440, 'height': 1080}, reduced_motion='reduce')
        page.set_default_timeout(30000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: requests.append(urlparse(request.url).path)
                if request.method == 'POST' and urlparse(request.url).path in API_PATHS else None)
        before = page.locator('.sg-pane[data-graph-phase=before]')
        after = page.locator('.sg-pane[data-graph-phase=after]')
        async with page.expect_response(api_response(EXAMPLE_API)) as pending:
            await page.goto(base + '/analysis/')
        response = await pending.value
        assert response.status == 200
        assert response.request.post_data_json == {'example': 'fls'}
        snapshot = initial_state(await response.json())
        assert snapshot['analysis']['summary'] == {'FAIL': 5, 'PASS': 4}
        assert len(snapshot['graph']['nodes']) == 6
        assert snapshot['graph']['summary']['structural_edges'] == 7
        assert len(snapshot['graph']['layer_edges']) == 12
        await assert_layer_drawing(before, snapshot)
        await graph_summary_matches(page, snapshot)
        pairs = Counter((edge['source'], edge['target']) for edge in snapshot['graph']['layer_edges'])
        assert len(pairs) == 4 and set(pairs.values()) == {3}
        protected = [edge for edge in snapshot['graph']['layer_edges'] if edge['via_protection']]
        assert len(protected) == 6 and len({(edge['source'], edge['target']) for edge in protected}) == 2
        assert all(edge['protection_via'] == ['guard-alpha'] for edge in protected)
        await expect(before.locator('[data-violator=true]')).to_have_count(1)
        await expect(page.locator('.sg-view-tabs [data-view=clusters]')).to_have_text('Между ПК')
        await page.screenshot(path=str(out / 'fls-before.png'), full_page=True)
        checks.append('Real default example: 12 distinct single-head arrows, three colors, three levels per direction; only the six explicitly protected arrows are dashed')

        await page.locator('.sg-source-options summary').click()
        await page.locator('.sg-source-options input').check()
        await expect(before.locator('[data-edge-kind=structural]')).to_have_count(7)
        assert await before.locator('.sg-layer-background').evaluate_all('(edges)=>edges.every(e=>getComputedStyle(e).stroke==="rgb(148, 163, 184)"&&e.getAttribute("marker-end").includes("plain"))')
        await page.locator('.sg-source-options input').uncheck()
        await expect(before.locator('[data-edge-kind=structural]')).to_have_count(0)
        await page.locator('.sg-source-options summary').click()
        checks.append('Original structure remains available separately in gray and is not inferred as F/L/S')

        for cluster in ('ПК1', 'ПК2'):
            await page.locator('.sg-view-tabs [data-view="cluster:' + cluster + '"]').click()
            await expect(before.locator('.sg-node')).to_have_count(3)
            expected_nodes = {node['key'] for node in snapshot['graph']['nodes'] if node['cluster'] == cluster}
            actual_nodes = await before.locator('.sg-node').evaluate_all('(nodes)=>nodes.map(node=>node.dataset.nodeKey)')
            assert set(actual_nodes) == expected_nodes
            internal = [edge for edge in snapshot['graph']['layer_edges'] if edge['source'] in expected_nodes and edge['target'] in expected_nodes]
            await expect(before.locator('.sg-layer-edge')).to_have_count(len(internal))
            await expect(before.locator('.sg-boundary-note')).to_contain_text('Внутри показаны только его компоненты')
        await page.locator('.sg-view-tabs [data-view=clusters]').click()
        await expect(before.locator('.sg-node')).to_have_count(2)
        await expect(before.locator('.sg-layer-edge')).to_have_count(6)
        await expect(before.locator('[data-violator=true]')).to_have_count(0)
        await before.locator('[data-cluster-id="ПК1"]').press('Enter')
        await expect(page.locator('.sg-view-tabs [data-view="cluster:ПК1"]')).to_have_attribute('aria-selected', 'true')
        await page.get_by_role('searchbox', name='Найти узел графа').fill('vault/research')
        await page.get_by_role('searchbox', name='Найти узел графа').press('Enter')
        await expect(page.locator('.sg-view-tabs [data-view="cluster:ПК2"]')).to_have_attribute('aria-selected', 'true')
        await expect(page.locator('.sg-inspector')).to_contain_text('База исследований')
        checks.append('PC tabs show their actual three components; inter-PC overview has two cluster vertices and six directed arrows, with drilldown and cross-view search')

        await page.locator('.sg-view-tabs [data-view=matrices]').click()
        for layer in LAYERS:
            await matrix_matches(page, snapshot, layer)
        await expect(page.locator('.sg-matrix-phase')).to_contain_text('До исправления')
        checks.append('All three directed matrices exactly match every source/target pair and protection annotation in the real API payload')

        mutated = deepcopy(fixture)
        for edge in mutated['edges']:
            if edge['id'] == 'workstation-link':
                edge['layers'] = {'physical': True, 'syntactic': False, 'semantic': 'UNKNOWN'}
            elif edge['id'] == 'archive-link':
                edge['layers'] = {'physical': 'UNKNOWN', 'syntactic': True, 'semantic': False}
        uncertain_report = await upload(page, {'name': 'fls-unknown-and-false.json', 'mimeType': 'application/json',
                                               'buffer': json.dumps(mutated, ensure_ascii=False).encode()})
        uncertain = initial_state(uncertain_report)
        await assert_layer_drawing(before, uncertain)
        await expect(page.locator('#system-status')).to_have_attribute('data-state', 'warning')
        await page.locator('.sg-view-tabs [data-view=matrices]').click()
        seen = set()
        for layer in LAYERS:
            await matrix_matches(page, uncertain, layer)
            seen.update(value[0] for value in values(uncertain, layer).values())
        assert seen == {'TRUE', 'FALSE', 'UNKNOWN', 'UNDECLARED'}, seen
        await page.screenshot(path=str(out / 'fls-matrix-unknown.png'), full_page=True)
        checks.append('A legitimate uploaded fixture distinguishes active 1, explicit 0, unknown ?, and undeclared — without using unknownness as a protection dash or safe conclusion')

        split = deepcopy(fixture)
        for edge in split['edges']:
            if edge['id'] == 'workstation-link':
                edge['layers'] = {'physical': True, 'syntactic': False, 'semantic': True}
        split['edges'].append({'id': 'split-level-backup', 'type': 'interaction',
                               'source': 'analyst:Елена', 'target': 'vault/research', 'bidirectional': True,
                               'layers': {'physical': False, 'syntactic': True, 'semantic': 'UNKNOWN'}})
        split['nodes']['vault/research']['name'] = '\t=1+1'
        split_state = initial_state(await upload(page, {'name': 'separate-channel-levels.json', 'mimeType': 'application/json',
                                                        'buffer': json.dumps(split, ensure_ascii=False).encode()}))
        await page.locator('.sg-view-tabs [data-view=matrices]').click()
        await expect(page.locator('.sg-matrix-note')).to_contain_text('Разные каналы не объединяются в один FLS-канал')
        for layer in LAYERS:
            await matrix_matches(page, split_state, layer)
            cell = page.locator('.sg-matrix td[data-source="analyst:Елена"][data-target="vault/research"]')
            await expect(cell).to_have_attribute('data-value', 'TRUE')
            title = await cell.get_attribute('title')
            assert 'workstation-link' in title and 'split-level-backup' in title
        access = [result for result in split_state['analysis']['results']
                  if result['checker'] == 'forbidden_operation' and result['subject'] == 'analyst:Елена'
                  and result['object'] == 'vault/research' and result['operation'] == 'read']
        assert access and all(result['status'] == 'PASS' for result in access), access
        async with page.expect_download() as pending:
            await page.get_by_role('button', name='CSV всех каналов').click()
        download = await pending.value
        await download.save_as(str(out / 'fls-formula-safe.csv'))
        csv_rows = list(csv.DictReader(io.StringIO((out / 'fls-formula-safe.csv').read_text(encoding='utf-8-sig'))))
        escaped_names = [row[field] for row in csv_rows for field in ('source_name', 'target_name') if '=1+1' in row[field]]
        assert escaped_names and set(escaped_names) == {"'\t=1+1"}, escaped_names
        checks.append('Per-level matrix unions retain separate channel identities: F=1, L=1, S=1 across incompatible channels does not create an actual access path; CSV neutralizes a tab-prefixed formula-like label')

        fresh = initial_state(await upload(page, ROOT / 'examples/portable/fls_clusters.json'))
        await page.locator('.sg-view-tabs [data-view=matrices]').click()
        await page.locator('.sg-matrix-tabs [data-layer=semantic]').click()
        await page.get_by_role('searchbox', name='Фильтр матрицы').fill('База')
        async with page.expect_response(api_response(REPAIR_API), timeout=60000) as pending:
            await page.locator('#repair-button').click()
        response = await pending.value
        assert response.status == 200, await response.text()
        repaired = await response.json()
        fixed = repaired['states']['repaired']
        assert fixed['analysis']['summary'] == {'PASS': 9}
        assert len(repaired['repair']['selected']) == 5
        await expect(page.locator('#repair-button')).to_have_text('Исправления проверены')
        await expect(page.locator('.sg-view-tabs [data-view=matrices]')).to_have_attribute('aria-selected', 'true')
        await expect(page.locator('.sg-matrix-tabs [data-layer=semantic]')).to_have_attribute('aria-selected', 'true')
        await expect(page.get_by_role('searchbox', name='Фильтр матрицы')).to_have_value('База')
        await expect(page.locator('.sg-matrix-phase')).to_contain_text('После исправления')
        await page.get_by_role('searchbox', name='Фильтр матрицы').fill('')
        await matrix_matches(page, fixed, 'semantic')
        request_count = len(requests)
        await page.locator('#before-tab').click()
        await expect(page.locator('.sg-matrix-phase')).to_contain_text('До исправления')
        await matrix_matches(page, fresh, 'semantic')
        await page.locator('#after-tab').click()
        await expect(page.locator('.sg-matrix-phase')).to_contain_text('После исправления')
        assert len(requests) == request_count
        checks.append('Real five-action repair gives nine PASS; matrix view, selected layer and query survive remount, while phase switching preserves state without new requests')

        await page.get_by_role('searchbox', name='Фильтр матрицы').fill('База')
        async with page.expect_download() as pending:
            await page.get_by_role('button', name='CSV всех каналов').click()
        download = await pending.value
        await download.save_as(str(out / 'fls-matrices-after.csv'))
        rows = list(csv.DictReader(io.StringIO((out / 'fls-matrices-after.csv').read_text(encoding='utf-8-sig'))))
        assert len(rows) == 12
        assert {(row['source'], row['target'], row['layer'], row['value']) for row in rows} == {
            (edge['source'], edge['target'], edge['layer'], edge['value']) for edge in fixed['graph']['layer_edges']}
        assert {row['state'] for row in rows} == {'after'}
        await page.get_by_role('searchbox', name='Фильтр матрицы').fill('')
        checks.append('Sparse CSV exports every declared directed layer of the selected phase, including values and protection routes')

        await page.locator('.sg-view-tabs [data-view=all]').click()
        await assert_layer_drawing(after, fixed)
        await expect(after.locator('[data-violator=true]')).to_have_count(0)
        await page.screenshot(path=str(out / 'fls-after.png'), full_page=True)
        await page.set_viewport_size({'width': 390, 'height': 844})
        assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        await page.screenshot(path=str(out / 'fls-mobile.png'), full_page=True)
        await page.locator('.sg-view-tabs [data-view=matrices]').click()
        await matrix_matches(page, fixed, 'physical')
        assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        await page.screenshot(path=str(out / 'fls-matrix-mobile.png'), full_page=True)
        await page.set_viewport_size({'width': 1440, 'height': 1080})
        checks.append('Verified after graph removes the red offender; graph and horizontally scrolling matrices fit a 390px page')

        for format_name, mime in [('json', 'application/json'), ('xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')]:
            response = await page.request.get(base + '/api/graph-example/file/?example=fls&format=' + format_name)
            assert response.status == 200
            payload = await response.body()
            roundtrip = initial_state(await upload(page, {'name': 'roundtrip-fls.' + format_name, 'mimeType': mime, 'buffer': payload}))
            assert signatures(roundtrip) == signatures(snapshot)
            assert roundtrip['analysis']['summary'] == snapshot['analysis']['summary']
            assert {node['key']: node['cluster'] for node in roundtrip['graph']['nodes']} == {node['key']: node['cluster'] for node in snapshot['graph']['nodes']}
            await assert_layer_drawing(before, roundtrip)
        checks.append('Actual downloaded JSON and XLSX preserve clusters, both directions, three levels, protection routes, and analysis when uploaded unchanged')

        legacy = initial_state(await upload(page, ROOT / 'data/sources/graf-svyazey-pk.html'))
        await graph_is_complete(before, legacy)
        assert len(legacy['graph']['nodes']) == 231 and legacy['graph']['summary']['structural_edges'] == 1100
        assert legacy['graph']['layer_edges'] == []
        await expect(before.locator('.sg-layer-edge')).to_have_count(0)
        await expect(page.locator('#system-status')).to_have_attribute('data-state', 'warning')
        await page.locator('.sg-view-tabs [data-view=matrices]').click()
        await expect(page.locator('.sg-matrix td')).to_have_count(900)
        await expect(page.locator('.sg-matrix-note').filter(has_text='Уровни связей не заданы')).to_be_visible()
        assert await page.locator('.sg-matrix td').evaluate_all('(cells)=>cells.every(cell=>cell.dataset.value==="UNDECLARED")')
        await page.get_by_role('button', name='Строки: следующая страница').click()
        await expect(page.locator('.sg-matrix-pagination')).to_contain_text('Строки: 31–60 из 231')
        await expect(page.locator('.sg-matrix td')).to_have_count(900)
        checks.append('Legacy HTML keeps 231 nodes and 1100 gray edges without invented F/L/S; matrices say levels are undeclared and remain bounded to 30×30 cells')
        assert not errors, errors
        await browser.close()

    result = {'status': 'PASS', 'checks': checks, 'javascript_errors': errors}
    (out / 'fls-browser-check.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:8012')
    parser.add_argument('--chrome', default='/usr/bin/google-chrome')
    parser.add_argument('--out', default='results/fls-ui')
    asyncio.run(check(parser.parse_args()))
