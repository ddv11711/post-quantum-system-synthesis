"""Real landing-file transfer: native multipart POST, no implicit demo fallback.

The bundled XLSX is a byte-identical copy of the supplied four-PC inventory.
Use --xlsx to exercise the original attachment path instead.
"""
import argparse
import asyncio
from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import urlparse

from playwright.async_api import async_playwright, expect

from check_test_ui import ROOT, EXAMPLE_API, UPLOAD_API, api_response, initial_state, graph_is_complete, graph_summary_matches, upload


async def new_page(context, errors):
    page = await context.new_page()
    page.set_default_timeout(30000)
    # File-transfer assertions use the normal system-font fallback, independent
    # of Google Fonts availability. Local pages, scripts and APIs remain real.
    await page.route(re.compile(r'https://fonts\.(?:googleapis|gstatic)\.com/'), lambda route: route.abort())
    page.on('pageerror', lambda error: errors.append(str(error)))
    requests = []
    page.on('request', lambda request: requests.append({
        'method': request.method, 'path': urlparse(request.url).path,
        'content_type': request.headers.get('content-type', '')})
        if urlparse(request.url).path in {'/analysis/', EXAMPLE_API, UPLOAD_API} else None)
    return page, requests


async def submit_file(page, file, *, status=200):
    await page.locator('#model-file').set_input_files(file)
    name = file['name'] if isinstance(file, dict) else Path(file).name
    await expect(page.locator('#file-hint')).to_have_text(name)
    async with page.expect_response(api_response('/analysis/')) as pending:
        await page.locator('#choose-template').click()
    response = await pending.value
    assert response.status == status, await response.text()
    assert 'multipart/form-data' in response.request.headers['content-type']
    await page.wait_for_url('**/analysis/')
    return response


def no_demo(requests):
    assert not [request for request in requests if request['path'] == EXAMPLE_API], requests


async def inventory_loaded(page, requests, filename):
    await expect(page.locator('#initial-report')).to_have_count(1)
    report = json.loads(await page.locator('#initial-report').text_content())
    snapshot = initial_state(report)
    assert report['filename'] == filename
    assert len(snapshot['graph']['nodes']) == 229
    assert snapshot['graph']['summary']['structural_edges'] == 1088
    assert snapshot['graph'].get('layer_edges', []) == []
    assert all(result.get('checker') == 'semantic_readiness' and result['status'] == 'UNKNOWN'
               for result in snapshot['analysis']['results'])
    assert all(requirement.get('checker') == 'semantic_readiness' for requirement in snapshot['model']['requirements'])
    assert not {'1:59', '2:90'} & {node['key'] for node in snapshot['graph']['nodes']}
    clusters = Counter(re.sub(r'\s+', '', node.get('cluster') or node.get('pc') or 'shared')
                       for node in snapshot['graph']['nodes'])
    assert clusters == {'ПК1': 52, 'ПК2': 56, 'ПК3': 59, 'ПК4': 56, 'shared': 6}, clusters
    await graph_is_complete(page.locator('.sg-pane[data-graph-phase=before]'), snapshot)
    await graph_summary_matches(page, snapshot)
    await expect(page.locator('#file-name')).to_have_text(filename)
    await expect(page.locator('#model-name')).to_have_text(filename)
    await expect(page.locator('#page-feedback')).to_be_hidden()
    await expect(page.locator('#system-status')).to_have_attribute('data-state', 'warning')
    await expect(page.locator('#status-title')).to_have_text('Проверка безопасности не выполнена')
    await expect(page.locator('#repair-button')).to_be_disabled()
    await expect(page.locator('.sg-view-tabs [data-view^="cluster:"]')).to_have_count(5)
    assert 'Елена' not in await page.locator('body').inner_text()
    no_demo(requests)
    assert [request['path'] for request in requests if request['method'] == 'POST'] == ['/analysis/'], requests
    return snapshot


async def check(args):
    source = Path(args.xlsx)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = args.url.rstrip('/')
    checks, errors = [], []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(executable_path=args.chrome, headless=True, args=['--no-sandbox'])
        context = await browser.new_context(viewport={'width': 1440, 'height': 1080}, reduced_motion='reduce')

        empty, empty_requests = await new_page(context, errors)
        await empty.goto(base + '/')
        await expect(empty.locator('#model-file')).to_have_attribute('name', 'file')
        assert await empty.locator('#model-file').evaluate('(input) => input.required')
        await empty.locator('#choose-template').click()
        await expect(empty.locator('#templates-screen')).to_have_class(re.compile(r'\bis-active\b'))
        assert urlparse(empty.url).path == '/'
        assert empty_requests == [], empty_requests
        await empty.goto(base + '/analysis/')
        assert not [request for request in empty_requests if request['method'] == 'POST'], empty_requests
        async with empty.expect_response(api_response(EXAMPLE_API)) as pending:
            await empty.locator('#example-button').click()
        response = await pending.value
        assert response.status == 200
        demo = initial_state(await response.json())
        await graph_is_complete(empty.locator('.sg-pane[data-graph-phase=before]'), demo)
        assert len(demo['graph']['nodes']) == 6
        checks.append('Submitting without a file opens template selection without analysis; the analyzer example runs only after explicitly pressing its example button')
        await empty.close()

        page, requests = await new_page(context, errors)
        await page.goto(base + '/')
        await submit_file(page, source)
        await inventory_loaded(page, requests, source.name)
        await page.screenshot(path=str(out / 'xlsx-from-landing.png'), full_page=True)
        checks.append('The supplied XLSX is posted from the landing form and renders 229 real nodes, 1088 edges, four PCs and shared resources; no example API call or Elena')

        replacement = initial_state(await upload(page, ROOT / 'examples/portable/structural_only.json'))
        await graph_is_complete(page.locator('.sg-pane[data-graph-phase=before]'), replacement)
        assert {node['key'] for node in replacement['graph']['nodes']} == {'sensor-A', 'board/Б'}
        assert replacement['analysis']['summary'].get('UNKNOWN', 0) > 0
        await expect(page.locator('#system-status')).to_have_attribute('data-state', 'warning')
        no_demo(requests)
        assert [request['path'] for request in requests if request['method'] == 'POST'] == ['/analysis/', UPLOAD_API], requests
        checks.append('The analyzer can replace the server-bootstrapped Excel with a newly selected JSON graph through the existing upload API')
        await page.close()

        dropped, drop_requests = await new_page(context, errors)
        await dropped.goto(base + '/')
        drop_name = 'перетаскивание-' + source.name
        transfer = await dropped.evaluate_handle('''payload => {
            const data = new DataTransfer();
            data.items.add(new File([new Uint8Array(payload.bytes)], payload.name,
                {type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}));
            return data;
        }''', {'name': drop_name, 'bytes': list(source.read_bytes())})
        await dropped.dispatch_event('#upload-target', 'dragover', {'dataTransfer': transfer})
        await dropped.dispatch_event('#upload-target', 'drop', {'dataTransfer': transfer})
        await transfer.dispose()
        await expect(dropped.locator('#file-hint')).to_have_text(drop_name)
        assert await dropped.locator('#model-file').evaluate('(input) => input.files.length') == 1
        async with dropped.expect_response(api_response('/analysis/')) as pending:
            await dropped.locator('#choose-template').click()
        assert (await pending.value).status == 200
        await dropped.wait_for_url('**/analysis/')
        await inventory_loaded(dropped, drop_requests, drop_name)
        checks.append('Dropping the real Excel bytes onto the landing target fills the submitted file input and preserves the actual uploaded filename and inventory')
        await dropped.close()

        invalid, invalid_requests = await new_page(context, errors)
        await invalid.goto(base + '/')
        await submit_file(invalid, {'name': 'broken-model.json', 'mimeType': 'application/json', 'buffer': b'{broken'}, status=400)
        await expect(invalid.locator('#initial-error')).to_have_count(1)
        assert json.loads(await invalid.locator('#initial-error').text_content())
        await expect(invalid.locator('#initial-report')).to_have_count(0)
        await expect(invalid.locator('#page-feedback')).to_be_visible()
        assert (await invalid.locator('#page-feedback').inner_text()).strip()
        await expect(invalid.locator('#security-graph .sg-node')).to_have_count(0)
        await expect(invalid.locator('#repair-button')).to_be_disabled()
        assert 'Елена' not in await invalid.locator('body').inner_text()
        no_demo(invalid_requests)
        await invalid.screenshot(path=str(out / 'invalid-file.png'), full_page=True)
        checks.append('An invalid landing upload returns HTTP400, renders the real error, and does not silently replace the failed file with the demo')

        await expect(invalid.locator('#retry-button')).to_have_text('Выбрать файл')
        async with invalid.expect_response(api_response(UPLOAD_API)) as pending:
            async with invalid.expect_file_chooser() as chooser_pending:
                await invalid.locator('#retry-button').click()
            chooser = await chooser_pending.value
            await chooser.set_files(ROOT / 'examples/portable/structural_only.json')
        response = await pending.value
        assert response.status == 200
        recovery = initial_state(await response.json())
        await graph_is_complete(invalid.locator('.sg-pane[data-graph-phase=before]'), recovery)
        await graph_summary_matches(invalid, recovery)
        await expect(invalid.locator('#page-feedback')).to_be_hidden()
        no_demo(invalid_requests)
        checks.append('After the landing upload error, the retry button opens a real file chooser and a valid replacement recovers without an example request')
        await invalid.close()

        no_js_context = await browser.new_context(java_script_enabled=False)
        no_js, no_js_requests = await new_page(no_js_context, errors)
        await no_js.goto(base + '/')
        await no_js.locator('#model-file').set_input_files(source)
        async with no_js.expect_response(api_response('/analysis/')) as pending:
            await no_js.locator('#choose-template').click()
        response = await pending.value
        assert response.status == 200
        assert 'multipart/form-data' in response.request.headers['content-type']
        await no_js.wait_for_url('**/analysis/')
        embedded = json.loads(await no_js.locator('#initial-report').text_content())
        embedded_state = initial_state(embedded)
        assert embedded['filename'] == source.name
        assert len(embedded_state['graph']['nodes']) == 229
        assert embedded_state['graph']['summary']['structural_edges'] == 1088
        no_demo(no_js_requests)
        checks.append('With JavaScript disabled, the native form still posts the actual Excel and receives its verified server-built report; graph rendering itself requires JavaScript')
        await no_js_context.close()
        assert not errors, errors
        await browser.close()

    result = {'status': 'PASS', 'checks': checks, 'javascript_errors': errors, 'xlsx_filename': source.name}
    (out / 'landing-upload-check.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:8012')
    parser.add_argument('--chrome', default='/usr/bin/google-chrome')
    parser.add_argument('--out', default='results/landing-upload')
    parser.add_argument('--xlsx', default=str(ROOT / 'data/sources/Четыре_конфигурации_ПК_уязвим.xlsx'))
    asyncio.run(check(parser.parse_args()))
