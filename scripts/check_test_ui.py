"""Browser QA for the single-scenario security graph; optional Playwright."""
import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright, expect


API_PATH = '/api/scenario/'
POSITIONS = '(nodes) => Object.fromEntries(nodes.map(n => [n.dataset.nodeKey, n.getAttribute("transform")]))'


def scenario_response(response):
    return urlparse(response.url).path == API_PATH and response.request.method == 'POST'


async def graph_is_complete(pane):
    await expect(pane).to_be_visible()
    await expect(pane.locator('.sg-node')).to_have_count(231)
    await expect(pane.locator('[data-edge-kind="structural"]')).to_have_count(1088)


async def check(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    base_url = args.url.rstrip('/')
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            executable_path=args.chrome, headless=True, args=['--no-sandbox'])
        context = await browser.new_context(
            viewport={'width': 1440, 'height': 1080}, reduced_motion='reduce')
        page = await context.new_page()
        page.set_default_timeout(30000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        requests = []
        page.on('request', lambda request: requests.append(request.post_data_json)
                if urlparse(request.url).path == API_PATH and request.method == 'POST' else None)

        async with page.expect_response(scenario_response) as pending:
            await page.goto(base_url + '/')
        response = await pending.value
        assert response.status == 200
        original = await response.json()
        assert requests == [{'repair': False}], requests
        assert original['scenario']['closed_inventory'] is True
        assert original['states']['before']['analysis']['summary'] == {'PASS': 9, 'FAIL': 3}
        assert 'repaired' not in original['states']
        before = page.locator('#security-graph section.sg-pane[data-graph-phase="before"]')
        after = page.locator('#security-graph section.sg-pane[data-graph-phase="after"]')
        repair = page.locator('#repair-button')
        await graph_is_complete(before)
        await expect(after).to_have_count(0)
        await expect(page.locator('#after-tab')).to_be_disabled()
        await expect(repair).to_be_enabled()
        await expect(repair).to_have_text('Исправить уязвимости')
        await expect(page.locator('#findings-list > .finding-card')).to_have_count(3)
        await expect(page.locator('#node-count')).to_contain_text('231')
        assert ''.join((await page.locator('#edge-count').inner_text()).split()) == '1088'
        await expect(page.locator('#check-count')).to_have_text('9 из 12 проверок пройдено')
        offender = before.locator('[data-node-key="2:99"]')
        await expect(offender).to_have_attribute('data-violator', 'true')
        assert await offender.locator('.sg-node-shape').evaluate(
            '(node) => getComputedStyle(node).fill') == 'rgb(213, 45, 66)'
        await expect(before.locator('[data-violator="true"]')).to_have_count(1)
        await expect(before.locator('.sg-risk-path')).to_have_count(2)
        await expect(before.locator('[data-node-key="1:59"]')).to_have_attribute('data-present', 'FALSE')
        original_positions = await before.locator('.sg-node').evaluate_all(POSITIONS)
        await expect(page.locator('pre:visible, input[type="file"], input[type="checkbox"], select, .scenario-card')).to_have_count(0)
        await page.screenshot(path=str(out / 'before-repair.png'), full_page=True)
        checks.append('Automatic complete scenario: 231 nodes, 1088 source links, 3 findings; only confirmed user 2:99 is red')

        async def repair_failure(route):
            if route.request.post_data_json == {'repair': True}:
                await route.fulfill(status=503, content_type='application/json',
                                    body=json.dumps({'error': 'Проверочная ошибка исправления'}, ensure_ascii=False))
            else:
                await route.continue_()

        await page.route('**' + API_PATH, repair_failure)
        async with page.expect_response(scenario_response) as pending:
            await repair.click()
        assert (await pending.value).status == 503
        await expect(page.locator('#page-feedback')).to_have_text('Проверочная ошибка исправления')
        await expect(page.locator('#page-feedback')).to_be_visible()
        await expect(repair).to_be_enabled()
        await graph_is_complete(before)
        await expect(offender).to_have_attribute('data-violator', 'true')
        await expect(after).to_have_count(0)
        await expect(page.locator('#after-tab')).to_be_disabled()
        await page.unroute('**' + API_PATH, repair_failure)
        checks.append('Failed repair retains the real vulnerable graph and allows retry; no fabricated after state')

        intercepted, release = asyncio.Event(), asyncio.Event()
        repair_requests = []

        async def delayed_repair(route):
            if route.request.post_data_json == {'repair': True}:
                repair_requests.append(route.request.url)
                intercepted.set()
                await release.wait()
            await route.continue_()

        await page.route('**' + API_PATH, delayed_repair)
        async with page.expect_response(scenario_response, timeout=60000) as pending:
            await repair.click()
            try:
                await asyncio.wait_for(intercepted.wait(), timeout=10)
                await expect(repair).to_be_disabled()
                # A second delivered event must also respect the in-flight guard.
                await repair.evaluate('(button) => button.dispatchEvent(new MouseEvent("click", {bubbles: true}))')
                await graph_is_complete(before)
                await expect(after).to_have_count(0)
            finally:
                release.set()
        response = await pending.value
        assert response.status == 200
        repaired = await response.json()
        await graph_is_complete(after)
        await expect(before).to_be_hidden()
        assert len(repair_requests) == 1, repair_requests
        await page.unroute('**' + API_PATH, delayed_repair)
        assert repaired['repair']['status'] in {'OPTIMAL_REPAIR', 'VERIFIED_CANDIDATE'}
        assert set(repaired['repair']['selected']) == {
            'close_application_acl', 'close_vpn_acl', 'enable_logger', 'restore_filter'}
        assert repaired['states']['repaired']['analysis']['summary'] == {'PASS': 12}
        await expect(after.locator('[data-violator="true"]')).to_have_count(0)
        await expect(after.locator('[data-node-key="2:99"]')).to_have_attribute('data-fixed', 'true')
        await expect(after.locator('.sg-blocked-path')).to_have_count(2)
        await expect(after.locator('[data-node-key="1:59"]')).to_have_attribute('data-present', 'TRUE')
        assert await after.locator('.sg-node').evaluate_all(POSITIONS) == original_positions
        await expect(repair).to_be_disabled()
        await expect(repair).to_have_text('Уязвимости устранены')
        await expect(page.locator('#after-tab')).to_be_enabled()
        await expect(page.locator('#check-count')).to_have_text('12 из 12 проверок пройдено')
        await expect(page.locator('#findings-list > .finding-card.is-fixed')).to_have_count(3)
        await expect(page.locator('#page-feedback')).to_be_hidden()
        await page.screenshot(path=str(out / 'after-repair.png'), full_page=True)
        checks.append('One repair request applies four actions; 12 requirements pass, both paths close, firewall returns, positions remain stable')

        request_count = len(requests)
        await page.locator('#before-tab').click()
        await graph_is_complete(before)
        await expect(after).to_be_hidden()
        await expect(before.locator('[data-violator="true"]')).to_have_count(1)
        await expect(page.locator('#findings-list > .finding-card')).to_have_count(3)
        await expect(page.locator('#findings-list > .finding-card.is-fixed')).to_have_count(0)
        await page.locator('#after-tab').click()
        await graph_is_complete(after)
        await expect(before).to_be_hidden()
        assert len(requests) == request_count, requests
        assert urlparse(page.url).path == '/'
        checks.append('Before/after tabs show one graph at a time, preserve history and make no additional requests')

        await page.set_viewport_size({'width': 390, 'height': 844})
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile page overflows horizontally'
        await graph_is_complete(after)
        await expect(page.locator('#before-tab')).to_be_visible()
        await expect(page.locator('#after-tab')).to_be_visible()
        await page.screenshot(path=str(out / 'mobile.png'), full_page=True)
        checks.append('Mobile layout retains the full graph and phase controls without horizontal page overflow')

        retry_page = await context.new_page()
        retry_page.set_default_timeout(30000)
        retry_page.on('pageerror', lambda error: errors.append(str(error)))

        async def initial_failure(route):
            await route.abort('failed')

        await retry_page.route('**' + API_PATH, initial_failure)
        await retry_page.goto(base_url + '/tests/')
        await expect(retry_page.locator('#retry-button')).to_be_visible()
        await expect(retry_page.locator('#repair-button')).to_be_disabled()
        await expect(retry_page.locator('#security-graph .sg-node')).to_have_count(0)
        assert urlparse(retry_page.url).path == '/', retry_page.url
        await retry_page.unroute('**' + API_PATH, initial_failure)
        async with retry_page.expect_response(scenario_response) as pending:
            await retry_page.locator('#retry-button').click()
        assert (await pending.value).status == 200
        await graph_is_complete(retry_page.locator('#security-graph section.sg-pane[data-graph-phase="before"]'))
        await expect(retry_page.locator('#retry-button')).to_be_hidden()
        await expect(retry_page.locator('#repair-button')).to_be_enabled()
        checks.append('Legacy /tests/ redirects to /; initial network failure has a working retry and no invented graph')
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
