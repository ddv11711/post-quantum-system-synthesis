"""Regression: a restored node has traceable topology, not an isolated green row."""
import json
from pathlib import Path

from analyzer.engine import analyze
from analyzer.importers import compare_sources, load_html, load_xlsx
from analyzer.profiles import apply_profile, comparison_model, imported_model
from analyzer.security_workbook import read_security_extension
from analyzer.transitions import apply_actions
from analyzer.xlsx_repair_export import (
    _declared_restoration_edges,
    export_verified_model_workbook,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'data' / 'sources' / 'Шаблон №1'


def _scenario():
    html = load_html(SOURCES / 'graf-svyazey-pk.html')
    source = next(SOURCES.glob('*.xlsx'))
    original = load_xlsx(source)
    baseline = apply_profile(imported_model(html), ROOT / 'examples' / 'demo_profile.json')
    comparison = compare_sources(html, original, True, as_states=True)
    before = comparison_model(baseline, original, comparison)
    experiment = json.loads((ROOT / 'examples' / 'experiment_actions.json').read_text(encoding='utf-8'))
    before = apply_actions(before, experiment['actions'], new_state='declared_experiment')
    catalog = {action['id']: action for action in before['action_catalog']}
    actions = ('restore_filter', 'enable_logger', 'close_application_acl', 'close_vpn_acl')
    repaired = apply_actions(before, [catalog[name] for name in actions], new_state='repaired')
    return html, source, original, before, repaired


def test_4pc_restored_firewall_has_source_verified_connections(tmp_path):
    baseline, source, original, before, repaired = _scenario()
    payload, counts = export_verified_model_workbook(source, before, repaired)
    output = tmp_path / 'repaired.xlsx'
    output.write_bytes(payload)
    graph = load_xlsx(output)
    expected = {(edge['source'], edge['target']) for edge in baseline['edges']
                if '1:59' in (edge['source'], edge['target'])}
    actual = {(edge['source'], edge['target']) for edge in graph['edges']
              if '1:59' in (edge['source'], edge['target'])}
    assert len(expected) == 9
    assert actual == expected
    assert len(graph['nodes']) == len(original['nodes']) + 1
    assert len(graph['edges']) == len(original['edges']) + 9
    assert counts['added_rows'] == 1
    assert counts['restored_edges'] == 9
    assert counts['cells'] == 2
    model = read_security_extension(output, imported_graph=graph)
    assert analyze(model)['summary'] == {'PASS': 12}


def test_restoration_does_not_invent_unrecorded_topology():
    _, _, graph, before, repaired = _scenario()
    active = set(graph['nodes']) | {'1:59'}
    assert _declared_restoration_edges(dict(before, comparison={}), repaired, '1:59', active) == set()
    incomplete = dict(before, comparison={**before['comparison'], 'assumptions': []})
    assert _declared_restoration_edges(incomplete, repaired, '1:59', active) == set()
