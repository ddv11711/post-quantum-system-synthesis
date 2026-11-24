"""The HTTP export path must retain source-comparison evidence for restored edges.

run_scenario() strips source_graph and comparison from the individual display
states. The full comparison remains in report['comparison'] and is required to
restore the administrator -> firewall edge from the historical HTML baseline.
"""
from hashlib import sha256

import pytest

from core import export_views


def test_declared_export_passes_verified_historical_comparison(monkeypatch, tmp_path):
    source = tmp_path / 'source.xlsx'
    source.write_bytes(b'synthetic excel contents for provenance test')
    comparison = {
        'mode': 'html_baseline_xlsx_changed',
        'sources': {'xlsx': {'sha256': sha256(source.read_bytes()).hexdigest()}},
        'missing_in_xlsx': ['1:59'],
        'only_html_edges': [['g:2', '1:59']],
        'assumptions': [{'id': 'xlsx_complete_inventory', 'value': True}],
    }
    report = {
        'repair': {'status': 'OPTIMAL_REPAIR'},
        'comparison': comparison,
        'states': {
            'experiment': {'model': {'state': 'experiment'}},
            'repaired': {'model': {'state': 'repaired'}},
        },
    }
    monkeypatch.setattr(export_views, 'run_scenario', lambda *a, **kw: {'report': report})
    observed = {}

    def fake_export(source_path, before, after, *, description):
        observed['comparison'] = before.get('comparison')
        observed['before_state'] = before.get('state')
        observed['after_state'] = after.get('state')
        return b'x', {'mode': 'verified_roundtrip'}

    monkeypatch.setattr(export_views, 'export_verified_model_workbook', fake_export)
    data, info = export_views._export_declared_scenario(
        source, tmp_path, {'scenario': 'experiment', 'closed_inventory': True})
    assert data == b'x'
    assert info['mode'] == 'verified_roundtrip'
    assert observed == {'comparison': comparison, 'before_state': 'experiment', 'after_state': 'repaired'}


def test_declared_export_rejects_mismatched_source(monkeypatch, tmp_path):
    source = tmp_path / 'source.xlsx'
    source.write_bytes(b'new file')
    report = {
        'repair': {'status': 'OPTIMAL_REPAIR'},
        'comparison': {
            'mode': 'html_baseline_xlsx_changed',
            'sources': {'xlsx': {'sha256': sha256(b'other file').hexdigest()}},
        },
        'states': {'experiment': {'model': {}}, 'repaired': {'model': {}}},
    }
    monkeypatch.setattr(export_views, 'run_scenario', lambda *a, **kw: {'report': report})
    with pytest.raises(ValueError, match='не совпадает'):
        export_views._export_declared_scenario(
            source, tmp_path, {'scenario': 'experiment', 'closed_inventory': True})
