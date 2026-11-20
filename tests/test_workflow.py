import json
from pathlib import Path
import pytest

from analyzer.cli import main
from analyzer.engine import analyze, reachability
from analyzer.export import export_matrices
from analyzer.importers import load_html, load_xlsx, compare_sources
from analyzer.profiles import imported_model, apply_profile, comparison_model
from analyzer.model import empty_model, fact

ROOT = Path(__file__).resolve().parents[1]


def test_cli_complete_workflow(tmp_path, capsys):
    assert main(['demo', '--closed-inventory', '--out', str(tmp_path)]) == 0
    bundle = json.loads((tmp_path/'report.json').read_text())
    assert bundle['states']['baseline']['analysis']['summary'] == {'PASS': 12}
    assert bundle['states']['changed']['analysis']['summary'] == {'PASS': 11, 'FAIL': 1}
    assert bundle['states']['experiment']['analysis']['summary'] == {'PASS': 9, 'FAIL': 3}
    assert bundle['states']['repaired']['analysis']['summary'] == {'PASS': 12}
    assert len(bundle['states']['baseline']['graph']['nodes']) == 231
    assert bundle['states']['baseline']['graph']['summary']['structural_edges'] == 1100
    assert bundle['states']['experiment']['graph']['summary']['violators'] == ['2:99']
    assert bundle['states']['repaired']['graph']['summary']['violators'] == []
    assert bundle['repair']['objective_value'] == [4, 4]
    assert bundle['repair']['optimality_proven']
    assert len(bundle['coverage']['rules']) == 324
    assert bundle['coverage']['summary'] == {'UNKNOWN': 324}
    assert bundle['comparison']['mode'] == 'html_baseline_xlsx_changed'
    assert (tmp_path/'baseline_matrices.json').exists()
    assert 'OPTIMAL_REPAIR' in capsys.readouterr().out


def test_missing_inventory_is_unknown_without_explicit_closed_world():
    h = load_html(ROOT/'data/sources/graf-svyazey-pk.html')
    x = load_xlsx(ROOT/'data/sources/Четыре_конфигурации_ПК_уязвим.xlsx')
    base = apply_profile(imported_model(h), ROOT/'examples/demo_profile.json')
    changed = comparison_model(base, x, compare_sources(h, x, as_states=True))
    results = {r['id']: r for r in analyze(changed)['results']}
    assert results['pc1_filtering']['status'] == 'UNKNOWN'
    assert results['pc2_auth']['status'] == 'PASS'
    assert h['nodes']['1:59']['name'] == 'Межсетевой экран'
    assert {f['value'] for f in base['facts'] if f['predicate'] == 'present'} == {'TRUE'}


def test_quantum_profile_does_not_create_active_read_or_write():
    base = imported_model(load_html(ROOT/'data/sources/graf-svyazey-pk.html'))
    quantum = apply_profile(base, ROOT/'examples/quantum_profile.json')
    result = {r['id']: r['status'] for r in analyze(quantum)['results']}
    assert result == {'passive_confidentiality': 'FAIL', 'active_read_not_created': 'FAIL',
                      'write_not_created': 'PASS', 'crypto_document': 'REQUIRES_EVIDENCE'}
    assert reachability(quantum, '2:99', '1:87', 'read')['value'] == 'FALSE'
    assert reachability(quantum, '2:99', '1:87', 'write')['value'] == 'FALSE'


def test_standalone_fixtures_and_matrix_semantics():
    fixture_root = ROOT/'examples/fixtures'
    expected = json.loads((fixture_root/'expected.json').read_text())
    for name, statuses in expected.items():
        model = json.loads((fixture_root/(name+'.json')).read_text())
        report = analyze(model)
        assert not report['model_errors'], report
        assert [r['status'] for r in report['results']] == statuses
    model = apply_profile(imported_model(load_html(ROOT/'data/sources/graf-svyazey-pk.html')), ROOT/'examples/demo_profile.json')
    matrices = export_matrices(model)
    assert matrices['matrix_index_to_node_key'] == sorted(model['nodes'])
    for relation in matrices['operation_and_flow_matrices']:
        for target, value in zip(relation['column_keys'], relation['values'][0]):
            assert value == reachability(model, relation['subject'], target, relation['operation'], relation['scenario'], relation['kind'])['value']
    assert any(m['relation'] == 'allowed' and 'TRUE' in m['values'][0] for m in matrices['policy_matrices'])


def test_policy_matrix_preserves_kind_and_applicability():
    model = empty_model()
    model['nodes'] = {'s': {'types': ['subject']}, 'd': {'types': ['data']}}
    model['facts'] = [fact('present', [k]) for k in model['nodes']]
    model['policy']['allowed'] = [
        {'subject': 's', 'object': 'd', 'operation': 'read', 'kind': 'flow', 'applicable': 'TRUE'},
        {'subject': 's', 'object': 'd', 'operation': 'read', 'kind': 'access', 'applicable': 'UNKNOWN'}]
    allowed = [m for m in export_matrices(model)['policy_matrices'] if m['relation'] == 'allowed']
    assert [m for m in allowed if m['kind'] == 'flow'][0]['values'][0][0] == 'TRUE'
    assert [m for m in allowed if m['kind'] == 'access'][0]['values'][0][0] == 'UNKNOWN'
    assert reachability(model, 's', 'd', 'read', kind='flow')['value'] == 'UNKNOWN'
    model['facts'].append(fact('present', ['d'], 'FALSE'))
    with pytest.raises(ValueError, match='MODEL_ERROR'):
        export_matrices(model)
