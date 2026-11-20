"""Small standalone teaching models for semantics absent from source files."""
import json
from pathlib import Path

from analyzer.model import empty_model, fact

OUT = Path(__file__).resolve().parent/'fixtures'


def model(name, types):
    m = empty_model(name, 'isolated_test_fixture')
    m['nodes'] = {k: {'types': v, 'name': k} for k, v in types.items()}
    m['assumptions'] = [{'kind': 'demo_assumption', 'description': 'Изолированная фикстура; не описание реального пользовательского ПК.'}]
    m['completeness'] = [{'predicate': 'dependencies', 'args_prefix': [], 'complete': True}]
    for node in types:
        for pred in ('present', 'enabled', 'healthy'):
            put(m, pred, [node], 'TRUE')
    return m


def put(m, pred, args, value):
    m['facts'] = [f for f in m['facts'] if (f['predicate'], f['args']) != (pred, args)]
    m['facts'].append(fact(pred, args, value, [{'kind': 'demo_assumption', 'file': f'examples/fixtures/{m["state"]}.json',
                                             'state': m['state'], 'raw_value': value, 'transformation': 'explicit isolated fixture'}]))


def build():
    fixtures = []
    m = model('dependency_cycle', {'a': ['component'], 'b': ['component']})
    m['dependencies'] = {'a': {'all': ['b']}, 'b': {'all': ['a']}}
    m['requirements'] = [{'id': 'cycle_has_no_ground', 'checker': 'required_function', 'object': 'a'}]
    fixtures.append((m, ['UNKNOWN']))
    m = model('keyed_backup', {'data': ['data'], 'copy': ['data', 'component'], 'key': ['key']})
    for pred, args, value in [('backup', ['data', 'copy'], 'TRUE'), ('readable', ['copy'], 'TRUE'),
                               ('key_required', ['copy', 'key'], 'TRUE'), ('key_accessible', ['key'], 'FALSE')]:
        put(m, pred, args, value)
    m['completeness'] += [{'predicate': pred, 'args_prefix': args, 'complete': True}
                          for pred, args in [('backup', ['data']), ('key_required', ['copy'])]]
    m['requirements'] = [{'id': 'key_missing', 'checker': 'recovery', 'object': 'data'}]
    fixtures.append((m, ['FAIL']))
    m = model('common_dependency', {k: ['component'] for k in ['service', 'replica_a', 'replica_b', 'power']})
    m['dependencies'] = {'replica_a': {'all': ['power']}, 'replica_b': {'all': ['power']}}
    m['requirements'] = [{'id': 'common_power', 'checker': 'redundancy', 'object': 'service',
                           'replicas': ['replica_a', 'replica_b'], 'replicas_complete': True}]
    fixtures.append((m, ['FAIL']))
    m = model('configuration_and_duties', {'os': ['component'], 'admin': ['subject'], 'approver': ['role'],
                                         'operator': ['role'], 'change': ['change'], 'link': ['channel']})
    for pred, args, value in [('trusted_boot', ['os'], 'FALSE'), ('integrity', ['os'], 'FALSE'),
                               ('has_role', ['admin', 'approver'], 'TRUE'), ('has_role', ['admin', 'operator'], 'TRUE'),
                               ('changed', ['change'], 'TRUE'), ('approved', ['change'], 'FALSE'),
                               ('crypto_protected', ['link'], 'FALSE')]:
        put(m, pred, args, value)
    m['requirements'] = [
        {'id': 'boot', 'checker': 'configuration', 'object': 'os', 'predicate': 'trusted_boot'},
        {'id': 'integrity', 'checker': 'configuration', 'object': 'os', 'predicate': 'integrity'},
        {'id': 'duties', 'checker': 'incompatible_roles', 'object': 'admin', 'subject': 'admin', 'roles': ['approver', 'operator']},
        {'id': 'change', 'checker': 'authorized_change', 'object': 'change'},
        {'id': 'crypto', 'checker': 'crypto', 'object': 'link'},
        {'id': 'certificate', 'checker': 'evidence', 'object': 'os'},
        {'id': 'unsupported', 'checker': 'hypothetical_unimplemented', 'object': 'os'}]
    fixtures.append((m, ['FAIL']*5+['REQUIRES_EVIDENCE', 'NOT_CHECKED']))
    OUT.mkdir(parents=True, exist_ok=True)
    expected = {}
    for m, statuses in fixtures:
        for collection in ('completeness', 'requirements'):
            for i, record in enumerate(m[collection]):
                record['provenance'] = [{'file': f'examples/fixtures/{m["state"]}.json', 'json_key': f'{collection}[{i}]',
                                        'state': m['state'], 'kind': 'demo_assumption', 'raw_value': record.get('id', record.get('complete')),
                                        'transformation': 'explicit isolated fixture declaration'}]
        m['dependency_provenance'] = {key: [{'file': f'examples/fixtures/{m["state"]}.json', 'json_key': f'dependencies.{key}',
            'state': m['state'], 'kind': 'demo_assumption', 'raw_value': expression,
            'transformation': 'explicit isolated dependency equation'}] for key, expression in m['dependencies'].items()}
        expected[m['state']] = statuses
        (OUT/(m['state']+'.json')).write_text(json.dumps(m, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (OUT/'expected.json').write_text(json.dumps(expected, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    build()
