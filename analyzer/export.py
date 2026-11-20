"""Stable-index matrices and readable reports, without a security score."""
from collections import Counter, defaultdict, deque
import json
from pathlib import Path

from .engine import Engine
from .model import FactBase, validate_model


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def export_matrices(model):
    errors = validate_model(model)
    if errors:
        raise ValueError('MODEL_ERROR: '+str(errors))
    keys = sorted(model['nodes'])
    index = {key: i for i, key in enumerate(keys)}
    base = FactBase(model)
    present = {k: base.boolean('present', [k]) for k in keys}
    adjacency = defaultdict(set)
    for edge in model.get('source_graph', model.get('raw_graph', {})).get('edges', []):
        a, b = (edge['source'], edge['target']) if isinstance(edge, dict) else edge
        if a in index and b in index and present[a] != 'FALSE' and present[b] != 'FALSE':
            adjacency[a].add(b)
    structural = []
    for source in keys:
        seen, queue = set(), deque(adjacency[source])
        while queue:
            target = queue.popleft()
            if target in seen:
                continue
            seen.add(target)
            queue.extend(adjacency[target] - seen)
        structural.append([int(k in seen) for k in keys])
    contexts = {(t['subject'], t['operation'], t.get('scenario', 'default'), t.get('kind', 'access'))
                for t in model.get('transitions', [])}
    contexts |= {(r['subject'], r['operation'], r.get('scenario', 'default'), r.get('kind', 'access'))
                 for r in model.get('requirements', []) if r.get('checker') in {'forbidden_operation', 'required_operation'}}
    allowed = model.get('policy', {}).get('allowed', [])
    contexts |= {(r['subject'], r['operation'], r.get('scenario', 'default'), r.get('kind', 'access')) for r in allowed}
    engine = Engine(model)
    semantic = []
    for subject, operation, scenario, kind in sorted(contexts):
        values = []
        for target in keys:
            engine.facts.reset_trace(); engine.derivations = []
            values.append(engine.reachability(subject, target, operation, scenario, kind)['value'])
        semantic.append({'subject': subject, 'operation': operation, 'scenario': scenario, 'kind': kind,
                         'row_keys': [subject], 'column_keys': keys,
                         'values': [values], 'must': [[int(v == 'TRUE') for v in values]],
                         'may': [[int(v != 'FALSE') for v in values]],
                         'scope_complete': base.complete('transitions', [subject, operation, scenario, kind])})
    policy = []
    for subject, operation, scenario, kind in sorted(contexts):
        requirements = [r for r in model.get('requirements', []) if
                        (r.get('subject'), r.get('operation'), r.get('scenario', 'default'), r.get('kind', 'access')) ==
                        (subject, operation, scenario, kind)]
        for checker, relation in [('forbidden_operation', 'forbidden'), ('required_operation', 'required'), ('allowed_operation', 'allowed')]:
            objects = {r['object'] for r in requirements if r['checker'] == checker and r.get('applicable', 'TRUE') == 'TRUE'}
            if relation == 'allowed':
                objects |= {r['object'] for r in allowed if r.get('applicable', 'TRUE') == 'TRUE' and
                            (r['subject'], r['operation'], r.get('scenario', 'default'), r.get('kind', 'access')) == (subject, operation, scenario, kind)}
            policy.append({'subject': subject, 'operation': operation, 'scenario': scenario, 'kind': kind, 'relation': relation,
                           'row_keys': [subject], 'column_keys': keys,
                           'values': [['TRUE' if k in objects else 'UNKNOWN' for k in keys]]})
    return {'state': model['state'], 'node_key_to_matrix_index': index, 'matrix_index_to_node_key': keys,
            'structural_observed_reachability': structural,
            'structural_semantics': 'positive-length paths in observed raw graph; zeros are not proofs of real-world disconnection or access denial',
            'operation_and_flow_matrices': semantic, 'policy_matrices': policy,
            'note': 'must=1 proves an explicit operation; may=1 includes UNKNOWN; raw topology grants no operations'}


def text_report(bundle):
    lines = ['Логический анализ компонентной системы', '']
    comparison = bundle.get('comparison', {})
    if comparison:
        lines += [f"Режим сравнения: {comparison.get('mode')}",
                  f"Нет строк в XLSX: {', '.join(comparison.get('missing_in_xlsx', []))}",
                  f"Совпадающих рёбер: {comparison.get('common_edges_count')}",
                  f"Неоднозначных деклараций: {len(comparison.get('ambiguous_references', []))}", '']
    for name, state in bundle.get('states', {}).items():
        analysis = state['analysis']
        lines += [f"{name}: {analysis['state']} / {analysis['profile']}", f"  Статусы: {analysis['summary']}"]
        for result in analysis['results']:
            lines.append(f"  {result['status']:18} {result['id']} [{result.get('object')}] {result.get('name', result['id'])}: {result['reason']}")
            if result.get('witness'):
                lines.append('    Путь: ' + ' → '.join(result['witness'].get('nodes', [])))
            if result.get('cause_components'):
                lines.append('    Причина: ' + ', '.join(result['cause_components']))
        lines.append('')
    repair = bundle.get('repair', {})
    if repair:
        lines += [f"Поиск: {repair['status']}; проверено наборов: {repair['checked_sets']}",
                  f"Выбрано: {', '.join(repair.get('selected', []))}",
                  f"Цель [число действий, стоимость]: {repair.get('objective_value')}",
                  f"Оптимальность в объявленном каталоге доказана: {repair['optimality_proven']}", '']
    coverage = bundle.get('coverage', {})
    if coverage:
        entries = coverage.get('rules', coverage.get('entries', []))
        lines += [f"Покрытие каталога: {coverage.get('summary', {})}",
                  'Проверка фрагмента локального профиля не удостоверяет выполнение всего нормативного пункта.', '']
    lines.append('Явные допущения:')
    for assumption in bundle.get('assumptions', []):
        lines.append('  '+json.dumps(assumption, ensure_ascii=False))
    lines += ['', 'Полные исходные свидетельства, неизвестные условия, деревья вывода, действия и diff находятся в JSON.']
    return '\n'.join(lines)+'\n'
