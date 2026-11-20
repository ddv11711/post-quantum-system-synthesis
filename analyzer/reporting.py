"""Describe the actual scope of a check without claiming universal security."""
from collections import Counter

FAMILIES = {
    'access': ('Права доступа', {'forbidden_operation', 'required_operation', 'policy_access'}),
    'mandatory': ('Мандатный доступ', {'mandatory_access', 'clearance'}),
    'labels': ('Перенос меток', {'label_flow'}),
    'availability': ('Работоспособность', {'required_function'}),
    'protection': ('Защитные механизмы', {'protection', 'authentication'}),
    'logging': ('Регистрация событий', {'logging'}),
    'recovery': ('Резервирование и восстановление', {'redundancy', 'recovery'}),
    'configuration': ('Конфигурация и известные уязвимости', {'configuration'}),
    'roles': ('Полномочия и изменения', {'incompatible_roles', 'authorized_change'}),
    'crypto': ('Защита каналов', {'crypto', 'quantum'}),
    'evidence': ('Внешние свидетельства', {'evidence'}),
}


def analysis_scope(model, analysis):
    results = analysis.get('results', [])
    counts = Counter(result['status'] for result in results)
    incomplete = sum(counts[key] for key in ('UNKNOWN', 'NOT_CHECKED', 'REQUIRES_EVIDENCE'))
    errors = analysis.get('model_errors', [])
    families = []
    for key, (name, checkers) in FAMILIES.items():
        selected = [r for r in results if r.get('checker') in checkers]
        families.append({'id': key, 'name': name, 'requirements': len(selected),
                         'statuses': dict(Counter(r['status'] for r in selected)),
                         'configured': bool(selected)})
    if errors:
        conclusion = 'MODEL_ERROR'
    elif not results or all(r['status'] == 'NOT_APPLICABLE' for r in results):
        conclusion = 'NO_REQUIREMENTS'
    elif counts['FAIL']:
        conclusion = 'VIOLATIONS'
    elif incomplete:
        conclusion = 'INCOMPLETE'
    else:
        conclusion = 'PASS'
    warnings = []
    if not results:
        warnings.append('В графе не заданы проверяемые требования. Состав и связи сами по себе не подтверждают безопасность.')
    if incomplete:
        warnings.append(f'Не завершены проверки: {incomplete}. Неизвестное значение не считается успешной проверкой.')
    diagnostics = model.get('input_diagnostics', [])
    if isinstance(diagnostics, list):
        warnings.extend(d.get('message', str(d)) if isinstance(d, dict) else str(d) for d in diagnostics)
    if model.get('repair_diagnostics'):
        warnings.extend(d.get('message', str(d)) if isinstance(d, dict) else str(d) for d in model['repair_diagnostics'])
    skipped = model.get('repair_generation', {}).get('skipped', [])
    uncertain_repairs = [item for item in skipped if item.get('reason') in {'unknown_fact', 'fact_not_explicit'}]
    if uncertain_repairs:
        warnings.append(f'Для {len(uncertain_repairs)} разрешённых изменений нет подтверждённого исходного факта; такие действия не предлагаются.')
    return {'conclusion': conclusion, 'requirements': len(results), 'statuses': dict(counts),
            'incomplete': incomplete, 'families': families, 'warnings': list(dict.fromkeys(warnings)),
            'statement': 'Вывод относится к заданным требованиям и фактам этой модели. Он не подтверждает отсутствие всех возможных уязвимостей.'}
