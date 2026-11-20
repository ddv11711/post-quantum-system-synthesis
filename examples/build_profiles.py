"""Build readable assumptions from names/scopes, never legacy numerical IDs.

Run from the repository root: python -m examples.build_profiles
"""
import json
from pathlib import Path

from analyzer.importers import load_html

ROOT = Path(__file__).resolve().parents[1]


def build():
    graph = load_html(ROOT/'data/sources/graf-svyazey-pk.html')
    def node(pc, name):
        matches = [k for k, n in graph['nodes'].items() if n['pc'] == pc and n['name'] == name]
        if len(matches) != 1:
            raise ValueError((pc, name, matches))
        return matches[0]
    p = {'profile': 'demo_local_v1', 'assumptions': [
        {'id': 'D1', 'kind': 'demo_assumption', 'description': 'Учебный локальный профиль, не заключение о реальных правах и нормативном соответствии.'},
        {'id': 'D2', 'kind': 'demo_assumption', 'description': 'Выбранные компоненты включены и исправны; таблицы переходов перечислены полностью только для указанных контекстов.'},
        {'id': 'D3', 'kind': 'demo_assumption', 'description': 'Каждый основной пользователь обязан читать NAS. Второму пользователю ПК 2 это запрещено; доступны два явно описанных интерфейса.'},
        {'id': 'D4', 'kind': 'demo_assumption', 'description': 'Фильтрация ПК 1 обязательна и покрывается только его межсетевым экраном. Система аутентификации ПК 2 разрешает пароль ИЛИ сертификат.'},
        {'id': 'D5', 'kind': 'demo_assumption', 'description': 'Системная служба ПК 1 регистрирует событие получения сетевого пакета. Это назначенная в примере роль, а не свойство, извлечённое из названия.'},
        {'id': 'D6', 'kind': 'demo_assumption', 'description': 'Семантические назначения сохраняются при сравнении источников. Отсутствие строки становится удалением только с отдельным --closed-inventory.'},
        {'id': 'D7', 'kind': 'demo_assumption', 'description': 'Стоимость каждого атомарного изменения равна 1; поиск ограничен явно разрешённым каталогом действий.'},
    ], 'nodes': {}, 'facts': [], 'completeness': [], 'requirements': [], 'dependencies': {},
         'transitions': [], 'mutable': [], 'action_catalog': [], 'policy': {'allowed': []},
         'normative_profile': {'name': 'local educational requirements', 'regulatory_applicability': 'UNKNOWN'}}
    def prov(value, location):
        return [{'file': 'examples/demo_profile.json', 'json_key': location, 'state': 'profile_binding',
                 'raw_value': value, 'transformation': 'explicit hypothetical scenario', 'kind': 'demo_assumption'}]
    def typ(k, *types):
        p['nodes'].setdefault(k, {'types': []})['types'] = list(dict.fromkeys([*p['nodes'].get(k, {}).get('types', []), *types]))
    def fact(pred, args, value='TRUE', mutable=False):
        p['facts'].append({'predicate': pred, 'args': args, 'value': value,
                           'provenance': prov(value, f'facts[{len(p["facts"])}]')})
        if mutable:
            p['mutable'].append({'predicate': pred, 'args': args})
    def complete(pred, prefix):
        p['completeness'].append({'predicate': pred, 'args_prefix': prefix, 'complete': True,
                                  'provenance': prov(True, 'completeness')})
    def req(i, checker, obj, **kw):
        if 'title' in kw:
            kw['name'] = kw.pop('title')
        p['requirements'].append(dict(id=i, checker=checker, object=obj, applicable='TRUE',
                                     provenance=prov('required', 'requirements/'+i), **kw))
    def action(i, pred, args, value, targets, old=None):
        p['action_catalog'].append({'id': i, 'object': args[0], 'cost': 1,
            'targets': targets, 'preconditions': [] if old is None else [{'predicate': pred, 'args': args, 'value': old}],
            'effects': [{'predicate': pred, 'args': args, 'value': value}],
            'requires': [], 'excludes': [], 'provenance': prov(value, 'action_catalog/'+i)})
    def transition(i, subject, source, target, conditions):
        p['transitions'].append({'id': i, 'subject': subject, 'source': source, 'target': target,
            'operation': 'read', 'scenario': 'default', 'kind': 'access', 'conditions': conditions,
            'provenance': prov('semantic transition', 'transitions/'+i)})
    def condition(pred, args):
        return {'predicate': pred, 'args': args, 'expected': 'TRUE'}

    nas = node(None, 'Сетевой диск (NAS)')
    typ(nas, 'component', 'data')
    selected = {nas}
    for pc in range(1, 5):
        owner = node(f'ПК {pc}', 'Пользователь 1')
        os = node(f'ПК {pc}', 'Операционная система')
        cpu = node(f'ПК {pc}', 'CPU')
        typ(owner, 'subject'); typ(os, 'component', 'function'); typ(cpu, 'component')
        selected.update([os, cpu])
        p['dependencies'][os] = {'all': [cpu]}
        fact('acl', [owner, nas, 'read'], mutable=True)
        p['policy']['allowed'].append({'subject': owner, 'object': nas, 'operation': 'read',
                                       'scenario': 'default', 'provenance': prov(True, 'policy/allowed')})
        transition(f'pc{pc}-nas', owner, owner, nas,
                   [condition('acl', [owner, nas, 'read']), condition('available', [nas]), condition('available', [os])])
        complete('transitions', [owner, 'read', 'default', 'access'])
        req(f'pc{pc}_nas_required', 'required_operation', nas, subject=owner, operation='read',
            title=f'ПК {pc}: обязательное чтение общего NAS')
        req(f'pc{pc}_os_required', 'required_function', os, catalog_rule_ids=['ST006'], title=f'ПК {pc}: ОС доступна')
    fw = node('ПК 1', 'Межсетевой экран')
    packet = node('ПК 1', 'Сетевой пакет')
    logger = node('ПК 1', 'Системная служба')
    account = node('ПК 2', 'Учётная запись пользователя 1')
    password = node('ПК 2', 'Пароль пользователя 1')
    cert = node('ПК 2', 'Цифровой сертификат')
    typ(fw, 'component'); typ(packet, 'event', 'data'); typ(logger, 'component')
    typ(account, 'component'); typ(password, 'component'); typ(cert, 'component')
    selected.update([fw, logger, password, cert])
    fact('cover', [packet, 'filtering', fw]); complete('cover', [packet, 'filtering'])
    req('pc1_filtering', 'protection', packet, control='filtering', catalog_rule_ids=['MD009'], title='ПК 1: фильтрация входящего потока')
    fact('cover', [account, 'authentication', password]); fact('cover', [account, 'authentication', cert])
    complete('cover', [account, 'authentication'])
    req('pc2_auth', 'authentication', account, control='authentication', catalog_rule_ids=['ST005'], title='ПК 2: один разрешённый метод аутентификации')
    fact('event_possible', [packet]); fact('logger', [packet, logger]); complete('logger', [packet])
    req('pc1_logging', 'logging', packet, title='ПК 1: регистрация обязательного события')

    adversary = node('ПК 2', 'Пользователь 2')
    typ(adversary, 'subject')
    for branch, middle in [('application', node('ПК 2', 'Пользовательское приложение')),
                           ('vpn', node(None, 'VPN-сервер'))]:
        typ(middle, 'component'); selected.add(middle)
        fact('acl', [adversary, middle, 'read'], 'FALSE', mutable=True)
        transition(f'outsider-{branch}-entry', adversary, adversary, middle,
                   [condition('acl', [adversary, middle, 'read'])])
        transition(f'outsider-{branch}-nas', adversary, middle, nas,
                   [condition('available', [middle]), condition('available', [nas])])
        action(f'close_{branch}_acl', 'acl', [adversary, middle, 'read'], 'FALSE', ['nas_forbidden'], 'TRUE')
    complete('transitions', [adversary, 'read', 'default', 'access'])
    req('nas_forbidden', 'forbidden_operation', nas, subject=adversary, operation='read', title='Второму пользователю ПК 2 запрещено чтение NAS')
    for k in sorted(selected):
        fact('enabled', [k], mutable=True)
        fact('healthy', [k], mutable=True)
        complete('dependencies', [k])
    # Presence is imported; only this explicitly allowed restoration may change it.
    p['mutable'].append({'predicate': 'present', 'args': [fw]})
    action('restore_filter', 'present', [fw], 'TRUE', ['pc1_filtering'], 'FALSE')
    action('enable_logger', 'enabled', [logger], 'TRUE', ['pc1_logging'], 'FALSE')
    action('disable_nas', 'enabled', [nas], 'FALSE', ['nas_forbidden'], 'TRUE')
    experiment = {'description': 'Отдельный учебный эксперимент после сравнения: отключить регистрацию и открыть два интерфейса NAS. Это не изменения, обнаруженные в XLSX.',
                  'actions': [
                      {'id': 'simulate_logger_disabled', 'effects': [{'predicate': 'enabled', 'args': [logger], 'value': 'FALSE'}]},
                      *[{'id': 'simulate_'+a['id'], 'effects': [dict(a['effects'][0], value='TRUE')]}
                        for a in p['action_catalog'] if a['id'].startswith('close_')]]}
    for a in experiment['actions']:
        a['provenance'] = prov('experiment', 'examples/experiment_actions.json')
    for name, obj in [('demo_profile.json', p), ('experiment_actions.json', experiment)]:
        (ROOT/'examples'/name).write_text(json.dumps(obj, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

    channel = node('ПК 1', 'VPN-соединение')
    q = {'profile': 'quantum_passive_teaching_v1', 'nodes': {channel: {'types': ['channel']}, adversary: {'types': ['subject']}},
         'assumptions': [
             {'kind': 'demo_assumption', 'description': 'Учебный сценарий: VPN явно назначены RSA-2048, функция key_exchange, наблюдаемый материал, возможность пассивного наблюдения и условный горизонт demo-horizon. Из имени VPN это не следует.'},
             {'kind': 'demo_assumption', 'description': 'Принята достаточная квантовая возможность для условного горизонта; реальный срок появления устройства не прогнозируется. Нормативная допустимость не проверена.'},
             {'kind': 'demo_assumption', 'description': 'Активные read/write переходы этого субъекта в примере перечислены полностью и отсутствуют. Пассивное раскрытие не добавляет ACL.'}],
         'facts': [], 'transitions': [], 'completeness': [], 'requirements': [], 'mutable': []}
    for pred, args, value in [
        ('crypto_algorithm', [channel], 'RSA'), ('crypto_function', [channel], 'key_exchange'),
        ('crypto_bits', [channel], '2048'), ('material_available', [adversary, channel], 'TRUE'),
        ('observes', [adversary, channel], 'TRUE'), ('quantum_capable', [adversary, 'demo-horizon'], 'TRUE'),
        ('horizon_valid', [channel, 'demo-horizon'], 'TRUE')]:
        q['facts'].append({'predicate': pred, 'args': args, 'value': value,
                            'provenance': [{'file': 'examples/quantum_profile.json', 'kind': 'demo_assumption',
                                            'json_key': f'facts[{len(q["facts"])}]', 'state': 'profile_binding',
                                            'raw_value': value, 'transformation': 'explicit teaching threat scenario'}]})
    q['completeness'] = [{'predicate': 'transitions', 'args_prefix': [adversary, op, 'default', 'access'],
                          'complete': True, 'provenance': [{'file': 'examples/quantum_profile.json', 'kind': 'demo_assumption'}]} for op in ['read', 'write']]
    q['requirements'] = [
        {'id': 'passive_confidentiality', 'checker': 'quantum', 'object': channel, 'subject': adversary, 'horizon': 'demo-horizon', 'catalog_rule_ids': ['CR040'], 'name': 'Пассивное раскрытие потока в условном квантовом сценарии'},
        {'id': 'active_read_not_created', 'checker': 'required_operation', 'object': channel, 'subject': adversary, 'operation': 'read', 'name': 'Контрольный эксперимент: обязательный активный read не достигается пассивным раскрытием'},
        {'id': 'write_not_created', 'checker': 'forbidden_operation', 'object': channel, 'subject': adversary, 'operation': 'write', 'name': 'Пассивное раскрытие не создаёт запись'},
        {'id': 'crypto_document', 'checker': 'evidence', 'object': channel, 'document': 'normative_approval', 'name': 'Документ нормативной допустимости не предоставлен'}]
    for r in q['requirements']:
        r['applicable'] = 'TRUE'
        r['provenance'] = [{'file': 'examples/quantum_profile.json', 'kind': 'demo_assumption', 'raw_value': r['id'], 'transformation': 'local test requirement', 'state': 'profile_binding'}]
    (ROOT/'examples/quantum_profile.json').write_text(json.dumps(q, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    build()
