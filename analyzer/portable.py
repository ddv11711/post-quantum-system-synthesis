"""Compile explicit, portable typed graphs into the finite analyzer model.

Names and numeric identifiers have no security semantics. Policy never filters
actual transitions. Missing facts remain unknown, including absent edge gates.
"""
from copy import deepcopy
from hashlib import sha256
import json

from .logic import conjunction, truth
from .fls import normalize_layers, validate_fls
from .model import FactBase, NODE_TYPES, OPERATIONS, empty_model, fact

SCHEMA = 'component-security-graph/v1'
ALIASES = {'user': 'subject', 'account': 'subject', 'file': 'data', 'database': 'data',
           'storage': 'data', 'host': 'component', 'server': 'component', 'firewall': 'component',
           'antivirus': 'component', 'service': 'component'}
MAX_REQUIREMENTS = 10000


def is_portable(payload):
    return isinstance(payload, dict) and (payload.get('schema') == SCHEMA or
        ('nodes' in payload and 'edges' in payload and 'facts' not in payload and 'requirements' not in payload))


def _bad(path, message):
    raise ValueError(f'{path}: {message}')


def _records(value, path):
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        _bad(path, 'ожидается список объектов')
    return value


def _strings(value, path):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        _bad(path, 'ожидается список непустых строк')
    return value


def _boolean(value, path):
    if value not in (True, False, 'TRUE', 'FALSE', 'UNKNOWN', None) or isinstance(value, (int, float)) and not isinstance(value, bool):
        _bad(path, 'ожидается true, false или UNKNOWN')
    return truth(value).value


def _id(*values):
    return json.dumps(values, ensure_ascii=False, separators=(',', ':'))


def load_portable(payload, *, source='<portable-json>'):
    """Return a canonical model without mutating input; malformed syntax raises ValueError.

    Conflicting explicit security facts are retained for analyze() → MODEL_ERROR.
    The compiler does not close relations just because an input list is finite.
    """
    if not is_portable(payload):
        _bad('$', f'ожидается schema={SCHEMA} или объект nodes/edges')
    payload = deepcopy(payload)
    if payload.get('schema', SCHEMA) != SCHEMA:
        _bad('$.schema', 'неподдерживаемая версия')
    model = empty_model(payload.get('state', 'portable'), payload.get('profile', 'declared-portable'))
    if not isinstance(model['state'], str) or not isinstance(model['profile'], str):
        _bad('$', 'state и profile должны быть строками')
    diagnostics = []
    model['input_diagnostics'] = diagnostics
    model['portable_schema'] = SCHEMA
    model['portable_source'] = payload
    model['assumptions'] = deepcopy(payload.get('assumptions', []))

    def evidence(path, raw, transformation='explicit portable declaration'):
        return [{'file': str(source), 'json_key': path, 'state': model['state'],
                 'raw_value': deepcopy(raw), 'transformation': transformation, 'kind': 'declared'}]

    def add_fact(predicate, args, value, path, raw=None, scalar=False):
        model['facts'].append(fact(predicate, args, value if scalar else _boolean(value, path),
                                   evidence(path, value if raw is None else raw)))

    def require(checker, path, **kwargs):
        if len(model['requirements']) >= MAX_REQUIREMENTS:
            _bad(path, f'превышен предел {MAX_REQUIREMENTS} требований; сузьте явную область политики')
        entry = {'id': _id(checker, path, kwargs.get('subject'), kwargs.get('object'), kwargs.get('operation')),
                 'rule_id': 'PORTABLE.' + checker, 'checker': checker, 'name': kwargs.pop('name', checker),
                 'provenance': evidence(path, kwargs), **kwargs}
        model['requirements'].append(entry)

    def reference(value, path):
        if not isinstance(value, str) or value not in model['nodes']:
            _bad(path, f'неизвестный узел {value!r}')
        return value

    node_input = payload.get('nodes')
    if isinstance(node_input, dict):
        records = []
        for key, attrs in node_input.items():
            if not isinstance(attrs, dict):
                _bad('$.nodes', 'запись узла должна быть объектом')
            if 'id' in attrs and attrs['id'] != key:
                _bad('$.nodes', 'id узла противоречит ключу словаря')
            records.append((key, dict(attrs, id=key), '$.nodes[' + json.dumps(key, ensure_ascii=False) + ']'))
    else:
        records = [(n.get('id', n.get('key')), n, f'$.nodes[{i}]') for i, n in enumerate(_records(node_input, '$.nodes'))]
    for key, node, path in records:
        if not isinstance(key, str) or not key or key in model['nodes']:
            _bad(path, 'id должен быть уникальной непустой строкой')
        kinds = node.get('types', [node.get('type', node.get('kind', 'unknown'))])
        kinds = _strings(kinds, path + '.types')
        types = sorted(set(ALIASES.get(t, t) for t in kinds))
        if not set(types) <= NODE_TYPES:
            _bad(path + '.types', 'неподдерживаемый явно объявленный тип')
        model['nodes'][key] = {**deepcopy(node), 'key': key, 'types': types,
            'original_types': kinds, 'provenance': evidence(path, node)}
    model['nodes'] = dict(sorted(model['nodes'].items()))
    for field in ('facts', 'requirements'):
        native = _records(payload.get(field, []), '$.' + field)
        if field == 'requirements' and len(native) > MAX_REQUIREMENTS:
            _bad('$.requirements', f'превышен предел {MAX_REQUIREMENTS} требований')
        for i, entry in enumerate(native):
            path = f'$.{field}[{i}]'
            if field == 'facts':
                if not isinstance(entry.get('predicate'), str) or 'value' not in entry:
                    _bad(path, 'факт требует predicate, args и value')
                _strings(entry.get('args'), path + '.args')
            elif not isinstance(entry.get('id'), str) or not entry.get('id') or not isinstance(entry.get('checker'), str):
                _bad(path, 'требование требует непустой строковый id и checker')
            provenance = _records(entry.get('provenance', []), path + '.provenance')
            model[field].append({**deepcopy(entry), 'provenance': deepcopy(provenance) + evidence(path, entry)})
    for key, node, path in records:
        for flag in ('required', 'authentication_required', 'logging_required', 'backup_required',
                     'integrity_required', 'trusted_boot_required', 'dependencies_complete', 'roles_complete',
                     'crypto_required', 'redundancy_required', 'replicas_complete'):
            if flag in node and not isinstance(node[flag], bool):
                _bad(path + '.' + flag, 'ожидается true или false (логическое значение JSON)')

        # Listed nodes explicitly denote present inventory unless overridden.
        add_fact('present', [key], node.get('present', True), path + '.present', node.get('present', 'listed inventory node'))
        for predicate in ('enabled', 'healthy', 'transport_enabled', 'event_possible', 'readable', 'key_accessible',
                          'integrity', 'trusted_boot', 'crypto_protected', 'changed', 'approved'):
            if predicate in node:
                add_fact(predicate, [key], node[predicate], path + '.' + predicate)
        for predicate in ('failure_mode', 'crypto_algorithm', 'crypto_function', 'crypto_bits'):
            if predicate in node:
                add_fact(predicate, [key], node[predicate], path + '.' + predicate, scalar=True)
        for field in ('parameters', 'expected_parameters'):
            if not isinstance(node.get(field, {}), dict):
                _bad(path + '.' + field, 'ожидается объект параметров')
        for parameter, value in node.get('parameters', {}).items():
            add_fact('parameter', [key, parameter], value, path + '.parameters.' + parameter, scalar=True)
        if 'dependencies' in node:
            expr = node['dependencies']
            if not isinstance(expr, dict) or set(expr) - {'all', 'any'}:
                _bad(path + '.dependencies', 'ожидается полное выражение all/any')
            for mode, refs in expr.items():
                for ref in _strings(refs, path + '.dependencies.' + mode):
                    reference(ref, path + '.dependencies')
            model['dependencies'][key] = deepcopy(expr)
            model.setdefault('dependency_provenance', {})[key] = evidence(path + '.dependencies', expr)
        if node.get('dependencies_complete') is True and key not in model['dependencies']:
            model['dependencies'][key] = {'all': []}
        for role in _strings(node.get('roles', []), path + '.roles'):
            reference(role, path + '.roles')
            add_fact('has_role', [key, role], True, path + '.roles', role)
        if node.get('roles_complete') is True:
            model['completeness'].append({'predicate': 'has_role', 'args_prefix': [key], 'complete': True,
                                          'provenance': evidence(path + '.roles_complete', True)})
        if node.get('required') is True:
            require('required_function', path + '.required', object=key)
        for control in _strings(node.get('required_controls', []), path + '.required_controls'):
            require('protection', path + '.required_controls.' + control, object=key, control=control)
        for attr, checker in [('authentication_required', 'authentication'), ('logging_required', 'logging'), ('backup_required', 'recovery')]:
            if node.get(attr) is True:
                require(checker, path + '.' + attr, object=key)
        if node.get('crypto_required') is True:
            require('crypto', path + '.crypto_required', object=key)
        if node.get('redundancy_required') is True:
            replicas = _strings(node.get('replicas', []), path + '.replicas')
            for replica in replicas:
                reference(replica, path + '.replicas')
            require('redundancy', path + '.redundancy_required', object=key,
                    replicas=replicas, replicas_complete=node.get('replicas_complete', False))
        for parameter, expected in node.get('expected_parameters', {}).items():
            require('configuration', path + '.expected_parameters.' + parameter, object=key,
                    predicate='parameter', args=[key, parameter], expected=('TRUE' if expected is True else 'FALSE' if expected is False else str(expected) if isinstance(expected, (int, float)) else expected))
        for attr, predicate in [('integrity_required', 'integrity'), ('trusted_boot_required', 'trusted_boot')]:
            if node.get(attr) is True:
                require('configuration', path + '.' + attr, object=key, predicate=predicate, expected='TRUE')
        for vuln in _records(node.get('known_vulnerabilities', []), path + '.known_vulnerabilities'):
            identifier = vuln.get('id')
            if not isinstance(identifier, str) or not identifier:
                _bad(path + '.known_vulnerabilities', 'уязвимость требует строковый id')
            value = _boolean(vuln.get('patched'), path + '.known_vulnerabilities.patched')
            add_fact('parameter', [key, 'patch:' + identifier], value, path + '.known_vulnerabilities', scalar=True)
            require('configuration', path + '.known_vulnerabilities.' + identifier, object=key,
                    predicate='parameter', args=[key, 'patch:' + identifier], expected='TRUE')

    for i, entry in enumerate(_records(payload.get('completeness', []), '$.completeness')):
        model['completeness'].append({**deepcopy(entry), 'provenance': evidence(f'$.completeness[{i}]', entry)})
    for i, acl in enumerate(_records(payload.get('actual_acl', []), '$.actual_acl')):
        path = f'$.actual_acl[{i}]'
        subject, target = reference(acl.get('subject'), path), reference(acl.get('object'), path)
        for operation in _strings(acl.get('operations'), path + '.operations'):
            if operation not in OPERATIONS:
                _bad(path, 'неподдерживаемая операция')
            add_fact('acl', [subject, target, operation], acl.get('allowed'), path)

    model['fls_channels'] = []
    raw_edges, access_contexts, flows, seen_edges = [], set(), [], set()
    access_targets = set()
    partial_dependencies = set()
    for i, edge in enumerate(_records(payload.get('edges', []), '$.edges')):
        path = f'$.edges[{i}]'
        if 'use_acl' in edge and not isinstance(edge['use_acl'], bool):
            _bad(path + '.use_acl', 'ожидается true или false (логическое значение JSON)')
        start, target = reference(edge.get('source'), path + '.source'), reference(edge.get('target'), path + '.target')
        eid = edge.get('id', 'edge:' + sha256(json.dumps(edge, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20])
        if not isinstance(eid, str) or not eid or eid in seen_edges:
            _bad(path + '.id', 'id ребра должен быть уникальной строкой')
        seen_edges.add(eid)
        kind = edge.get('type', 'untyped')
        if kind != 'interaction' and any(field in edge for field in ('layers', 'bidirectional', 'protection_via')):
            _bad(path, 'layers, bidirectional и protection_via относятся только к type=interaction; доступ связывается через channel')
        if 'channel' in edge and kind not in ('access', 'flow', 'copy'):
            _bad(path + '.channel', 'ссылка channel допустима только для access/flow/copy')
        if kind == 'interaction' and edge.get('bidirectional') is True and start == target:
            _bad(path + '.bidirectional', 'для петли требуется один явно направленный канал, а не две одинаковые стороны')
        raw_edges.append({**deepcopy(edge), 'id': eid, 'source': start, 'target': target, 'provenance': evidence(path, edge)})
        if kind == 'interaction':
            if 'bidirectional' in edge and not isinstance(edge['bidirectional'], bool):
                _bad(path + '.bidirectional', 'ожидается true или false')
            try:
                layers = normalize_layers(edge.get('layers', {}))
            except ValueError as exc:
                _bad(path + '.layers', str(exc))
            protection = _strings(edge.get('protection_via', []), path + '.protection_via')
            for node in protection:
                reference(node, path + '.protection_via')
            for reverse in ([False, True] if edge.get('bidirectional', False) else [False]):
                model['fls_channels'].append({
                    'id': eid + '::reverse' if reverse else eid,
                    'original_channel_id': eid, 'direction': 'reverse' if reverse else 'forward',
                    'source': target if reverse else start, 'target': start if reverse else target,
                    'layers': deepcopy(layers), 'protection_via': list(reversed(protection)) if reverse else list(protection),
                    'provenance': evidence(path, edge, 'explicit FLS interaction; reverse direction expanded only by bidirectional=true'),
                })
        elif kind in ('access', 'flow', 'copy'):
            subject = reference(edge.get('subject'), path + '.subject')
            operations = _strings(edge.get('operations', ['write'] if kind in ('flow', 'copy') else None), path + '.operations')
            for operation in operations:
                if operation not in OPERATIONS or kind in ('flow', 'copy') and operation != 'write':
                    _bad(path + '.operations', 'access: read/write/execute/administer; flow/copy: write')
                scenario = edge.get('scenario', 'default')
                tid = _id(eid, operation)
                gate = conjunction([truth(_boolean(edge.get('allowed'), path + '.allowed')),
                                    truth(_boolean(edge.get('enabled'), path + '.enabled'))]).value
                add_fact('transition_enabled', [tid], gate, path, edge)
                conditions = [{'predicate': 'transition_enabled', 'args': [tid]}] + deepcopy(_records(edge.get('conditions', []), path + '.conditions'))
                if edge.get('use_acl') is True:
                    conditions.append({'predicate': 'acl', 'args': [subject, target, operation]})
                transition = {'id': tid, 'portable_edge_id': eid, 'source': start, 'target': target,
                    'subject': subject, 'operation': operation, 'kind': 'access' if kind == 'access' else 'flow',
                    'scenario': scenario, 'value': 'TRUE', 'conditions': conditions, 'provenance': evidence(path, edge)}
                if 'via' in edge:
                    transition['via'] = reference(edge['via'], path + '.via')
                if 'channel' in edge:
                    if not isinstance(edge['channel'], str) or not edge['channel']:
                        _bad(path + '.channel', 'ожидается точный id канала interaction')
                    transition['channel'] = edge['channel']
                model['transitions'].append(transition)
                if kind == 'access':
                    access_targets.add(target)
                    access_contexts.add((subject, operation, scenario))
                else:
                    flows.append((eid, subject, start, target, scenario))
        elif kind == 'dependency':
            mode = edge.get('mode', 'all')
            if mode not in ('all', 'any'):
                _bad(path + '.mode', 'ожидается all или any')
            model['dependencies'].setdefault(start, {}).setdefault(mode, []).append(target)
            model.setdefault('dependency_provenance', {}).setdefault(start, []).extend(evidence(path, edge))
            if model['nodes'][start].get('dependencies_complete') is not True and 'dependencies' not in model['nodes'][start]:
                partial_dependencies.add(start)
        elif kind in ('protection', 'control_coverage', 'authentication'):
            control = edge.get('control', 'authentication' if kind == 'authentication' else None)
            if not isinstance(control, str) or not control:
                _bad(path + '.control', 'защитное покрытие требует имя функции control')
            add_fact('cover', [target, control, start], edge.get('value', True), path)
        elif kind == 'logger':
            add_fact('logger', [target, start], edge.get('value', True), path)
        elif kind == 'backup':
            add_fact('backup', [start, target], edge.get('value', True), path)
        elif kind == 'key_required':
            add_fact('key_required', [start, target], edge.get('value', True), path)
        elif kind in ('physical', 'channel', 'stores', 'executes', 'owns', 'authenticates', 'independent'):
            add_fact(kind, [start, target], edge.get('value', True), path)
        elif kind == 'untyped':
            diagnostics.append({'code': 'UNTYPED_EDGE', 'edge': eid, 'path': path, 'message': 'Структурная связь не дает права операции.'})
        else:
            _bad(path + '.type', f'неподдерживаемый тип связи {kind!r}; используйте untyped для неизвестной семантики')
    # Resolve after all edges: source order must not affect channel binding.
    for transition in model['transitions']:
        if 'channel' not in transition:
            continue
        requested = transition['channel']
        matches = [channel for channel in model['fls_channels']
                   if requested in (channel['id'], channel['original_channel_id'])
                   and (transition['source'], transition['target']) == (channel['source'], channel['target'])]
        if len(matches) != 1:
            _bad('$.edges.channel', f'канал {requested!r} отсутствует, неоднозначен или не соответствует направлению перехода')
        transition['channel'] = matches[0]['id']
    fls_errors = validate_fls(model)
    if fls_errors:
        _bad('$.edges', 'некорректные FLS-каналы: ' + json.dumps(fls_errors, ensure_ascii=False))
    model['fls_channels'].sort(key=lambda channel: channel['id'])
    model['incomplete_dependencies'] = sorted(partial_dependencies)
    for node, expr in model['dependencies'].items():
        for mode, refs in expr.items():
            expr[mode] = sorted(set(refs))
    model['source_graph'] = {'nodes': deepcopy(model['nodes']), 'edges': raw_edges,
        'state': model['state'], 'metadata': {'format': 'portable', 'node_count': len(model['nodes']),
        'edge_count': len(raw_edges), 'file': str(source)}, 'issues': diagnostics}

    policy = payload.get('policy', {})
    if not isinstance(policy, dict) or policy.get('default', 'unknown') not in ('deny', 'unknown'):
        _bad('$.policy', 'default должен быть deny или unknown')
    if 'complete' in policy and not isinstance(policy['complete'], bool):
        _bad('$.policy.complete', 'ожидается true или false (логическое значение JSON)')
    model['declared_policy'] = deepcopy(policy)
    membership = FactBase(model)
    subjects = sorted(k for k, n in model['nodes'].items() if 'subject' in n['types'])
    grants = {}

    def expand(entry, path):
        target = reference(entry.get('object'), path + '.object')
        operations = _strings(entry.get('operations'), path + '.operations')
        if not set(operations) <= OPERATIONS:
            _bad(path + '.operations', 'неподдерживаемая операция')
        if ('subject' in entry) == ('role' in entry):
            _bad(path, 'укажите ровно одно поле subject или role')
        if 'subject' in entry:
            candidates = [(reference(entry['subject'], path + '.subject'), 'TRUE')]
        else:
            role = reference(entry['role'], path + '.role')
            candidates = [(s, membership.boolean('has_role', [s, role]).value) for s in subjects]
        for subject, applicable in candidates:
            if applicable == 'FALSE':
                continue
            for operation in operations:
                yield {'subject': subject, 'object': target, 'operation': operation,
                       'scenario': entry.get('scenario', 'default'), 'kind': entry.get('kind', 'access'),
                       'applicable': applicable}

    for field, checker in [('grants', None), ('denies', 'forbidden_operation'), ('required', 'required_operation')]:
        for i, entry in enumerate(_records(policy.get(field, []), '$.policy.' + field)):
            path = f'$.policy.{field}[{i}]'
            for permission in expand(entry, path):
                key = tuple(permission[k] for k in ('subject', 'object', 'operation', 'scenario', 'kind'))
                if checker is None:
                    grants[key] = 'TRUE' if permission['applicable'] == 'TRUE' or grants.get(key) == 'TRUE' else 'UNKNOWN'
                    model['policy']['allowed'].append({**permission, 'provenance': evidence(path, entry)})
                else:
                    require(checker, path, **permission)
    if policy.get('default') == 'deny':
        if policy.get('complete') is True:
            scope = policy.get('scope', {})
            if not isinstance(scope, dict):
                _bad('$.policy.scope', 'ожидается объект области')
            domain_subjects = _strings(scope.get('subjects', subjects), '$.policy.scope.subjects')
            default_objects = {k for k,n in model['nodes'].items() if not set(n['types']) & {'subject', 'role'}} | access_targets
            domain_objects = _strings(scope.get('objects', sorted(default_objects)), '$.policy.scope.objects')
            operations = _strings(scope.get('operations', sorted(OPERATIONS)), '$.policy.scope.operations')
            if not set(operations) <= OPERATIONS:
                _bad('$.policy.scope.operations', 'неподдерживаемая операция')
            for subject in domain_subjects:
                reference(subject, '$.policy.scope.subjects')
                for obj in domain_objects:
                    reference(obj, '$.policy.scope.objects')
                    for operation in operations:
                        key = (subject, obj, operation, scope.get('scenario', 'default'), 'access')
                        if grants.get(key) == 'TRUE':
                            continue
                        require('forbidden_operation', '$.policy.default.' + _id(*key), subject=subject, object=obj,
                            operation=operation, scenario=key[3], applicable='UNKNOWN' if grants.get(key) == 'UNKNOWN' else 'TRUE')
        else:
            diagnostics.append({'code': 'INCOMPLETE_POLICY', 'path': '$.policy.complete', 'message': 'default=deny не раскрывается без явной полноты grants.'})
            require('semantic_readiness', '$.policy.complete', missing=['Полнота перечня разрешенных политикой операций не подтверждена'])
    if 'security_policy' in payload:
        model['security_policy'] = deepcopy(payload['security_policy'])
        if not isinstance(model['security_policy'], dict):
            _bad('$.security_policy', 'ожидается объект')
        if model['security_policy'].get('enabled') is True:
            scope = model['security_policy'].get('scope', {})
            if not isinstance(scope, dict):
                _bad('$.security_policy.scope', 'ожидается объект области')
            default_targets = {k for k,n in model['nodes'].items()
                if 'subject' not in n['types'] and ('data' in n['types'] or 'security_label' in n or 'integrity_label' in n)}
            default_targets |= access_targets
            data_nodes = _strings(scope.get('objects', sorted(default_targets)), '$.security_policy.scope.objects')
            scoped_subjects = _strings(scope.get('subjects', subjects), '$.security_policy.scope.subjects')
            scoped_operations = _strings(scope.get('operations', ['read', 'write']), '$.security_policy.scope.operations')
            if not set(scoped_operations) <= {'read', 'write'}:
                _bad('$.security_policy.scope.operations', 'MAC поддерживает read и write')
            scenarios = _strings(scope.get('scenarios', ['default']), '$.security_policy.scope.scenarios')
            for obj in data_nodes:
                reference(obj, '$.security_policy.scope.objects')
            for subject in scoped_subjects:
                reference(subject, '$.security_policy.scope.subjects')
            contexts = {(s, op, scenario) for s in scoped_subjects for op in scoped_operations for scenario in scenarios}
            # Include explicitly declared access contexts even when no route currently exists.
            if not scope:
                contexts |= access_contexts | {(r['subject'], r['operation'], r.get('scenario', 'default'))
                    for r in model['requirements'] if r.get('checker') in ('required_operation', 'forbidden_operation')
                    and isinstance(r.get('subject'), str) and isinstance(r.get('operation'), str)}
            for subject, operation, scenario in sorted(contexts):
                if operation in ('read', 'write'):
                    for target in data_nodes:
                        require('mandatory_access', '$.security_policy.' + _id(subject,target,operation,scenario),
                                subject=subject, object=target, operation=operation, scenario=scenario)
            for eid, subject, start, target, scenario in flows:
                require('label_flow', '$.edges.' + eid, subject=subject, source=start, object=target,
                        operation='write', scenario=scenario, kind='flow',
                        catalog_rule_ids=['FT025'], catalog_scope='fragment')
            for subject in subjects:
                if 'clearance' in model['nodes'][subject]:
                    require('clearance', '$.nodes.' + subject + '.clearance', subject=subject, object=subject)
    if not model['requirements']:
        require('semantic_readiness', '$', missing=['Нет явных требований политики или проверяемых намерений узлов'])
    if partial_dependencies:
        diagnostics.append({'code': 'INCOMPLETE_DEPENDENCIES', 'nodes': sorted(partial_dependencies),
                            'message': 'Неполный перечень зависимостей сохраняет UNKNOWN работоспособности.'})
    for field in ('mutable', 'action_catalog'):
        if field in payload:
            model[field] = deepcopy(_records(payload[field], '$.' + field))
    if 'repair_policy' in payload:
        model['repair_policy'] = deepcopy(payload['repair_policy'])
    model['transitions'].sort(key=lambda t: t['id'])
    return model
