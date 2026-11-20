"""Editable typed graph workbooks. Formula cells are never evaluated."""
from copy import deepcopy
from io import BytesIO
import json

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill, Alignment
from .workbook import WorkbookFormatError, read_bounded_rows

NODE_COLUMNS = ['id', 'name', 'type', 'group', 'cluster', 'present', 'enabled', 'healthy',
                'security_level', 'security_categories', 'clearance_level', 'clearance_categories',
                'integrity_level', 'integrity_categories', 'required', 'required_controls',
                'authentication_required', 'logging_required', 'backup_required', 'attributes']
EDGE_COLUMNS = ['id', 'type', 'source', 'target', 'subject', 'operations', 'allowed', 'enabled', 'control',
                'physical', 'syntactic', 'semantic', 'bidirectional', 'protection_via', 'channel', 'attributes']
POLICY_COLUMNS = ['effect', 'subject', 'role', 'object', 'operations', 'scenario', 'kind', 'attributes']
NAMES = {'nodes': ('Nodes', 'Узлы'), 'edges': ('Edges', 'Связи'), 'policy': ('Policy', 'Политика'),
         'settings': ('Settings', 'Настройки')}
ARRAYS = {'operations', 'required_controls', 'security_categories', 'clearance_categories', 'integrity_categories', 'protection_via'}
BOOLEANS = {'present', 'enabled', 'healthy', 'required', 'authentication_required', 'logging_required', 'backup_required', 'allowed',
            'physical', 'syntactic', 'semantic', 'bidirectional'}


def _sheet(book, kind):
    return next((book[name] for name in NAMES[kind] if name in book.sheetnames), None)


def is_portable_workbook(path):
    book = load_workbook(path, read_only=True, data_only=False)
    try:
        return _sheet(book, 'nodes') is not None
    finally:
        book.close()


def _records(sheet, allowed, limit):
    if sheet is None:
        return []
    try:
        rows = iter(read_bounded_rows(sheet, max_rows=limit + 1, max_columns=len(allowed)))
    except WorkbookFormatError as exc:
        raise ValueError(str(exc).replace('Formula cells are unsupported', 'формулы не поддерживаются; укажите значение')) from exc
    header = next(rows, ())
    fields = [str(cell.value).strip() if cell.value is not None else '' for cell in header]
    if not fields or any(cell.data_type == 'f' for cell in header) or len(fields) != len(set(fields)) or set(fields) - set(allowed):
        raise ValueError(f'Лист {sheet.title}: неизвестные или повторяющиеся столбцы. Используйте скачанный образец.')
    result = []
    for cells in rows:
        if not any(cell.value is not None for cell in cells):
            continue
        for cell in cells[len(fields):]:
            if cell.value not in (None, ''):
                raise ValueError(f'{sheet.title}!{cell.coordinate}: значение вне столбцов, заданных заголовком.')
        item = {}
        for field, cell in zip(fields, cells):
            if cell.data_type == 'f':
                raise ValueError(f'{sheet.title}!{cell.coordinate}: формулы не поддерживаются; укажите значение.')
            value = cell.value
            if value is None or value == '':
                continue
            if field in ARRAYS:
                if not isinstance(value, str):
                    raise ValueError(f'{sheet.title}!{cell.coordinate}: ожидается список JSON или значения через точку с запятой.')
                value = json.loads(value) if value.strip().startswith('[') else [part.strip() for part in value.split(';') if part.strip()]
            elif field in BOOLEANS and isinstance(value, str) and value.upper() in {'TRUE', 'FALSE'}:
                value = value.upper() == 'TRUE'
            elif field == 'attributes':
                value = json.loads(value)
                if not isinstance(value, dict):
                    raise ValueError(f'{sheet.title}!{cell.coordinate}: attributes должен содержать объект JSON.')
            item[field] = value
        extras = item.pop('attributes', {})
        if extras.keys() & item.keys():
            raise ValueError(f'Лист {sheet.title}: attributes повторяет явно заданное поле.')
        item.update(extras)
        result.append(item)
    return result


def load_portable_workbook(path):
    book = load_workbook(path, read_only=True, data_only=False)
    try:
        if _sheet(book, 'nodes') is None:
            raise ValueError('В типизированном графе нужен лист Nodes или Узлы.')
        permitted = {name for names in NAMES.values() for name in names}
        if set(book.sheetnames) - permitted:
            raise ValueError('Допустимы листы Nodes, Edges, Policy, Settings (или русские названия из образца).')
        for kind, names in NAMES.items():
            if sum(name in book.sheetnames for name in names) > 1:
                raise ValueError(f'Два листа описывают {kind}; оставьте один.')
        payload = {'schema': 'component-security-graph/v1', 'nodes': [], 'edges': []}
        for record in _records(_sheet(book, 'nodes'), NODE_COLUMNS, 5000):
            if isinstance(record.get('type'), str) and record['type'].strip().startswith('['):
                record['types'] = json.loads(record.pop('type'))
            for prefix, target in [('security', 'security_label'), ('clearance', 'clearance'), ('integrity', 'integrity_label')]:
                label = {key: record.pop(f'{prefix}_{key}') for key in ('level', 'categories') if f'{prefix}_{key}' in record}
                if label:
                    if target in record:
                        raise ValueError(f'Метка {target} задана дважды.')
                    record[target] = label
            payload['nodes'].append(record)
        payload['edges'] = _records(_sheet(book, 'edges'), EDGE_COLUMNS, 20000)
        for edge in payload['edges']:
            layers = {name: edge.pop(name) for name in ('physical', 'syntactic', 'semantic') if name in edge}
            if layers:
                if 'layers' in edge:
                    raise ValueError('Уровни связи заданы дважды: в столбцах и attributes.layers.')
                edge['layers'] = layers
        policy = {}
        for record in _records(_sheet(book, 'policy'), POLICY_COLUMNS, 10000):
            effect = record.pop('effect', '')
            if effect not in {'grant', 'deny', 'required'}:
                raise ValueError('Policy.effect: допустимы grant, deny, required.')
            policy.setdefault({'grant': 'grants', 'deny': 'denies', 'required': 'required'}[effect], []).append(record)
        for setting in _records(_sheet(book, 'settings'), ['key', 'value'], 100):
            key = setting.get('key')
            if not isinstance(key, str) or key in {'schema', 'nodes', 'edges', 'policy'} or key in payload:
                raise ValueError(f'Недопустимый или повторяющийся ключ Settings: {key}.')
            try:
                payload[key] = json.loads(str(setting['value']))
            except (KeyError, ValueError) as exc:
                raise ValueError(f'Settings.{key}: ожидается значение JSON.') from exc
        options = payload.pop('policy_options', {})
        if not isinstance(options, dict) or set(options) & {'grants', 'denies', 'required'}:
            raise ValueError('policy_options содержит только настройки политики, без списков правил.')
        if policy or options:
            payload['policy'] = {**options, **policy}
        return payload
    finally:
        book.close()


def portable_workbook(payload):
    book = Workbook()
    book.remove(book.active)
    def value(item):
        return json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else item
    def table(title, columns, rows):
        sheet = book.create_sheet(title)
        sheet.append(columns)
        for item in rows:
            record = deepcopy(item)
            extra = {key: record.pop(key) for key in list(record) if key not in columns}
            if 'attributes' in columns and extra:
                record['attributes'] = extra
            sheet.append([value(record.get(key)) for key in columns])
        sheet.freeze_panes = 'A2'
        sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]:
            cell.font = Font(bold=True, color='FFFFFF')
            cell.fill = PatternFill('solid', fgColor='5353D9')
        for cells in sheet.columns:
            sheet.column_dimensions[cells[0].column_letter].width = min(55, max(18, len(str(cells[0].value)) + 4))
        for row in sheet.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(vertical='top', wrap_text=True)
    nodes = payload.get('nodes', [])
    nodes = [dict(node, id=key) for key, node in nodes.items()] if isinstance(nodes, dict) else nodes
    rows = []
    for source in nodes:
        record = deepcopy(source)
        if 'types' in record and 'type' not in record:
            record['type'] = json.dumps(record.pop('types'), ensure_ascii=False)
        for prefix, field in [('security', 'security_label'), ('clearance', 'clearance'), ('integrity', 'integrity_label')]:
            label = record.pop(field, None)
            if isinstance(label, dict):
                record.update({f'{prefix}_{key}': val for key, val in label.items()})
        rows.append(record)
    table('Nodes', NODE_COLUMNS, rows)
    edge_rows = []
    for source in payload.get('edges', []):
        record = deepcopy(source)
        layers = record.pop('layers', None)
        if isinstance(layers, dict):
            if set(layers) - {'physical', 'syntactic', 'semantic'} or set(layers) & record.keys():
                raise ValueError('Некорректные или повторяющиеся уровни связи.')
            record.update(layers)
        elif layers is not None:
            raise ValueError('layers должен быть объектом трёх уровней связи.')
        edge_rows.append(record)
    table('Edges', EDGE_COLUMNS, edge_rows)
    policy = payload.get('policy', {})
    table('Policy', POLICY_COLUMNS, [dict(rule, effect=effect) for field, effect in [('grants', 'grant'), ('denies', 'deny'), ('required', 'required')] for rule in policy.get(field, [])])
    settings = {key: val for key, val in payload.items() if key not in {'schema', 'nodes', 'edges', 'policy'}}
    if policy:
        settings['policy_options'] = {key: val for key, val in policy.items() if key not in {'grants', 'denies', 'required'}}
    table('Settings', ['key', 'value'], [{'key': key, 'value': json.dumps(val, ensure_ascii=False)} for key, val in settings.items()])
    output = BytesIO()
    book.save(output)
    return output.getvalue()
