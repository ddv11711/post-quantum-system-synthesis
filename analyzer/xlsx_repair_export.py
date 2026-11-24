"""Export a verified *simulation* in the same five-column XLSX input schema.

A mandate-flow action disables a concrete source edge.  That is the only kind
of repair we can faithfully write back into the incoming/outgoing XLSX cells.
The four-PC educational policy has additional facts outside that XLSX schema:
we annotate its action plan, but never falsely change data-transfer cells.
"""
from collections import Counter, defaultdict
from copy import copy, deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from openpyxl import load_workbook
from openpyxl.comments import Comment
from openpyxl.styles import PatternFill

from .importers import GLOBAL_NAMES, load_xlsx

GREEN = PatternFill(fill_type='solid', fgColor='DDF5E7')
AMBER = PatternFill(fill_type='solid', fgColor='FFF0C7')
COMMENT_AUTHOR = 'Логический анализатор'


def _mark(cell, color, message):
    cell.fill = color
    previous = cell.comment.text + '\n\n' if cell.comment else ''
    cell.comment = Comment((previous + message)[:32000], COMMENT_AUTHOR)


def _xlsx_bytes(workbook):
    data = BytesIO()
    workbook.save(data)
    return data.getvalue()


def export_mandate_workbook(source_path, model, repaired):
    """Return bytes and count, refusing any edit that lacks precise provenance.

    `repaired` is the VERIFIED_CANDIDATE returned by repair_mandate_flows;
    the caller must re-run that server-side on the same source and never trust
    client-submitted targets. The file retains exactly one worksheet, original
    header order and all five original columns, so it can be re-imported.
    """
    if repaired.get('status') != 'VERIFIED_CANDIDATE' or not repaired.get('independently_rechecked'):
        raise ValueError('Подтверждённые исправления отсутствуют.')
    graph = model.get('source_graph')
    if not isinstance(graph, dict) or graph.get('format') != 'xlsx':
        raise ValueError('Исходная таблица Excel для исправления недоступна.')
    selected = set(repaired.get('targets') or [])
    transitions = {item['id']: item for item in model['transitions']}
    if not selected or selected - set(transitions):
        raise ValueError('Недостаточно данных, чтобы перенести исправления в Excel.')
    edge_indices = set()
    affected = defaultdict(set)
    for target in selected:
        transition = transitions[target]
        index = transition.get('source_edge_index')
        if not isinstance(index, int) or not 0 <= index < len(graph['edges']):
            raise ValueError('Не найдена исходная связь для исправления.')
        edge = graph['edges'][index]
        if (edge['source'], edge['target']) != (transition['source'], transition['target']):
            raise ValueError('Нарушена связь между проверкой и строкой Excel.')
        if index in edge_indices:
            raise ValueError('Два исправления ссылаются на одну и ту же связь.')
        edge_indices.add(index)
        evidence = edge.get('provenance', [])
        if not evidence:
            raise ValueError('У удаляемой связи нет исходных ячеек Excel.')
        for item in evidence:
            cell, ref = item.get('cell'), item.get('reference')
            if (not isinstance(cell, str) or not isinstance(ref, str)
                    or item.get('direction') not in {'incoming', 'outgoing'}):
                raise ValueError('Для изменения связи требуется точная ячейка и ссылка.')
            affected[(item.get('sheet'), cell)].add(ref)

    original_edges = {(e['source'], e['target']) for e in graph['edges']}
    removed_edges = {(graph['edges'][index]['source'], graph['edges'][index]['target']) for index in edge_indices}
    book = load_workbook(source_path, keep_links=False)
    try:
        if len(book.worksheets) != 1:
            raise ValueError('Входной Excel должен содержать ровно один лист.')
        sheet = book.active
        count = 0
        for (sheet_name, address), refs in sorted(affected.items()):
            if sheet_name != sheet.title:
                raise ValueError('Исходное имя листа не совпало с моделью.')
            cell = sheet[address]
            if cell.column not in (4, 5) or cell.row < 2 or not isinstance(cell.value, str):
                raise ValueError(f'Недопустимая исходная ячейка {address}.')
            fragments = cell.value.split(',')
            present = {' '.join(item.split()) for item in fragments if item.strip()}
            if refs - present:
                raise ValueError(f'В ячейке {address} отсутствует ожидаемая связь.')
            kept = [part.strip() for part in fragments if ' '.join(part.split()) not in refs and part.strip()]
            original_text = cell.value
            cell.value = ', '.join(kept) if kept else None
            _mark(cell, GREEN, 'УДАЛЕНЫ ЗАПРЕЩЁННЫЕ СВЯЗИ (проверенное моделирование).\n'
                  + 'Было: ' + original_text[:9000] + '\nУдалено: ' + '; '.join(sorted(refs))[:9000]
                  + '\nИсходный файл не изменён. Остальные связи сохранены.')
            count += 1
        book.properties.description = (f'Моделирование исправления: удалено направленных связей {len(removed_edges)}; '
                                        f'изменено ячеек Вход/Выход: {count}. Выделены светло-зелёным.')
        data = _xlsx_bytes(book)
    finally:
        book.close()

    # Independently verify that the exported XLSX is still importable and that
    # *only* the selected directed edges disappeared; no adjacent rows change.
    with TemporaryDirectory(prefix='verified-export-') as folder:
        output_path = Path(folder) / 'repaired.xlsx'
        output_path.write_bytes(data)
        reloaded = load_xlsx(output_path, state='verified-export')
        new_edges = {(e['source'], e['target']) for e in reloaded['edges']}
        if new_edges != original_edges - removed_edges or set(reloaded['nodes']) != set(graph['nodes']):
            raise ValueError('Контроль повторного импорта не пройден: были затронуты посторонние связи.')
    return data, {'edges': len(removed_edges), 'cells': count, 'mode': 'workbook_edges'}


def export_annotated_scenario_workbook(source_path, selected_actions):
    """Keep five source columns unchanged; annotate non-representable policy edits.

    The four-PC educational repair is about *policy facts*, not XLSX arrows.
    There is no truthful way to write those facts into the original five fields.
    Attach highly visible warning/comments instead of fabricating graph edits.
    """
    if not selected_actions:
        raise ValueError('Нет подтверждённых действий для экспорта.')
    book = load_workbook(source_path, keep_links=False)
    try:
        if len(book.worksheets) != 1:
            raise ValueError('Входной Excel должен содержать ровно один лист.')
        sheet = book.active
        details = []
        node_ids = set()
        for action in selected_actions:
            details.append(str(action.get('id', 'действие')) + ': ' + ', '.join(
                str(effect.get('predicate', '')) + '(' + ', '.join(map(str, effect.get('args', [])))
                    + ') = ' + str(effect.get('value'))
                for effect in action.get('effects', [])))
            for effect in action.get('effects', []):
                for item in effect.get('args', []):
                    if isinstance(item, str) and ':' in item:
                        node_ids.add(item)
        intro = ('ВНИМАНИЕ: модель исправлена только в демонстрационном профиле. '
                 'Пять исходных столбцов Excel не содержат полей для этих прав и настроек; '
                 'значения Вход/Выход НЕ ИЗМЕНЕНЫ. Чтобы повторный анализ подтвердил '
                 'исправления, необходимо задать эти факты в машинно-читаемой модели.\n\n'
                 'Моделируемые действия:\n' + '\n'.join(details))
        _mark(sheet['C1'], AMBER, intro)
        # Highlight source entities affected by action effects when their
        # globally unique PK:ID identifier is unambiguously present in rows.
        for row in sheet.iter_rows(min_row=2, max_col=3):
            scope, ident, cell = row
            if not isinstance(ident.value, int):
                continue
            scope_name = str(scope.value or '').strip()
            key = (scope_name.split()[1] + ':' + str(ident.value)) if scope_name.startswith('ПК ') else 'g:' + str(ident.value)
            if key in node_ids:
                _mark(cell, AMBER, 'Объект упомянут в плане исправления. Значения исходных связей не менялись.\n' + intro[:8000])
        book.properties.description = 'СЦЕНАРИЙ: исправления зафиксированы в комментариях, но НЕ выражены в исходных пяти столбцах.'
        return _xlsx_bytes(book), {'mode': 'annotations_only', 'actions': len(selected_actions)}
    finally:
        book.close()



def _declared_restoration_edges(before_model, repaired_model, restored_node, active_nodes):
    """Use ONLY historical, explicitly compared topology for a restored component.

    A `present=TRUE` fact by itself never implies a physical connection. The
    former edges must have been recorded in an explicit HTML -> XLSX comparison
    with closed inventory, and both endpoints must now be present.
    """
    comparison = before_model.get('comparison') or {}
    if comparison.get('mode') != 'html_baseline_xlsx_changed':
        return set()
    if not any(item.get('id') == 'xlsx_complete_inventory' and item.get('value') is True
               for item in comparison.get('assumptions', []) if isinstance(item, dict)):
        return set()
    if restored_node not in comparison.get('missing_in_xlsx', []):
        return set()
    from .model import FactBase
    facts = FactBase(repaired_model)
    declared = set()
    for record in comparison.get('only_html_edges', []):
        if not isinstance(record, (list, tuple)) or len(record) != 2:
            raise ValueError('Повреждены сведения о прежних связях компонента.')
        source, target = record
        if restored_node not in (source, target):
            continue
        if (source in active_nodes and target in active_nodes
                and facts.get('present', [source]) == 'TRUE'
                and facts.get('present', [target]) == 'TRUE'):
            declared.add((source, target))
    return declared


def _connection_reference(node_key, nodes, scoped_counts):
    """Use a non-ambiguous name accepted by the existing five-column importer."""
    node = nodes[node_key]
    name = node.get('name')
    pc = node.get('pc')
    if not isinstance(name, str) or not name.strip():
        raise ValueError('Невозможно экспортировать связь без имени компонента.')
    if pc is None:
        if name not in GLOBAL_NAMES:
            raise ValueError('Для общего компонента не указан однозначный идентификатор: ' + node_key)
        return name
    if scoped_counts[(pc, name)] != 1:
        raise ValueError('Для связи неоднозначно имя компонента ' + str(pc) + ': ' + name)
    return pc + ' / ' + name

def export_verified_model_workbook(source_path, before_model, repaired_model, *,
                                   mandate_result=None, description=''):
    """Unified XLSX export for all supported, independently verified repairs.

    Neither computer counts nor template names have any meaning here. We edit
    source-table rows only where a precise change is available; all non-tabular
    security facts and requirements round-trip in the structured extension.
    """
    from .security_workbook import (add_security_extension, read_security_extension,
                                    security_workbook_bytes)
    from .engine import analyze
    from .model import FactBase, validate_model

    if validate_model(repaired_model):
        raise ValueError('Исправленная модель содержит ошибки.')
    original_report, fixed_report = analyze(before_model), analyze(repaired_model)
    from .repair_validation import validate_repair, preserve_protected_resources
    targets = [r['id'] for r in original_report.get('results', []) if r.get('status') == 'FAIL']
    errors = validate_repair(original_report, fixed_report, targets)
    errors += preserve_protected_resources(before_model, repaired_model, targets)
    if errors or fixed_report.get('model_errors'):
        raise ValueError('Проверка модели после исправления не пройдена: ' + '; '.join(errors[:3]))
    if not targets:
        raise ValueError('В исходной модели нет подтверждённых нарушений.')

    changes = []
    if mandate_result is not None:
        binary, original_info = export_mandate_workbook(source_path, before_model, mandate_result)
        workbook = load_workbook(BytesIO(binary), keep_links=False)
        for target in mandate_result['targets']:
            transition = next(item for item in before_model['transitions'] if item['id'] == target)
            changes.append({'kind': 'Отключена запрещённая связь',
                            'object': transition['source'] + ' → ' + transition['target'],
                            'before': 'TRUE', 'after': 'FALSE', 'action': target})
    else:
        workbook = load_workbook(source_path, keep_links=False)
        original_info = {'cells': 0, 'edges': 0}

    try:
        if len(workbook.worksheets) != 1:
            raise ValueError('Для экспорта необходим один исходный лист.')
        sheet = workbook.active
        graph_before = before_model.get('source_graph') or load_xlsx(source_path)
        original_nodes = set(graph_before['nodes'])
        initial_facts = FactBase(before_model)
        final_facts = FactBase(repaired_model)
        added_rows = 0
        added_relation_cells = 0
        restored_edges = set()
        node_names = Counter((n.get('pc'), n.get('name')) for n in repaired_model['nodes'].values())
        active_nodes = set(graph_before['nodes']) | {
            d['args'][0] for d in repaired_model.get('diff', [])
            if d.get('predicate') == 'present' and d.get('after') == 'TRUE'
            and isinstance(d.get('args'), list) and len(d['args']) == 1
        }
        for diff in repaired_model.get('diff', []):
            predicate, args = diff.get('predicate'), diff.get('args', [])
            if predicate != 'present' or len(args) != 1 or diff.get('after') != 'TRUE':
                continue
            node_key = args[0]
            if node_key in original_nodes or node_key not in repaired_model.get('nodes', {}):
                continue
            # Adding a previously absent node is safe only if explicit verified
            # facts declare its presence. Never infer connectivity from its name.
            if initial_facts.get('present', [node_key]) != 'FALSE' or final_facts.get('present', [node_key]) != 'TRUE':
                raise ValueError('Недостаточно фактов для добавления компонента в Excel.')
            node = repaired_model['nodes'][node_key]
            node_id = node.get('id')
            node_pc = node.get('pc')
            node_name = node.get('name')
            if not isinstance(node_id, int) or not isinstance(node_name, str) or not node_name.strip():
                raise ValueError('Не задано корректное имя или ID восстановленного компонента.')
            # Preserve old XLSX naming conventions and only write known facts.
            scope_header = str(sheet.cell(1, 1).value or '').strip().casefold()
            if node_pc and not node_pc.startswith('ПК '):
                raise ValueError('Неизвестный формат ПК восстановленного компонента.')
            scope = node_pc or ('' if scope_header in {'пк', 'pc'} else node.get('cluster', ''))
            # Recover only explicitly documented old edges. A restored node
            # is not automatically wired to arbitrary neighbours by its name.
            historical_edges = _declared_restoration_edges(
                before_model, repaired_model, node_key, active_nodes)
            incoming = sorted(s for s, t in historical_edges if t == node_key)
            outgoing = sorted(t for s, t in historical_edges if s == node_key)
            incoming_text = ', '.join(_connection_reference(k, repaired_model['nodes'], node_names)
                                      for k in incoming)
            outgoing_text = ', '.join(_connection_reference(k, repaired_model['nodes'], node_names)
                                      for k in outgoing)
            if len(incoming_text) > 32000 or len(outgoing_text) > 32000:
                raise ValueError('Перечень восстановленных связей не помещается в ячейку Excel.')
            row = [scope, node_id, node_name, incoming_text or None, outgoing_text or None]
            sheet.append(row)
            new_cell = sheet.cell(sheet.max_row, 3)
            note = ('ВОССТАНОВЛЕН КОМПОНЕНТ (подтверждённая смена present=FALSE → TRUE).\n'
                    + (f'Его {len(historical_edges)} направленных связей перенесены из '
                       'явно сопоставленной исходной HTML-модели. ' if historical_edges else
                       'Подтверждённая исходная топология не задана; связи не создавались. ')
                    + 'Это моделирование, а не подтверждение настройки оборудования.')
            _mark(new_cell, GREEN, note)
            for cell in sheet[sheet.max_row]:
                cell.fill = GREEN
            for col in (4, 5):
                if sheet.cell(sheet.max_row, col).value:
                    _mark(sheet.cell(sheet.max_row, col), GREEN, note)
            added_relation_cells += bool(incoming_text) + bool(outgoing_text)
            restored_edges.update(historical_edges)
            for source, target in sorted(historical_edges):
                changes.append({'kind': 'Восстановлена связь по исходной модели',
                                'object': source + ' → ' + target,
                                'before': 'Отсутствовала в актуальном Excel',
                                'after': 'Восстановлена по HTML-модели',
                                'action': ', '.join(diff.get('actions', []))})
            changes.append({'kind': 'Восстановлен компонент', 'object': node_key + ' ' + node_name,
                            'before': 'Отсутствует', 'after': 'Присутствует',
                            'action': ', '.join(diff.get('actions', []))})
            original_nodes.add(node_key)
            added_rows += 1
        for diff in repaired_model.get('diff', []):
            if not isinstance(diff, dict) or 'predicate' not in diff:
                continue
            changes.append({'kind': 'Изменён параметр безопасности',
                            'object': diff['predicate'] + '(' + ', '.join(map(str, diff.get('args', []))) + ')',
                            'before': diff.get('before'), 'after': diff.get('after'),
                            'action': ', '.join(diff.get('actions', []))})

        # The serialized graph and visible first sheet MUST describe identical
        # node identities and structural edges on import.
        raw = security_workbook_bytes(workbook)
        with TemporaryDirectory(prefix='roundtrip-source-') as folder:
            temp = Path(folder) / 'raw.xlsx'
            temp.write_bytes(raw)
            graph_after = load_xlsx(temp, state='export-repaired-xlsx')

        # A verified restoration may re-resolve an old cell reference when
        # the target node reappears. Accept only the explicitly documented
        # historical edges in an HTML->XLSX comparison, never unrelated links.
        if restored_edges:
            edges_before = {(e['source'], e['target']) for e in graph_before['edges']}
            edges_after = {(e['source'], e['target']) for e in graph_after['edges']}
            if edges_after != edges_before | restored_edges:
                raise ValueError('Восстановленные связи не совпадают с заявленной исходной топологией.')

        changed_model = deepcopy(repaired_model)
        changed_model['source_graph'] = graph_after
        # No fabricated relations: the main worksheet is the independent
        # structural source, the extra sheets carry semantic facts.
        add_security_extension(workbook, changed_model, changes=changes,
                               source_description=description)
        payload = security_workbook_bytes(workbook)
    finally:
        workbook.close()

    with TemporaryDirectory(prefix='verify-security-workbook-') as folder:
        result_path = Path(folder) / 'verified.xlsx'
        result_path.write_bytes(payload)
        roundtrip_graph = load_xlsx(result_path, state='export-repaired-xlsx')
        recovered = read_security_extension(result_path, imported_graph=roundtrip_graph)
        from .model import validate_model
        if validate_model(recovered):
            raise ValueError('После повторного импорта модель стала противоречивой.')
        reread_analysis = analyze(recovered)
        original_statuses = {entry['id']: entry['status'] for entry in fixed_report['results']}
        replayed_statuses = {entry['id']: entry['status'] for entry in reread_analysis['results']}
        if original_statuses != replayed_statuses or reread_analysis.get('model_errors'):
            raise ValueError('Повторный анализ экспортированного Excel не воспроизводит исправления.')
        if {k for k, v in replayed_statuses.items() if v == 'FAIL'}:
            raise ValueError('В исправленном Excel остались подтверждённые нарушения.')
    return payload, {'mode': 'verified_roundtrip',
                     'cells': original_info.get('cells', 0) + added_relation_cells,
                     'edges': original_info.get('edges', 0), 'added_rows': added_rows,
                     'facts': len(repaired_model.get('diff', [])),
                     'changes': len(changes), 'restored_edges': len(restored_edges)}
