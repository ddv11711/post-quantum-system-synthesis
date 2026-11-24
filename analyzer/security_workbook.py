"""Versioned, round-trippable security extensions for five-column system XLSX.

The five-column graph stays the first sheet. Structured policy facts are saved as
an explicit, parseable semantic snapshot, never inferred from component names.
No workbook can claim a verified repair merely because cells were coloured.
"""
import base64
from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import zlib

from openpyxl import load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .excel_columns import resolve_columns
from .workbook import read_bounded_rows

SHEET_PARAMETERS = 'Параметры безопасности'
SHEET_REQUIREMENTS = 'Требования безопасности'
SHEET_CHANGES = 'История изменений'
SHEET_MODEL = 'Модель анализатора'
EXTENSION_SHEETS = (SHEET_PARAMETERS, SHEET_REQUIREMENTS, SHEET_CHANGES, SHEET_MODEL)
MARKER = 'SECURITY_MODEL_XLSX_V1'
MAX_MODEL_BYTES = 60 * 1024 * 1024
MAX_PAYLOAD_CHARS = 12 * 1024 * 1024
CHUNK_SIZE = 24000


def _json_bytes(item):
    return json.dumps(item, ensure_ascii=False, separators=(',', ':'), sort_keys=True,
                      allow_nan=False).encode('utf-8')


def _tabular_digest(sheet):
    """Bind semantic model to *actual* first five-column workbook contents."""
    if hasattr(sheet, '_get_source'):
        rows = read_bounded_rows(sheet, max_rows=10001, max_columns=5)
    else:
        if sheet.max_row > 10001:
            raise ValueError('Слишком много строк в таблице компонентов.')
        if any(cell.value is not None for row in sheet.iter_rows(min_col=6) for cell in row):
            raise ValueError('В исходной таблице есть данные вне пяти столбцов.')
        rows = list(sheet.iter_rows(min_row=1, max_col=5))
        if any(cell.data_type == 'f' for row in rows for cell in row):
            raise ValueError('Формулы не допускаются в таблице компонентов.')
    if not rows:
        raise ValueError('В Excel отсутствует таблица компонентов.')
    headers = [cell.value for cell in rows[0]]
    order = resolve_columns(headers)
    records = []
    for row in rows:
        records.append([(None if row[i].value == '' else row[i].value) if i < len(row) else None for i in order])
    return sha256(_json_bytes(records)).hexdigest()


def has_security_extension(path):
    workbook = load_workbook(path, read_only=True, data_only=False)
    try:
        return SHEET_MODEL in workbook.sheetnames
    finally:
        workbook.close()


def _text(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    text = '' if value is None else str(value)
    # Never let user-supplied node names or rule IDs turn into Excel formulas.
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def _record(sheet, values):
    sheet.append([_text(item) for item in values])


def _human_digest(workbook):
    sections = []
    for name in EXTENSION_SHEETS[:3]:
        sheet = workbook[name]
        if sheet.max_row > 25000 or sheet.max_column > 6:
            raise ValueError('Нарушены ограничения служебных листов Excel.')
        rows = []
        for row in sheet.iter_rows(values_only=True):
            rows.append([None if value == '' else value for value in row])
        sections.append((name, rows))
    return sha256(_json_bytes(sections)).hexdigest()


def _style_sheet(sheet, widths, green=False):
    dark = PatternFill('solid', fgColor='242424')
    light = PatternFill('solid', fgColor='E7F5EB' if green else 'EFEFEF')
    for cell in sheet[1]:
        cell.fill = dark
        cell.font = Font(color='FFFFFF', bold=True)
        cell.alignment = Alignment(wrap_text=True, vertical='center')
    sheet.row_dimensions[1].height = 30
    sheet.freeze_panes = 'A2'
    sheet.auto_filter.ref = sheet.dimensions
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            if cell.value is not None:
                cell.alignment = Alignment(wrap_text=True, vertical='top')
                if green:
                    cell.fill = light
    sheet.sheet_view.showGridLines = False


def add_security_extension(workbook, model, *, changes, source_description=''):
    """Write machine-readable facts AND transparent human-readable delta tables."""
    if len(workbook.worksheets) != 1:
        raise ValueError('Исходный Excel должен содержать один лист конфигурации.')
    source_digest = _tabular_digest(workbook.active)
    model = deepcopy(model)
    if not isinstance(model, dict) or not isinstance(model.get('nodes'), dict):
        raise ValueError('Отсутствует проверенная модель для экспорта.')

    parameters = workbook.create_sheet(SHEET_PARAMETERS)
    _record(parameters, ('Объект / аргументы', 'Параметр', 'До', 'После', 'Действия'))
    for entry in model.get('diff', []):
        if not isinstance(entry, dict) or 'predicate' not in entry:
            continue
        _record(parameters, (_text(entry.get('args', [])), entry['predicate'],
                             entry.get('before'), entry.get('after'), entry.get('actions', [])))
    if parameters.max_row == 1:
        _record(parameters, ('—', 'Изменения фактов отсутствуют', '', '', ''))
    _style_sheet(parameters, (35, 27, 22, 22, 42), green=True)

    requirements = workbook.create_sheet(SHEET_REQUIREMENTS)
    _record(requirements, ('ID требования', 'Название', 'Проверка', 'Основание'))
    for item in model.get('requirements', []):
        _record(requirements, (item.get('id'), item.get('name'), item.get('checker'),
                               item.get('scenario') or item.get('subject') or ''))
    if requirements.max_row == 1:
        _record(requirements, ('—', 'Формализованные требования не заданы', '', ''))
    _style_sheet(requirements, (35, 62, 27, 42))

    history = workbook.create_sheet(SHEET_CHANGES)
    _record(history, ('№', 'Тип изменения', 'Объект', 'Было', 'Стало', 'Источник / действие'))
    for index, item in enumerate(changes, start=1):
        _record(history, (index, item.get('kind', ''), item.get('object', ''),
                          item.get('before', ''), item.get('after', ''),
                          item.get('action', '')))
    if history.max_row == 1:
        _record(history, ('—', 'Изменения структуры отсутствуют', '', '', '', ''))
    _style_sheet(history, (8, 30, 38, 42, 42, 52), green=True)

    payload_bytes = _json_bytes(model)
    if len(payload_bytes) > MAX_MODEL_BYTES:
        raise ValueError('Модель слишком велика для безопасного XLSX-экспорта.')
    compressed = zlib.compress(payload_bytes, level=6)
    payload = base64.b64encode(compressed).decode('ascii')
    if len(payload) > MAX_PAYLOAD_CHARS:
        raise ValueError('Слишком большой объём машинно-читаемых данных.')
    data = workbook.create_sheet(SHEET_MODEL)
    data.append(('Формат', MARKER))
    data.append(('Версия', 1))
    data.append(('Контрольная сумма таблицы', source_digest))
    data.append(('Контрольная сумма модели', sha256(payload_bytes).hexdigest()))
    data.append(('Число байт модели', len(payload_bytes)))
    data.append(('Число фрагментов', (len(payload) + CHUNK_SIZE - 1) // CHUNK_SIZE))
    data.append(('Источник', source_description[:300]))
    data.append(('Контрольная сумма листов', _human_digest(workbook)))
    data.append(('Фрагмент', 'Сжатая модель JSON (Base64 + zlib)'))
    for offset in range(0, len(payload), CHUNK_SIZE):
        data.append((offset // CHUNK_SIZE + 1, payload[offset:offset + CHUNK_SIZE]))
    data.sheet_state = 'hidden'
    # Don't hide the edit history: the user's five columns remain readable.
    return len(changes)


def read_security_extension(path, *, imported_graph=None):
    """Rebuild semantic inputs from XLSX and reject stale or corrupted snapshots.

    A hash is a *consistency check*, not proof of authenticity. The imported
    workbook is always user-provided and the analyzer recomputes every finding.
    """
    workbook = load_workbook(path, read_only=True, data_only=False)
    try:
        names = workbook.sheetnames
        if len(names) == 1:
            return None
        if names[1:] != list(EXTENSION_SHEETS):
            raise ValueError('Неверный состав листов расширенного Excel.')
        sheet = workbook[SHEET_MODEL]
        machine_rows = read_bounded_rows(sheet,
                                         max_rows=MAX_PAYLOAD_CHARS // CHUNK_SIZE + 10,
                                         max_columns=2)
        def val(row, col):
            record = machine_rows[row - 1] if row <= len(machine_rows) else ()
            return record[col - 1].value if col <= len(record) else None
        if (val(1, 2) != MARKER or val(2, 2) != 1):
            raise ValueError('Неизвестная версия модели безопасности в Excel.')
        if val(3, 2) != _tabular_digest(workbook.worksheets[0]):
            raise ValueError('Основная таблица была изменена после формирования модели. Повторите анализ из исходных данных.')
        if val(8, 2) != _human_digest(workbook):
            raise ValueError('Листы параметров или изменений не соответствуют сохранённой модели.')
        count = val(6, 2)
        size = val(5, 2)
        if (not isinstance(count, int) or not 1 <= count <= MAX_PAYLOAD_CHARS // CHUNK_SIZE + 1
                or not isinstance(size, int) or not 1 <= size <= MAX_MODEL_BYTES):
            raise ValueError('Недопустимый размер модели безопасности.')
        chunks = []
        for index in range(1, count + 1):
            part = val(9 + index, 2)
            if (val(9 + index, 1) != index or not isinstance(part, str)
                    or len(part) > CHUNK_SIZE or not part):
                raise ValueError('Повреждён фрагмент модели безопасности.')
            chunks.append(part)
        payload = ''.join(chunks)
        if len(payload) > MAX_PAYLOAD_CHARS:
            raise ValueError('Слишком большой объём модели безопасности.')
        try:
            compressed = base64.b64decode(payload, validate=True)
            decoder = zlib.decompressobj()
            raw = decoder.decompress(compressed, MAX_MODEL_BYTES + 1)
            if not decoder.eof or decoder.unconsumed_tail or len(raw) != size or len(raw) > MAX_MODEL_BYTES:
                raise ValueError('Размер распакованной модели не совпадает.')
            if sha256(raw).hexdigest() != val(4, 2):
                raise ValueError('Контрольная сумма модели не совпадает.')
            model = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeError, zlib.error, json.JSONDecodeError) as exc:
            raise ValueError('Не удалось проверить машинно-читаемую модель Excel.') from exc
        if not isinstance(model, dict) or not isinstance(model.get('source_graph'), dict):
            raise ValueError('Модель не содержит исходный граф.')
        if imported_graph is not None:
            expected = model['source_graph']
            def edges(graph):
                return {(e['source'], e['target']) for e in graph['edges']}
            if set(imported_graph['nodes']) != set(expected.get('nodes', [])) or edges(imported_graph) != edges(expected):
                raise ValueError('Структура графа в модели и таблице Excel не совпадает.')
        # Keep the current source file name/provenance for graph rendering;
        # the policy facts and verified corrections came from the extension.
        if imported_graph is not None:
            model['source_graph'] = imported_graph
        # Human-readable sheets are checksummed notes, not extra executable rules.
        return model
    finally:
        workbook.close()


def security_workbook_bytes(workbook):
    with BytesIO() as content:
        workbook.save(content)
        return content.getvalue()
