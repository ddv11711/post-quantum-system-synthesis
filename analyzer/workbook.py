"""Bounded worksheet reads independent of optional/stale XLSX dimensions.

The pinned openpyxl read-only worksheet exposes its XML stream via
``_get_source``. A streaming preflight checks actual cells before a bounded
openpyxl read, so neither false cached dimensions nor a distant cell can hide
unexpected columns or cause allocation of a huge padded worksheet.
"""
from xml.etree.ElementTree import ParseError, iterparse

from openpyxl.utils.cell import coordinate_to_tuple, get_column_letter


class WorkbookFormatError(ValueError):
    """Actual worksheet content does not fit the requested tabular schema."""


def read_bounded_rows(sheet, *, max_rows, max_columns):
    """Return actual rows, preserving gaps and trimming trailing empty cells.

    Limits apply to real XML coordinates, never ``max_row/max_column`` caches.
    Formula cells anywhere are rejected, including outside a misleading cached
    dimension. Blank styled cells beyond the allowed columns are harmless.
    Returned openpyxl cells retain coordinates; callers can pad missing columns
    if their schema has a fixed width. The workbook must use read_only=True and
    data_only=False. Empty rows are empty tuples, not inherited values.
    """
    if max_rows < 1 or max_columns < 1:
        raise ValueError('Worksheet limits must be positive')
    actual_last_row = 0
    current_row, current_column = 0, 0
    try:
        with sheet._get_source() as source:
            for event, element in iterparse(source, events=('start', 'end')):
                name = element.tag.rsplit('}', 1)[-1]
                if event == 'start' and name == 'row':
                    try:
                        current_row = int(element.get('r', current_row + 1))
                    except (TypeError, ValueError) as exc:
                        raise WorkbookFormatError(f'{sheet.title}: invalid row coordinate') from exc
                    current_column = 0
                    if not 1 <= current_row <= max_rows:
                        raise WorkbookFormatError(f'{sheet.title}: row {current_row} exceeds allowed rows 1:{max_rows}')
                    actual_last_row = max(actual_last_row, current_row)
                if event != 'end':
                    continue
                if name == 'c':
                    address = element.get('r')
                    if address:
                        try:
                            row, column = coordinate_to_tuple(address)
                        except (ValueError, TypeError) as exc:
                            raise WorkbookFormatError(f'{sheet.title}: invalid cell coordinate {address!r}') from exc
                    else:
                        row, column = current_row, current_column + 1
                        address = f'{get_column_letter(column)}{row}'
                    current_column = column
                    if not 1 <= row <= max_rows:
                        raise WorkbookFormatError(f'{sheet.title}!{address}: exceeds allowed rows 1:{max_rows}')
                    actual_last_row = max(actual_last_row, row)
                    children = {child.tag.rsplit('}', 1)[-1]: child for child in element}
                    if 'f' in children:
                        raise WorkbookFormatError(f'{sheet.title}!{address}: Formula cells are unsupported')
                    value = children.get('v')
                    inline = children.get('is')
                    populated = (value is not None and value.text not in (None, '')) or (
                        inline is not None and any(t.text not in (None, '') for t in inline.iter()
                                                  if t.tag.rsplit('}', 1)[-1] == 't'))
                    if populated and column > max_columns:
                        raise WorkbookFormatError(f'{sheet.title}!{address}: populated cell outside allowed columns A:{get_column_letter(max_columns)}')
                    element.clear()
                elif name == 'row':
                    element.clear()
    except ParseError as exc:
        raise WorkbookFormatError(f"{sheet.title}: malformed worksheet XML") from exc
    if not actual_last_row:
        return []
    sheet.reset_dimensions()
    rows = []
    iterator = sheet.iter_rows(min_row=1, min_col=1, max_row=actual_last_row, max_col=max_columns)
    try:
        for cells in iterator:
            values = list(cells)
            while values and values[-1].value in (None, ''):
                values.pop()
            rows.append(tuple(values))
    finally:
        iterator.close()
    # Read-only iteration may omit trailing explicitly empty XML rows.
    rows.extend([()] * (actual_last_row - len(rows)))
    return rows
