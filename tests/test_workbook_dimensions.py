"""Worksheet dimensions are optional metadata, never a source of lost cells."""
from io import BytesIO
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from openpyxl import Workbook
import pytest

from analyzer.engine import analyze
from analyzer.portable import load_portable
from analyzer.portable_files import load_portable_workbook, portable_workbook

NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'


def dimensions(content, ref):
    output = BytesIO()
    with ZipFile(BytesIO(content)) as source, ZipFile(output, 'w') as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.startswith('xl/worksheets/sheet') and item.filename.endswith('.xml'):
                sheet = ET.fromstring(data)
                for node in list(sheet.findall(NS + 'dimension')):
                    sheet.remove(node)
                if ref is not None:
                    sheet.insert(0, ET.Element(NS + 'dimension', ref=ref))
                data = ET.tostring(sheet, encoding='utf-8', xml_declaration=True)
            target.writestr(item, data)
    return output.getvalue()


@pytest.mark.parametrize('ref', [None, 'A1:A1', 'A1:XFD1048576'])
def test_portable_import_uses_actual_rows_even_with_missing_or_stale_dimensions(tmp_path, ref):
    original = json.loads((Path(__file__).resolve().parents[1] / 'examples/portable/fls_clusters.json').read_text())
    path = tmp_path / 'dimensions.xlsx'
    path.write_bytes(dimensions(portable_workbook(original), ref))
    actual = load_portable(load_portable_workbook(path))
    expected = load_portable(original)
    assert set(actual['nodes']) == set(expected['nodes'])
    assert [(c['id'], c['layers'], c['protection_via']) for c in actual['fls_channels']] == [
        (c['id'], c['layers'], c['protection_via']) for c in expected['fls_channels']]
    assert analyze(actual)['summary'] == analyze(expected)['summary'] == {'FAIL': 5, 'PASS': 4}


def test_write_only_workbook_without_dimension_imports_all_nodes_and_relationships(tmp_path):
    book = Workbook(write_only=True)
    nodes = book.create_sheet('Nodes'); nodes.append(['id', 'name', 'type'])
    nodes.append(['a', 'Первый', 'subject']); nodes.append(['b', 'Второй', 'data'])
    edges = book.create_sheet('Edges'); edges.append(['id', 'source', 'target', 'type', 'attributes'])
    edges.append(['pair', 'a', 'b', 'interaction', json.dumps({'layers': {'physical': True, 'syntactic': False}})])
    path = tmp_path / 'streamed.xlsx'; book.save(path); book.close()
    model = load_portable(load_portable_workbook(path))
    assert set(model['nodes']) == {'a', 'b'}
    assert model['fls_channels'][0]['layers'] == {'physical': 'TRUE', 'syntactic': 'FALSE', 'semantic': 'UNKNOWN'}


@pytest.mark.parametrize('extra', ['hidden data', '=1+1'])
def test_bad_dimensions_cannot_hide_values_or_formulas_beyond_header(tmp_path, extra):
    book = Workbook(); nodes = book.active; nodes.title = 'Nodes'
    nodes.append(['id', 'type']); nodes.append(['a', 'subject', extra])
    stream = BytesIO(); book.save(stream); book.close()
    path = tmp_path / 'hidden.xlsx'; path.write_bytes(dimensions(stream.getvalue(), 'A1:B2'))
    with pytest.raises(ValueError):
        load_portable_workbook(path)


def test_actual_row_limit_is_enforced_despite_tiny_cached_dimension(tmp_path):
    book = Workbook(); nodes = book.active; nodes.title = 'Nodes'
    nodes.append(['id', 'type']); nodes.cell(5002, 1, 'outside-limit')
    stream = BytesIO(); book.save(stream); book.close()
    path = tmp_path / 'large.xlsx'; path.write_bytes(dimensions(stream.getvalue(), 'A1:B1'))
    with pytest.raises(ValueError, match='5002'):
        load_portable_workbook(path)
