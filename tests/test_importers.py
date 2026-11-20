from copy import deepcopy
import json
from pathlib import Path
import random

from openpyxl import Workbook, load_workbook
import pytest

from analyzer.importers import ImportFormatError, compare_sources, load_html, load_xlsx

SOURCES = Path(__file__).resolve().parents[1] / "data" / "sources"
HTML = SOURCES / "graf-svyazey-pk.html"
XLSX = SOURCES / "Четыре_конфигурации_ПК_уязвим.xlsx"


@pytest.fixture(scope="module")
def imported():
    return load_html(HTML), load_xlsx(XLSX)


def edge_set(graph):
    return {(edge["source"], edge["target"]) for edge in graph["edges"]}


def write_sheet(path, rows):
    wb = Workbook()
    ws = wb.active
    ws.title = "Конфигурации ПК"
    ws.append(["ПК", "ID", "Сущность", "Вход", "Выход"])
    for row in rows:
        ws.append(row)
    wb.save(path)
    wb.close()


def test_supplied_import_sizes_and_discrepancies(imported):
    html, xlsx = imported
    comparison = compare_sources(html, xlsx)
    assert len(html["nodes"]) == 231
    assert len(html["edges"]) == 1100
    assert len(xlsx["nodes"]) == 229
    assert len(xlsx["edges"]) == 1088
    assert html["metadata"]["scope_counts"] == {"ПК 1": 53, "ПК 2": 57, "ПК 3": 59, "ПК 4": 56, "shared": 6}
    assert xlsx["metadata"]["scope_counts"] == {"ПК 1": 52, "ПК 2": 56, "ПК 3": 59, "ПК 4": 56, "shared": 6}
    assert comparison["missing_in_xlsx"] == ["1:59", "2:90"]
    assert comparison["missing_in_html"] == []
    assert comparison["common_edges_count"] == 1088
    assert len(comparison["only_html_edges"]) == 12
    assert comparison["only_xlsx_edges"] == []
    assert comparison["node_changes"] == []
    assert xlsx["metadata"]["row_count"] == 230
    assert xlsx["metadata"]["formula_count"] == 0
    assert xlsx["nodes"]["1:83"]["id"] == xlsx["nodes"]["2:83"]["id"]
    assert xlsx["nodes"]["1:83"] is not xlsx["nodes"]["2:83"]


def test_all_dangling_references_are_retained_without_reconstructing_rows(imported):
    html, xlsx = imported
    refs = compare_sources(html, xlsx)["unresolved_references"]
    actual = {(r["provenance"][0]["cell"], r["resolved_against_html"]) for r in refs}
    expected = {(cell, "1:59") for cell in ["D25", "E25", "D26", "E26", "D28", "E28", "D52", "E52"]}
    expected |= {("E54", "2:90"), ("D94", "2:90")}
    assert actual == expected
    assert "1:59" not in xlsx["nodes"] and "2:90" not in xlsx["nodes"]
    assert all(e["source"] in xlsx["nodes"] and e["target"] in xlsx["nodes"] for e in xlsx["edges"])


def test_administrator_ambiguity_never_expands_to_wildcard(imported):
    _, xlsx = imported
    ambiguous = [i for i in xlsx["issues"] if i["kind"] == "ambiguous_reference"]
    assert len(ambiguous) == 61
    assert {i["provenance"][0]["cell"] for i in ambiguous} == {"E230"}
    assert all(len(i["candidates"]) >= 2 for i in ambiguous)
    local_admin = [edge for edge in xlsx["edges"] if edge["source"] == "g:2" and not edge["target"].startswith("g:")]
    assert len(local_admin) == 223
    assert all({p["direction"] for p in edge["provenance"]} == {"incoming"} for edge in local_admin)
    assert all(all(p["cell"] != "E230" for p in edge["provenance"]) for edge in local_admin)
    assert all(not edge["symmetric_declaration"] for edge in local_admin)


def test_presence_requires_two_explicit_options(imported):
    html, xlsx = imported
    independent = compare_sources(html, xlsx)
    assert independent["mode"] == "independent_descriptions"
    assert independent["presence_changes"] == []
    uncertain = compare_sources(html, xlsx, as_states=True)
    assert {c["changed"] for c in uncertain["presence_changes"]} == {"UNKNOWN"}
    declared = compare_sources(html, xlsx, closed_inventory=True, as_states=True)
    assert {c["changed"] for c in declared["presence_changes"]} == {"FALSE"}
    assert declared["assumptions"][0]["value"] is True
    with pytest.raises(ValueError, match="as_states"):
        compare_sources(html, xlsx, closed_inventory=True)


def test_two_cell_declarations_merge_with_both_provenances(tmp_path):
    path = tmp_path / "simple.xlsx"
    write_sheet(path, [["ПК 1", 10, "A", None, "B"], ["ПК 1", 20, "B", "A", None]])
    graph = load_xlsx(path, state="before")
    assert edge_set(graph) == {("1:10", "1:20")}
    edge = graph["edges"][0]
    assert edge["symmetric_declaration"]
    assert {p["cell"] for p in edge["provenance"]} == {"E2", "D3"}
    assert all(p["state"] == "before" and p["kind"] == "imported" for p in edge["provenance"])
    assert graph["issues"] == []


def test_scope_resolution_qualified_local_and_shared_are_separate(tmp_path):
    path = tmp_path / "scope.xlsx"
    write_sheet(path, [
        ["ПК 1", 7, "Same", "Администратор", "ПК 2 / Same, Интернет"],
        ["ПК 2", 7, "Same", "ПК 1 / Same", "Same"],
        [None, 61, "Интернет", "ПК 1 / Same", None],
        [None, 2, "Администратор", None, "Same"],
    ])
    graph = load_xlsx(path)
    assert edge_set(graph) == {("g:2", "1:7"), ("1:7", "2:7"), ("1:7", "g:61"), ("2:7", "2:7")}
    assert graph["nodes"]["g:61"]["pc"] is None
    assert ("g:2", "2:7") not in edge_set(graph)
    assert any(i["kind"] == "ambiguous_reference" for i in graph["issues"])


def test_row_permutation_does_not_change_the_graph(imported, tmp_path):
    _, original = imported
    workbook = load_workbook(XLSX, read_only=True)
    rows = list(workbook.active.values)[1:]
    workbook.close()
    random.Random(31).shuffle(rows)
    path = tmp_path / "reordered.xlsx"
    write_sheet(path, rows)
    changed = load_xlsx(path)
    assert set(original["nodes"]) == set(changed["nodes"])
    assert edge_set(original) == edge_set(changed)
    assert original["metadata"]["issue_counts"] == changed["metadata"]["issue_counts"]
    assert {(k, n["pc"], n["name"]) for k, n in original["nodes"].items()} == {(k, n["pc"], n["name"]) for k, n in changed["nodes"].items()}


def test_html_is_parsed_as_data_and_accepts_consistent_key_renaming(imported, tmp_path):
    original, _ = imported
    data = deepcopy(original["raw_data"])
    names = {key: f"renamed-{i}" for i, key in enumerate(sorted(original["nodes"]))}
    for n in data["nodes"]:
        n["key"] = names[n["key"]]
    data["edges"] = [[names[a], names[b]] for a, b in data["edges"]]
    data["nodes"].reverse()
    data["edges"].reverse()
    path = tmp_path / "renamed.html"
    path.write_text('<script>throw new Error("Must never run");</script><script id="data" type="application/json">' + json.dumps(data) + '</script>', encoding="utf-8")
    graph = load_html(path)
    assert edge_set(graph) == {(names[a], names[b]) for a, b in edge_set(original)}
    assert set(graph["nodes"]) == set(names.values())


def test_unknown_blank_scope_and_formula_are_diagnosed(tmp_path):
    path = tmp_path / "bad.xlsx"
    write_sheet(path, [[None, 1, "Not registered as shared", None, None]])
    with pytest.raises(ImportFormatError, match="explicit shared-name registry"):
        load_xlsx(path)
    write_sheet(path, [["ПК 1", 1, "A", None, "=1+1"]])
    with pytest.raises(ImportFormatError, match="Formula cells"):
        load_xlsx(path)


def test_invalid_html_keys_and_dangling_edges_are_not_silently_accepted(tmp_path):
    path = tmp_path / "bad.html"
    data = {"pcs": [], "nodes": [{"key": "a", "id": 1, "pc": None, "name": "A"}],
            "edges": [["a", "missing"]], "layout": {}, "size": {}}
    path.write_text('<script id="data" type="application/json">' + json.dumps(data) + '</script>')
    graph = load_html(path)
    assert graph["edges"] == []
    assert graph["issues"][0]["kind"] == "dangling_edge"
    data["nodes"].append(dict(data["nodes"][0]))
    path.write_text('<script id="data" type="application/json">' + json.dumps(data) + '</script>')
    with pytest.raises(ImportFormatError, match="Duplicate"):
        load_html(path)


def rewrite_sheet_xml(path, transform):
    """Mutate only cached dimensions in a tiny workbook, never the real fixtures."""
    from zipfile import ZipFile, ZIP_DEFLATED
    with ZipFile(path) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    contents['xl/worksheets/sheet1.xml'] = transform(contents['xl/worksheets/sheet1.xml'].decode()).encode()
    with ZipFile(path, 'w', ZIP_DEFLATED) as archive:
        for name, value in contents.items():
            archive.writestr(name, value)


def write_streaming_sheet(path, rows, headers=None):
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet('Конфигурации ПК')
    sheet.append(headers or ['ПК', 'ID', 'Сущность', 'Вход', 'Выход'])
    for row in rows:
        sheet.append(row)
    workbook.save(path)
    workbook.close()


def test_dimensionless_write_only_workbook_is_read_from_actual_cells(tmp_path):
    path = tmp_path / 'streamed.xlsx'
    write_streaming_sheet(path, [['ПК 1', 1, 'A', None, 'B'], ['ПК 1', 2, 'B', 'A', None]])
    from zipfile import ZipFile
    with ZipFile(path) as archive:
        assert b'<dimension ' not in archive.read('xl/worksheets/sheet1.xml')
    graph = load_xlsx(path)
    assert set(graph['nodes']) == {'1:1', '1:2'}
    assert edge_set(graph) == {('1:1', '1:2')}
    assert graph['metadata']['row_count'] == 3
    assert {p['cell'] for p in graph['edges'][0]['provenance']} == {'E2', 'D3'}


@pytest.mark.parametrize('dimension', ['A1:A1', 'A1:C2', 'A1:XFD1048576'])
def test_inaccurate_dimensions_neither_truncate_nor_inflate_actual_inventory(tmp_path, dimension):
    import re
    path = tmp_path / 'stale.xlsx'
    write_sheet(path, [['ПК 1', 1, 'A', None, 'B'], ['ПК 1', 2, 'B', 'A', None]])
    rewrite_sheet_xml(path, lambda xml: re.sub(r'<dimension\b[^>]*/>', f'<dimension ref="{dimension}"/>', xml))
    graph = load_xlsx(path)
    assert graph['metadata']['node_count'] == 2
    assert graph['metadata']['row_count'] == 3
    assert edge_set(graph) == {('1:1', '1:2')}


@pytest.mark.parametrize('extra', ['unexpected value', '=1+1'])
def test_populated_or_formula_column_outside_cached_dimension_is_rejected(tmp_path, extra):
    import re
    path = tmp_path / 'hidden-extra.xlsx'
    write_sheet(path, [['ПК 1', 1, 'A', None, None, extra]])
    rewrite_sheet_xml(path, lambda xml: re.sub(r'<dimension\b[^>]*/>', '<dimension ref="A1:A1"/>', xml))
    with pytest.raises(ImportFormatError, match='F2'):
        load_xlsx(path)


def test_dimensionless_formula_is_not_treated_as_a_cached_value(tmp_path):
    path = tmp_path / 'formula.xlsx'
    write_streaming_sheet(path, [['ПК 1', 1, 'A', None, '=1+1']])
    with pytest.raises(ImportFormatError, match='E2.*Formula'):
        load_xlsx(path)


def test_blank_rows_do_not_inherit_scope_or_break_coordinates(tmp_path):
    path = tmp_path / 'blanks.xlsx'
    write_streaming_sheet(path, [[None] * 5, ['ПК 9', 4, 'A', None, None], [None] * 5])
    graph = load_xlsx(path)
    assert graph['metadata']['row_count'] == 4
    assert graph['metadata']['object_rows'] == 1
    assert list(graph['nodes']) == ['9:4']
    assert graph['nodes']['9:4']['field_provenance']['name'][0]['cell'] == 'C3'


def test_style_only_extra_columns_are_not_phantom_data(tmp_path):
    path = tmp_path / 'styled.xlsx'
    write_sheet(path, [['ПК 1', 1, 'A', None, None]])
    workbook = load_workbook(path)
    workbook.active['XFD2'].number_format = '0.00'
    workbook.save(path)
    workbook.close()
    graph = load_xlsx(path)
    assert graph['metadata']['object_rows'] == 1
    assert graph['metadata']['row_count'] == 2


def test_actual_row_limit_applies_even_when_cached_extent_is_small(tmp_path):
    import re
    path = tmp_path / 'far-row.xlsx'
    write_sheet(path, [['ПК 1', 1, 'A', None, None]])
    workbook = load_workbook(path)
    workbook.active['A10002'] = 'ПК 2'
    workbook.save(path)
    workbook.close()
    rewrite_sheet_xml(path, lambda xml: re.sub(r'<dimension\b[^>]*/>', '<dimension ref="A1:A1"/>', xml))
    with pytest.raises(ImportFormatError, match='10002.*exceeds'):
        load_xlsx(path)


def test_cluster_column_keeps_scoped_keys_and_resolves_only_declared_registry(tmp_path):
    from urllib.parse import quote
    path = tmp_path / 'clusters.xlsx'
    write_streaming_sheet(path, [
        ['ПК 1', 1, 'A', None, 'Service, Ops / Service, Shared, ПК 2 / A, Storage / zone / Shared'],
        ['ПК 1', 2, 'Service', None, None],
        ['ПК 2', 1, 'A', None, 'Service'],
        ['Ops', 2, 'Service', None, 'A'],
        ['Storage / zone', 2, 'Shared', None, None],
        ['Admin', 2, 'Shared', None, None],
    ], headers=['Кластер', 'ID', 'Сущность', 'Вход', 'Выход'])
    graph = load_xlsx(path)
    ops = 'c:Ops:2'
    storage = 'c:' + quote('Storage / zone', safe='') + ':2'
    assert len(graph['nodes']) == 6
    assert graph['nodes'][ops]['pc'] is None and graph['nodes'][ops]['cluster'] == 'Ops'
    assert ('1:1', '1:2') in edge_set(graph)  # Local name wins over shared registry.
    assert ('1:1', ops) in edge_set(graph)  # Explicitly qualified cluster.
    assert ('2:1', ops) in edge_set(graph)  # Unique declared non-PC registry match.
    assert ('1:1', storage) in edge_set(graph)
    assert (ops, '1:1') not in edge_set(graph) and (ops, '2:1') not in edge_set(graph)
    ambiguity = [i for i in graph['issues'] if i['kind'] == 'ambiguous_reference']
    assert {i['reference'] for i in ambiguity} == {'Shared', 'A'}
    assert graph['metadata']['headers'][0] == 'Кластер'
    assert graph['metadata']['row_count'] == 7


def test_pc_reference_does_not_fall_back_to_another_pc_in_cluster_sheet(tmp_path):
    path = tmp_path / 'local-only.xlsx'
    write_streaming_sheet(path, [
        ['ПК 1', 1, 'A', None, 'Absent locally'],
        ['ПК 2', 2, 'Absent locally', None, None],
        ['shared', 1, 'Named group entry', None, 'Named group entry'],
    ], headers=['Кластер', 'ID', 'Сущность', 'Вход', 'Выход'])
    graph = load_xlsx(path)
    assert ('1:1', '2:2') not in edge_set(graph)
    assert any(i['kind'] == 'unresolved_reference' and i['reference_scope'] == 'ПК 1' for i in graph['issues'])
    assert ('c:shared:1', 'c:shared:1') in edge_set(graph)


def test_malformed_tail_xml_is_a_diagnosed_import_error(tmp_path):
    path = tmp_path / 'malformed.xlsx'
    write_sheet(path, [['ПК 1', 1, 'A', None, None]])
    # Workbook metadata and the initial dimension remain readable; corruption
    # occurs in the sheet content that our complete XML preflight must inspect.
    rewrite_sheet_xml(path, lambda xml: xml.replace('</sheetData>', '</sheetDataBROKEN>'))
    with pytest.raises(ImportFormatError, match='malformed worksheet XML'):
        load_xlsx(path)
