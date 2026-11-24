"""Import the supplied structural graph as data, never as access permissions.

Imports are independent, loss-aware descriptions.  No HTML script is executed,
no missing spreadsheet row is synthesised, and no unqualified shared-row
reference expands to a wildcard.  Every accepted declaration retains evidence.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import quote

from .workbook import WorkbookFormatError, read_bounded_rows
from .excel_columns import resolve_columns


# This is an explicit vocabulary for shared scope, not an ID-to-security-type map.
GLOBAL_NAMES = frozenset({
    "Интернет", "VPN-сервер", "Общая локальная сеть", "Общий принтер",
    "Сетевой диск (NAS)", "Администратор",
})
HEADERS = ("ПК", "ID", "Сущность", "Вход", "Выход")


class ImportFormatError(ValueError):
    """The file cannot be interpreted under the declared input schema."""


class _DataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.active = False
        self.parts: list[str] = []
        self.count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs = dict(attrs)
        if tag == "script" and attrs.get("id") == "data":
            if attrs.get("type") != "application/json":
                raise ImportFormatError("script#data must have type application/json")
            self.active = True
            self.count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.active = False

    def handle_data(self, data: str) -> None:
        if self.active:
            self.parts.append(data)


def _evidence(path: Path, state: str, raw: Any, transformation: str, **location: Any) -> dict:
    return {"file": str(path), "state": state, "raw_value": raw,
            "transformation": transformation, "kind": "imported", **location}


def _normalise_name(value: Any) -> str:
    # No case folding or ё/е collapsing: distinct source names stay distinct.
    return " ".join(str(value).split()) if value is not None else ""


def _metadata(path: Path, nodes: dict, edges: list, state: str, **extra: Any) -> dict:
    return {"file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "state": state, "node_count": len(nodes), "edge_count": len(edges),
            "scope_counts": dict(sorted(Counter(n["pc"] or "shared" for n in nodes.values()).items())),
            "security_semantics": "untyped structural declarations; no ACL or operation inferred",
            "complete_relations": [], **extra}


def load_html(path: str | Path, state: str = "html") -> dict:
    """Parse exactly one JSON script#data and preserve all directed declarations."""
    path = Path(path)
    parser = _DataParser()
    parser.feed(path.read_text(encoding="utf-8-sig"))
    if parser.count != 1:
        raise ImportFormatError(f"Expected one application/json script#data, found {parser.count}")
    try:
        data = json.loads("".join(parser.parts))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ImportFormatError(f"Invalid embedded JSON: {exc}") from exc
    required = {"pcs", "nodes", "edges", "layout", "size"}
    if not isinstance(data, dict) or not required <= data.keys():
        raise ImportFormatError("HTML data requires pcs, nodes, edges, layout, size")
    if not isinstance(data["nodes"], list) or not isinstance(data["edges"], list):
        raise ImportFormatError("nodes and edges must be arrays")
    nodes: dict[str, dict] = {}
    for i, record in enumerate(data["nodes"]):
        if not isinstance(record, dict) or not {"key", "id", "pc", "name"} <= record.keys():
            raise ImportFormatError(f"Invalid node at nodes[{i}]")
        key = record["key"]
        if not isinstance(key, str) or not key or key in nodes:
            raise ImportFormatError(f"Duplicate or invalid node key: {key!r}")
        if not isinstance(record["id"], int) or isinstance(record["id"], bool):
            raise ImportFormatError(f"Node {key}: id must be integer")
        if not isinstance(record["name"], str) or not record["name"].strip():
            raise ImportFormatError(f"Node {key}: name must be nonempty string")
        if record["pc"] is not None and not isinstance(record["pc"], str):
            raise ImportFormatError(f"Node {key}: pc must be string or null")
        node = deepcopy(record)
        node["provenance"] = [_evidence(path, state, record, "copy node record; retain globally unique key", json_key=f"$.nodes[{i}]")]
        node["field_provenance"] = {
            field: [_evidence(path, state, record[field], "identity", json_key=f"$.nodes[{i}].{field}")]
            for field in ("key", "id", "pc", "name")
        }
        nodes[key] = node
    merged: dict[tuple[str, str], list] = defaultdict(list)
    issues = []
    for i, edge in enumerate(data["edges"]):
        if not isinstance(edge, list) or len(edge) != 2 or not all(isinstance(k, str) for k in edge):
            raise ImportFormatError(f"Invalid directed edge at edges[{i}]")
        source, target = edge
        provenance = _evidence(path, state, edge, "directed source → target", json_key=f"$.edges[{i}]")
        if source not in nodes or target not in nodes:
            issues.append({"kind": "dangling_edge", "source": source, "target": target,
                           "provenance": [provenance]})
            continue
        merged[(source, target)].append(provenance)
    edges = [{"source": source, "target": target, "provenance": declarations}
             for (source, target), declarations in sorted(merged.items())]
    nodes = dict(sorted(nodes.items()))
    return {"schema_version": 1, "state": state, "format": "html", "nodes": nodes,
            "edges": edges, "issues": issues, "raw_data": data,
            "metadata": _metadata(path, nodes, edges, state, pcs=data["pcs"],
                                  declared_edge_count=len(data["edges"]),
                                  top_level_keys=sorted(data))}


def _scope(pc: Any, name: str, global_names: frozenset[str]) -> str | None:
    text = _normalise_name(pc)
    if not text:
        if name not in global_names:
            raise ImportFormatError(f"Blank ПК for {name!r}; add it to an explicit shared-name registry")
        return None
    if not re.fullmatch(r"ПК [1-9]\d*", text):
        raise ImportFormatError(f"Invalid ПК scope: {pc!r}")
    return text


def _references(value: Any) -> Iterable[str]:
    if value is None or not str(value).strip():
        return []
    return [_normalise_name(part) for part in str(value).split(",") if part.strip()]


def _resolve(reference: str, pc: str | None, by_name: dict, by_scope: dict,
             global_names: frozenset[str]) -> tuple[list[str], str, str | None, str]:
    match = re.fullmatch(r"(ПК [1-9]\d*)\s*/\s*(.+)", reference)
    if match:
        scope, name = match.groups()
        return sorted(by_scope.get((scope, name), [])), "qualified", scope, name
    if reference in global_names:
        return sorted(by_scope.get((None, reference), [])), "explicit_global_registry", None, reference
    if pc is not None:
        return sorted(by_scope.get((pc, reference), [])), "local_scope", pc, reference
    # A shared row has no implicit PC. Even a unique local match needs explicit qualification.
    return sorted(by_name.get(reference, [])), "unqualified_shared_reference", None, reference


def _resolve_cluster(reference, scope, by_name, by_scope, shared_registry, qualified_scopes):
    """Cluster-sheet references use declared scopes, never a global PC wildcard."""
    for candidate_scope in qualified_scopes:
        prefix = candidate_scope + " / "
        if reference.startswith(prefix):
            name = reference[len(prefix):]
            return sorted(by_scope.get((candidate_scope, name), [])), "qualified", candidate_scope, name
    match = re.fullmatch(r"(ПК [1-9]\d*)\s*/\s*(.+)", reference)
    if match:
        target_scope, name = match.groups()
        return sorted(by_scope.get((target_scope, name), [])), "qualified", target_scope, name
    local = sorted(by_scope.get((scope, reference), []))
    if local:
        return local, "local_cluster", scope, reference
    if reference in shared_registry:
        return sorted(shared_registry[reference]), "declared_non_pc_registry", None, reference
    if scope is not None and re.fullmatch(r"ПК [1-9]\d*", scope):
        return [], "local_scope", scope, reference
    candidates = sorted(by_name.get(reference, []))
    return candidates, "unqualified_shared_reference" if candidates else "unresolved_cluster_reference", None, reference


def load_xlsx(path: str | Path, state: str = "xlsx", *,
              global_names: Iterable[str] = GLOBAL_NAMES) -> dict:
    """Read rows independently; merge incoming/outgoing declarations with provenance.

    Formula cells are rejected rather than accepted as cached values. Unknown
    scopes and duplicate keys are schema errors; unresolved references are retained
    as issues and never create nodes or edges.
    """
    from openpyxl import load_workbook
    from openpyxl.cell.read_only import EMPTY_CELL, ReadOnlyCell

    path = Path(path)
    global_names = frozenset(global_names)
    workbook = load_workbook(path, read_only=True, data_only=False)
    try:
        # Workbook names are presentation details, not a semantic constraint.
        if len(workbook.sheetnames) != 1:
            from .security_workbook import EXTENSION_SHEETS
            if workbook.sheetnames[1:] != list(EXTENSION_SHEETS):
                raise ImportFormatError("Ожидается Excel с одним листом конфигурации или поддерживаемым расширением безопасности.")
        sheet = workbook.active
        try:
            actual_rows = read_bounded_rows(sheet, max_rows=10001, max_columns=5)
        except WorkbookFormatError as exc:
            raise ImportFormatError(str(exc)) from exc
        headers = tuple(cell.value for cell in actual_rows[0]) if actual_rows else ()
        try:
            order = resolve_columns(headers)
        except ValueError as exc:
            raise ImportFormatError(str(exc)) from exc
        # The first semantic column can be labelled ПК, Кластер, etc.
        # An explicit cluster label permits shared scopes like 'Общая сеть'.
        scope_header = str(headers[order[0]] or "").strip().casefold()
        cluster_mode = scope_header not in {"пк", "pc"}
        rows = [
            tuple(
                row[i] if i < len(row) and hasattr(row[i], "coordinate")
                else ReadOnlyCell(sheet, row_number, i + 1, None)
                for i in order
            )
            for row_number, row in enumerate(actual_rows, start=1)
        ]
        original_headers = headers
        nodes: dict[str, dict] = {}
        row_records = []
        for row_number, row in enumerate(rows[1:], start=2):
            values = [cell.value for cell in row]
            if all(value is None for value in values):
                continue
            pc_raw, identifier, name_raw, incoming, outgoing = values
            if not isinstance(identifier, int) or isinstance(identifier, bool):
                raise ImportFormatError(f"B{row_number}: ID must be an integer")
            name = _normalise_name(name_raw)
            if not name:
                raise ImportFormatError(f"C{row_number}: empty entity name")
            if cluster_mode:
                scope = _normalise_name(pc_raw) or None
                pc = scope if scope and re.fullmatch(r"ПК [1-9]\d*", scope) else None
                if scope is None:
                    _scope(pc_raw, name, global_names)  # no implicit inheritance for blank clusters
                key = (f"{pc.split()[1]}:{identifier}" if pc else
                       f"c:{quote(scope, safe='')}:{identifier}" if scope else f"g:{identifier}")
            else:
                pc = _scope(pc_raw, name, global_names)
                scope = pc
                key = f"g:{identifier}" if pc is None else f"{pc.split()[1]}:{identifier}"
            if key in nodes:
                raise ImportFormatError(f"Duplicate key {key} at {row[1].coordinate}")
            field_provenance = {
                field: [_evidence(path, state, cell.value, transform,
                                  sheet=sheet.title, cell=cell.coordinate)]
                for field, cell, column, transform in (
                    ("pc", row[0], "A", "explicit scope; blank is shared, never forward-filled"),
                    ("id", row[1], "B", "integer identity"),
                    ("name", row[2], "C", "normalise whitespace"),
                )
            }
            provenance = [_evidence(path, state, values[:3], "compose key from explicit PC/shared scope and ID",
                                    sheet=sheet.title, cell=",".join(cell.coordinate for cell in row[:3]))]
            field_provenance["key"] = provenance
            nodes[key] = {"key": key, "id": identifier, "pc": pc, "name": name,
                          "provenance": provenance, "field_provenance": field_provenance}
            if cluster_mode:
                nodes[key]["cluster"] = scope or "shared"
                field_provenance["cluster"] = deepcopy(field_provenance["pc"])
                field_provenance["pc"][0]["transformation"] = "retain ПК N scope; other explicit cluster names have pc=null"
            row_records.append((key, scope, row))
        by_name: dict[str, list[str]] = defaultdict(list)
        by_scope: dict[tuple, list[str]] = defaultdict(list)
        shared_registry: dict[str, list[str]] = defaultdict(list)
        for key, node in nodes.items():
            by_name[node["name"]].append(key)
            node_scope = node.get("cluster") if cluster_mode else node["pc"]
            if cluster_mode and key.startswith("g:"):
                node_scope = None
            by_scope[(node_scope, node["name"])].append(key)
            if cluster_mode and node["pc"] is None:
                shared_registry[node["name"]].append(key)
        qualified_scopes = sorted({scope for scope, _ in by_scope if scope}, key=lambda scope: (-len(scope), scope))
        merged: dict[tuple[str, str], list] = defaultdict(list)
        issues = []
        declarations = []
        for key, pc, row in row_records:
            for column, direction in ((3, "incoming"), (4, "outgoing")):
                cell = row[column]
                for ref in _references(cell.value):
                    candidates, resolution, ref_scope, ref_name = (
                        _resolve_cluster(ref, pc, by_name, by_scope, shared_registry, qualified_scopes) if cluster_mode else
                        _resolve(ref, pc, by_name, by_scope, global_names))
                    provenance = _evidence(path, state, cell.value,
                        f"split comma list; {resolution}; {direction} {'referenced → row' if direction == 'incoming' else 'row → referenced'}",
                        sheet=sheet.title, cell=cell.coordinate, reference=ref, direction=direction)
                    declaration = {"row_key": key, "direction": direction, "reference": ref,
                                   "reference_scope": ref_scope, "reference_name": ref_name,
                                   "resolution": resolution, "candidates": candidates,
                                   "provenance": [provenance]}
                    if resolution == "unqualified_shared_reference" or len(candidates) > 1:
                        declaration["status"] = "ambiguous_reference"
                        issues.append({"kind": "ambiguous_reference", **declaration})
                    elif not candidates:
                        declaration["status"] = "unresolved_reference"
                        issues.append({"kind": "unresolved_reference", **declaration})
                    else:
                        other = candidates[0]
                        source, target = (other, key) if direction == "incoming" else (key, other)
                        declaration.update(status="resolved", source=source, target=target)
                        merged[(source, target)].append(provenance)
                    declarations.append(declaration)
        edges = []
        for (source, target), provenance in sorted(merged.items()):
            directions = {e["direction"] for e in provenance}
            edge = {"source": source, "target": target, "provenance": provenance,
                    "declarations": sorted(directions), "symmetric_declaration": len(directions) == 2}
            edges.append(edge)
            if len(directions) != 2:
                issues.append({"kind": "asymmetric_declaration", "source": source, "target": target,
                               "missing_declaration": "incoming" if "outgoing" in directions else "outgoing",
                               "provenance": deepcopy(provenance)})
        nodes = dict(sorted(nodes.items()))
        return {"schema_version": 1, "state": state, "format": "xlsx", "nodes": nodes,
                "edges": edges, "issues": issues, "declarations": declarations,
                "metadata": _metadata(path, nodes, edges, state, sheet=sheet.title,
                    row_count=len(rows), object_rows=len(row_records), formula_count=0,
                    declaration_count=len(declarations),
                    headers=list(headers), scope_column=headers[order[0]], global_name_registry=sorted(global_names),
                    declared_non_pc_registry={name: sorted(keys) for name, keys in sorted(shared_registry.items())},
                    cluster_counts=dict(sorted(Counter(n.get("cluster") or n["pc"] or "shared" for n in nodes.values()).items())),
                    issue_counts=dict(sorted(Counter(i["kind"] for i in issues).items())))}
    finally:
        workbook.close()


def compare_sources(html: dict, xlsx: dict, closed_inventory: bool = False, *,
                    as_states: bool = False) -> dict:
    """Compare descriptions, optionally declaring a directed version relationship.

    Merely missing a row never proves removal.  Only the conjunction of the
    explicit version relationship and a complete-inventory assumption does so.
    Unresolved references may be *explained* against HTML, never imported into XLSX.
    """
    if closed_inventory and not as_states:
        raise ValueError("closed_inventory requires explicit as_states=True (HTML baseline → XLSX changed)")
    hnodes, xnodes = html["nodes"], xlsx["nodes"]
    hkeys, xkeys = set(hnodes), set(xnodes)
    common = hkeys & xkeys
    he = {(e["source"], e["target"]) for e in html["edges"]}
    xe = {(e["source"], e["target"]) for e in xlsx["edges"]}
    common_he = {e for e in he if e[0] in common and e[1] in common}
    common_xe = {e for e in xe if e[0] in common and e[1] in common}
    missing_x = sorted(hkeys - xkeys)
    missing_h = sorted(xkeys - hkeys)
    hscope: dict[tuple, list] = defaultdict(list)
    for key, node in hnodes.items():
        hscope[(node["pc"] or None, node["name"])].append(key)
    unresolved = []
    for issue in xlsx["issues"]:
        if issue["kind"] != "unresolved_reference":
            continue
        item = deepcopy(issue)
        candidates = sorted(hscope.get((issue["reference_scope"], issue["reference_name"]), []))
        item["resolved_against_html"] = candidates[0] if len(candidates) == 1 else None
        item["html_candidates"] = candidates
        item["comparison_only"] = True
        unresolved.append(item)
    changes = []
    for key in sorted(common):
        fields = {field: {"html": hnodes[key][field], "xlsx": xnodes[key][field]}
                  for field in ("id", "pc", "name")
                  if (hnodes[key][field] or None) != (xnodes[key][field] or None)}
        if fields:
            changes.append({"key": key, "fields": fields,
                            "provenance": hnodes[key]["provenance"] + xnodes[key]["provenance"]})
    assumption = {
        "id": "xlsx_complete_inventory", "kind": "declared", "value": closed_inventory,
        "description": "XLSX enumerates every present component of the changed state; missing rows mean present=FALSE",
        "file": xlsx["metadata"]["file"], "state": xlsx["state"],
        "raw_value": closed_inventory, "transformation": "explicit comparison option",
    }
    return {
        "schema_version": 1,
        "mode": "html_baseline_xlsx_changed" if as_states else "independent_descriptions",
        "baseline_state": html["state"] if as_states else None,
        "changed_state": xlsx["state"] if as_states else None,
        "sources": {"html": deepcopy(html["metadata"]), "xlsx": deepcopy(xlsx["metadata"])},
        "assumptions": [assumption] if as_states else [],
        "missing_in_xlsx": missing_x, "missing_in_html": missing_h,
        "common_nodes_count": len(common), "common_edges_count": len(he & xe),
        "common_node_edges": {"html": len(common_he), "xlsx": len(common_xe),
                              "matching": len(common_he & common_xe)},
        "only_html_edges": [list(e) for e in sorted(he - xe)],
        "only_xlsx_edges": [list(e) for e in sorted(xe - he)],
        "node_changes": changes,
        "presence_changes": [{"key": key, "baseline": "TRUE", "changed": "FALSE" if closed_inventory else "UNKNOWN",
                              "provenance": deepcopy(hnodes[key]["provenance"]),
                              "reason": "complete changed-state inventory explicitly assumed" if closed_inventory else "missing row is not evidence of removal"}
                             for key in missing_x] if as_states else [],
        "unresolved_references": unresolved,
        "ambiguous_references": [deepcopy(i) for i in xlsx["issues"] if i["kind"] == "ambiguous_reference"],
        "asymmetric_declarations": [deepcopy(i) for i in xlsx["issues"] if i["kind"] == "asymmetric_declaration"],
        "html_issues": deepcopy(html["issues"]),
        "warnings": ["Structural edges do not establish subject operations, ACLs, control coverage, or F/L/S types.",
                     "PC membership denotes simultaneous components of one system, not a version order."],
    }
