"""Explicit, optional interpretations of an otherwise untyped source graph.

Detection never applies semantics. The mandate profile is a user's choice to
interpret non-marker arrows as possible data transfers, not evidence of ACL,
human authorship, physical connectivity, or read/write permissions.
"""
from collections import defaultdict
from copy import deepcopy
from hashlib import sha256
import json
import re

from .model import fact, validate_model
from .profiles import imported_model


PROFILE_ID = "mandate-flows-v1"
MAX_NODES = 5000
MAX_EDGES = 20000
MAX_REQUIREMENTS = 10000
_MARKER = re.compile(r"^Мандат ([1-9][0-9]*) [—–-] (.+)$")
_ASSUMPTIONS = [
    "Профиль применяется для подтверждённой трактовки стрелок как передачи данных; исходный граф сохраняется без изменений.",
    "Номер N в имени «Мандат N — Уровень» задаёт порядок конфиденциальности: больший номер означает более высокий уровень.",
    "Исходящее ребро из узла мандата в кластере «Мандаты» назначает метку целевому узлу; это ребро не является потоком данных.",
    "Остальные стрелки рассматриваются как возможные направленные потоки данных. Передача с более высокого уровня на более низкий запрещена; исключения рассекречивания не заданы.",
    "Категории конфиденциальности в этом профиле не используются. Непомеченные узлы не получают метку по умолчанию.",
    "Проверяются отдельные прямые потоки с двумя известными метками. Права чтения/записи, типы узлов, фактическое авторство, допуски, целостность и уровни F/L/S из стрелок не выводятся.",
]


def _bad(path, message):
    raise ValueError(f"{path}: {message}")


def validate_input_graph(graph):
    """Validate a bounded imported graph without changing or interpreting it."""
    if not isinstance(graph, dict):
        _bad("$", "ожидается объект исходного графа")
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes, dict):
        _bad("$.nodes", "ожидается словарь узлов")
    if len(nodes) > MAX_NODES:
        _bad("$.nodes", f"допустимо не более {MAX_NODES} узлов")
    if not isinstance(edges, list):
        _bad("$.edges", "ожидается список направленных рёбер")
    if len(edges) > MAX_EDGES:
        _bad("$.edges", f"допустимо не более {MAX_EDGES} рёбер")
    for key, node in nodes.items():
        if not isinstance(key, str) or not key.strip():
            _bad("$.nodes", "ключ узла должен быть непустой строкой")
        path = f"$.nodes[{key!r}]"
        if not isinstance(node, dict):
            _bad(path, "ожидается объект узла")
        if not isinstance(node.get("name"), str) or not node["name"].strip():
            _bad(path + ".name", "ожидается непустое строковое имя")
        if "key" in node and node["key"] != key:
            _bad(path + ".key", "ключ записи не совпадает с ключом словаря")
        if "cluster" in node and (not isinstance(node["cluster"], str) or not node["cluster"].strip()):
            _bad(path + ".cluster", "ожидается непустая строка кластера")
        _provenance_shape(node, path)
    for index, edge in enumerate(edges):
        path = f"$.edges[{index}]"
        if not isinstance(edge, dict):
            _bad(path, "ожидается объект ребра")
        for field in ("source", "target"):
            if not isinstance(edge.get(field), str) or edge[field] not in nodes:
                _bad(path + "." + field, "ожидается ключ существующего узла")
        _provenance_shape(edge, path)
    if "state" in graph and not isinstance(graph["state"], str):
        _bad("$.state", "ожидается строка состояния")
    if "metadata" in graph and not isinstance(graph["metadata"], dict):
        _bad("$.metadata", "ожидается объект метаданных")
    if "issues" in graph and (not isinstance(graph["issues"], list) or any(not isinstance(i, dict) for i in graph["issues"])):
        _bad("$.issues", "ожидается список диагностик")
    try:
        json.dumps(graph, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        _bad("$", "исходный граф должен быть совместим с JSON: " + str(exc))


def _provenance_shape(record, path):
    if "provenance" in record and (not isinstance(record["provenance"], list)
            or any(not isinstance(p, dict) for p in record["provenance"])):
        _bad(path + ".provenance", "ожидается список объектов происхождения")


def _inspect(graph):
    levels, diagnostics = [], []
    for key, node in sorted(graph["nodes"].items()):
        match = _MARKER.fullmatch(node["name"]) if node.get("cluster") == "Мандаты" else None
        if not match:
            continue
        try:
            rank = int(match[1])
        except ValueError:
            _bad(f"$.nodes[{key!r}].name", "номер мандата слишком велик")
        label = match[2].strip()
        if not label:
            _bad(f"$.nodes[{key!r}].name", "название уровня мандата пусто")
        levels.append({"node_key": key, "rank": rank, "label": label})
    if not levels:
        return None
    levels.sort(key=lambda level: (level["rank"], level["node_key"]))
    for field, code in (("rank", "duplicate_mandate_rank"), ("label", "duplicate_mandate_label")):
        grouped = defaultdict(list)
        for level in levels:
            grouped[level[field]].append(level["node_key"])
        for value, keys in grouped.items():
            if len(keys) > 1:
                diagnostics.append({"kind": code, "severity": "error", "value": value, "node_keys": keys,
                                    "message": "Ранги и названия уровней должны быть уникальными."})
    by_marker = {level["node_key"]: level for level in levels}
    assignments, assignment_edges, flows = defaultdict(set), defaultdict(list), []
    excluded = 0
    for index, edge in enumerate(graph["edges"]):
        source, target = edge["source"], edge["target"]
        if source in by_marker:
            excluded += 1
            if target in by_marker:
                diagnostics.append({"kind": "mandate_assigned_to_mandate", "severity": "error", "edge_index": index,
                                    "message": "Узел уровня мандата не может получать метку другого уровня."})
            else:
                assignments[target].add(source)
                assignment_edges[target].append(index)
        elif target in by_marker:
            excluded += 1
            diagnostics.append({"kind": "incoming_mandate_edge", "severity": "warning", "edge_index": index,
                                "message": "Входящее ребро мандата не назначает метку и исключено из потоков."})
        else:
            flows.append((index, edge))
    for key, markers in sorted(assignments.items()):
        if len(markers) > 1:
            diagnostics.append({"kind": "conflicting_mandate_assignments", "severity": "error", "node_key": key,
                                "mandate_keys": sorted(markers), "edge_indices": assignment_edges[key],
                                "message": "Узлу назначены несколько мандатов; нельзя выбирать метку автоматически."})
    labeled = {key for key, markers in assignments.items() if len(markers) == 1}
    checked = [(index, edge) for index, edge in flows if edge["source"] in labeled and edge["target"] in labeled]
    unlabeled = {edge[field] for _, edge in flows for field in ("source", "target") if edge[field] not in labeled}
    unresolved = sum(issue.get("kind") in {"ambiguous_reference", "unresolved_reference"}
                     for issue in graph.get("issues", []))
    if unresolved:
        diagnostics.append({"kind": "unresolved_source_references", "severity": "warning", "count": unresolved,
                            "message": "Часть исходных ссылок не разрешена однозначно; такие связи не проверены."})
    counts = {"levels": len(levels), "assignments": sum(map(len, assignment_edges.values())),
              "labeled_nodes": len(labeled), "flows": len(flows), "checked_flows": len(checked),
              "unchecked_flows": len(flows) - len(checked), "unlabeled_nodes": len(unlabeled),
              "marker_edges_excluded": excluded, "unresolved_references": unresolved}
    if len(checked) >= MAX_REQUIREMENTS:
        diagnostics.append({"kind": "requirement_limit", "severity": "error",
                            "message": f"Профиль ограничен {MAX_REQUIREMENTS - 1} прямыми проверками и одной проверкой полноты."})
    descriptor = {"id": PROFILE_ID, "name": "Мандатные метки: возможные потоки данных",
                  "description": (f"Обнаружено уровней: {len(levels)}, назначений: {counts['assignments']}. "
                                  f"Будут проверены {len(checked)} прямых потоков; {counts['unchecked_flows']} связей "
                                  "не имеют меток на обоих концах. Профиль предполагает рост конфиденциальности "
                                  "с номером мандата и трактует немандатные стрелки как возможные потоки данных; "
                                  "категории конфиденциальности не используются. Назначенные метки считаются текущими метками объектов, а не пределами допуска. "
                                  "Связи администрирования также будут считаться потоками: выбирайте профиль, только если это соответствует смыслу вашего графа."),
                  "assumptions": list(_ASSUMPTIONS), "counts": counts, "levels": levels,
                  "diagnostics": diagnostics, "can_apply": not any(d["severity"] == "error" for d in diagnostics)}
    return descriptor, by_marker, assignments, assignment_edges, checked


def detect_mandate_profile(graph):
    """Describe a recognizable optional profile; never apply it implicitly."""
    validate_input_graph(graph)
    inspected = _inspect(graph)
    return inspected[0] if inspected else None


def _evidence(record, source_path, transformation):
    # Full raw cell values remain in source_graph. References avoid multiplying
    # large adjacency cells in every derived fact, label and finding.
    origin = [{key: deepcopy(item[key]) for key in ("file", "sheet", "cell", "json_key", "reference", "direction") if key in item}
              for item in record.get("provenance", [])]
    return [{"kind": "profile_assumption", "profile": PROFILE_ID, "source_path": source_path,
             "source_references": origin, "transformation": transformation}]


def compile_mandate_flows(graph):
    """Compile only after explicit user selection of the mandate-flow profile."""
    validate_input_graph(graph)
    inspected = _inspect(graph)
    if inspected is None:
        _bad("$.nodes", "не найден профиль мандатов: нужны узлы «Мандат N — Уровень» в кластере «Мандаты»")
    descriptor, markers, assignments, assignment_edges, checked = inspected
    if not descriptor["can_apply"]:
        _bad("$.profile", "; ".join(d["message"] for d in descriptor["diagnostics"] if d["severity"] == "error"))
    # imported_model expects metadata even when the caller supplied a minimal
    # graph. Its original snapshot is restored exactly after that adaptation.
    source = deepcopy(graph)
    source.setdefault("metadata", {})
    model = imported_model(source)
    model["source_graph"] = deepcopy(graph)
    # This profile obtains labels only from mandate assignments. Other raw
    # attributes are not an independent semantic policy or a clearance grant.
    # Preserve them in source_graph, never in the derived policy-bearing nodes.
    for node in model["nodes"].values():
        for field in ("security_label", "integrity_label", "clearance"):
            node.pop(field, None)
            node.pop(field + "_provenance", None)
            if isinstance(node.get("field_provenance"), dict):
                node["field_provenance"].pop(field, None)
    model["profile"] = PROFILE_ID
    model["assumptions"] = list(_ASSUMPTIONS)
    model["detected_profile"] = deepcopy(descriptor)
    model["profile_coverage"] = dict(descriptor["counts"], coverage_complete=descriptor["counts"]["unchecked_flows"] == 0
                                     and descriptor["counts"]["unresolved_references"] == 0 and bool(checked))
    model["security_policy"] = {"enabled": True, "confidentiality_levels": [level["label"] for level in descriptor["levels"]],
                                "categories": [], "integrity_enabled": False, "declassifications": [],
                                "provenance": [{"kind": "profile_assumption", "profile": PROFILE_ID,
                                                "transformation": "explicit profile selection; numeric mandate order; no categories or declassification exceptions"}]}
    for key, assigned in assignments.items():
        marker = next(iter(assigned))
        node = model["nodes"][key]
        node["security_label"] = {"level": markers[marker]["label"], "categories": []}
        evidence = _evidence(graph["nodes"][marker], f"source_graph.nodes[{marker!r}]", "explicit profile: numeric mandate name defines this level")
        for index in assignment_edges[key]:
            evidence += _evidence(graph["edges"][index], f"source_graph.edges[{index}]", "explicit profile: outgoing mandate edge assigns this label")
        node["security_label_provenance"] = evidence
        node.setdefault("provenance", []).extend(deepcopy(evidence))
    # Stable edge-based IDs preserve findings when input records are reordered.
    fingerprints = [(sha256(json.dumps(edge, sort_keys=True, ensure_ascii=False).encode()).hexdigest(), index, edge)
                    for index, edge in checked]
    repetitions = defaultdict(int)
    for digest, index, edge in sorted(fingerprints, key=lambda item: (item[0], item[1])):
        repetitions[digest] += 1
        identifier = "mandate-flow:" + digest + ":" + str(repetitions[digest])
        start, target = edge["source"], edge["target"]
        evidence = _evidence(edge, f"source_graph.edges[{index}]", "explicit profile: this directed arrow is a possible data transfer; no human author or access right is inferred")
        model["facts"].append(fact("transition_enabled", [identifier], "TRUE", evidence))
        model["transitions"].append({"id": identifier, "source": start, "target": target, "subject": start,
                                     "operation": "write", "kind": "flow", "scenario": identifier, "value": "TRUE",
                                     "conditions": [{"predicate": "transition_enabled", "args": [identifier]}],
                                     "source_edge_index": index, "provenance": deepcopy(evidence)})
        model["requirements"].append({"id": identifier, "checker": "label_flow", "subject": start, "source": start,
                                      "object": target, "operation": "write", "kind": "flow", "scenario": identifier,
                                      "name": f"Сохранение метки: {graph['nodes'][start]['name']} → {graph['nodes'][target]['name']}",
                                      "catalog_rule_ids": ["FT025"], "catalog_scope": "fragment",
                                      "provenance": deepcopy(evidence)})
    missing = []
    counts = descriptor["counts"]
    if counts["unchecked_flows"]:
        missing.append(f"Не заданы метки для {counts['unlabeled_nodes']} узлов на {counts['unchecked_flows']} связях; эти потоки не проверены")
    if counts["unresolved_references"]:
        missing.append(f"Не разрешены однозначно {counts['unresolved_references']} исходных ссылок; соответствующие связи не проверены")
    if not checked:
        missing.append("Нет прямых потоков с известными метками обоих концов; безопасность по отсутствию проверок не подтверждается")
    if missing:
        model["requirements"].append({"id": "mandate-flow:coverage", "checker": "semantic_readiness",
                                      "name": "Полнота меток для анализа потоков", "missing": missing,
                                      "provenance": [{"kind": "profile_assumption", "profile": PROFILE_ID,
                                                      "transformation": "unlabeled flow scope is explicitly not checked"}]})
    errors = validate_model(model)
    if errors:
        _bad("$.profile", "не удалось построить согласованную модель: " + json.dumps(errors, ensure_ascii=False))
    return model
