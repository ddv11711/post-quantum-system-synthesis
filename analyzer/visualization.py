"""Compact, evidence-based graphs for the before/after user interface.

Structural declarations are retained as a separate layer. Only a confirmed
forbidden operation (or explicitly modelled authentication bypass) marks a
subject as a violator. A failed availability requirement never accuses a user.
"""
from collections import Counter, defaultdict
from copy import deepcopy
import json

from .engine import Engine, analyze
from .logic import conjunction
from .model import FactBase, PREDICATES, validate_model


# Public sparse F/L/S overlay contract. These are display colors for explicitly
# declared channels, never an inference from legacy HTML colors or connectivity.
_LAYER_LEGEND = {
    "physical": {"code": "F", "name": "Физический", "color": "#2563eb"},
    "syntactic": {"code": "L", "name": "Синтаксический", "color": "#7c3aed"},
    "semantic": {"code": "S", "name": "Семантический", "color": "#078574"},
}

_CHECKER_NAMES = {
    "forbidden_operation": "Запрещённый доступ", "required_operation": "Обязательный доступ",
    "required_function": "Работоспособность компонента", "protection": "Защита компонента",
    "authentication": "Аутентификация", "logging": "Регистрация событий",
    "redundancy": "Независимое резервирование", "recovery": "Восстановление данных",
    "configuration": "Настройки компонента", "incompatible_roles": "Разделение полномочий",
    "authorized_change": "Согласование изменений", "crypto": "Криптографическая защита",
    "quantum": "Устойчивость к квантовой угрозе", "evidence": "Свидетельство выполнения",
    "mandatory_access": "Мандатный контроль доступа", "label_flow": "Сохранение меток при передаче",
    "clearance": "Соответствие допуска", "semantic_readiness": "Полнота описания безопасности",
}


def _value(value):
    return value.value if hasattr(value, "value") else value


def _atom(record):
    return record.get("predicate"), tuple(record.get("args", []))


def _origin(provenance):
    """A small provenance label; full evidence remains in the analysis result."""
    return sorted({item.get("kind", "declared") for item in (provenance or []) if isinstance(item, dict)})


def _name(nodes, key):
    if key is None:
        return "объект"
    return nodes.get(key, {}).get("name", key)


def _message(finding, names, offender, causes):
    target = _name(names, finding.get("object"))
    checker, status = finding.get("checker"), finding.get("status")
    if offender:
        operations = {"read": "читать", "write": "изменять", "execute": "исполнять", "administer": "администрировать"}
        operation = operations.get(finding.get("operation"), finding.get("operation") or "получать доступ к")
        message = f"{_name(names, offender)} может {operation} «{target}», хотя это запрещено политикой."
        mandatory = finding.get("mandatory") or {}
        if checker == "mandatory_access":
            if _value(mandatory.get("confidentiality", {}).get("value")) == "FALSE":
                message += " Метки конфиденциальности или категории несовместимы с этой операцией."
            if _value(mandatory.get("integrity", {}).get("value")) == "FALSE":
                message += " Нарушается заданное правило целостности данных."
            if _value(mandatory.get("clearance", {}).get("value")) == "FALSE":
                message += " Текущая метка пользователя превышает его допуск."
        return message
    if status == "FAIL":
        messages = {
            "required_operation": f"Не удаётся выполнить обязательную операцию с «{target}». Это потеря доступа, а не нарушение со стороны пользователя.",
            "required_function": f"Обязательная функция «{target}» недоступна.",
            "protection": f"Для «{target}» не работает требуемая защита.",
            "authentication": f"Для «{target}» не обеспечена требуемая аутентификация.",
            "logging": f"Обязательное событие «{target}» может произойти, но работающий регистратор его не покрывает.",
            "redundancy": f"Для «{target}» не подтверждено требуемое независимое резервирование.",
            "recovery": f"«{target}» нельзя восстановить из описанных копий и доступных ключей.",
            "configuration": f"Фактическое состояние «{target}» не соответствует заданному требованию.",
            "incompatible_roles": f"Подтверждено запрещённое совмещение полномочий у «{_name(names, finding.get('subject'))}».",
            "authorized_change": f"Изменение «{target}» не имеет требуемого согласования.",
            "crypto": f"Участок «{target}» не обеспечивает заданную криптографическую защиту.",
            "quantum": f"В учебном квантовом сценарии возможно пассивное раскрытие «{target}». Активные права доступа из этого не следуют.",
            "evidence": f"Свидетельство выполнения требования для «{target}» опровергнуто.",
            "mandatory_access": f"Доступ к «{target}» нарушает явно заданные правила меток безопасности.",
            "label_flow": f"Передача данных из «{_name(names, finding.get('source'))}» в «{target}» нарушает правила сохранения меток безопасности.",
            "clearance": f"Метка субъекта «{_name(names, finding.get('subject') or finding.get('object'))}» превышает его явно заданный допуск. Изменение допуска не является допустимым исправлением графа.",
        }
        message = messages.get(checker, finding.get("reason", "Подтверждено нарушение требования."))
        if causes:
            message += " Причина: " + ", ".join(_name(names, key) for key in causes) + "."
        return message
    return {
        "PASS": f"Требование для «{target}» выполнено в описанной области.",
        "UNKNOWN": f"Для вывода о «{target}» недостаточно данных или подтверждённой полноты описания.",
        "REQUIRES_EVIDENCE": f"Для «{target}» требуется внешнее свидетельство.",
        "NOT_CHECKED": f"Требование для «{target}» пока не проверяется этим модулем.",
        "NOT_APPLICABLE": f"Требование для «{target}» явно исключено выбранным профилем.",
        "MODEL_ERROR": "Модель противоречива или некорректна; граф не подтверждает безопасность.",
    }.get(status, finding.get("reason", ""))


def _display_finding_valid(finding):
    """Saved reports are display input, not trusted engine-produced records."""
    if not isinstance(finding, dict):
        return False
    for field in ("id", "status", "checker", "subject", "object", "source", "name", "rule_id", "operation"):
        if finding.get(field) is not None and not isinstance(finding[field], str):
            return False
    causes = finding.get("cause_components", [])
    if not isinstance(causes, list) or any(not isinstance(key, str) for key in causes):
        return False
    witness = finding.get("witness") or {}
    if not isinstance(witness, dict):
        return False
    if not isinstance(witness.get("nodes", []), list) or any(not isinstance(key, str) for key in witness.get("nodes", [])):
        return False
    if not isinstance(witness.get("edges", []), list) or any(not isinstance(edge, dict) or
            (edge.get("id") is not None and not isinstance(edge["id"], str)) for edge in witness.get("edges", [])):
        return False
    mandatory = finding.get("mandatory") or {}
    if not isinstance(mandatory, dict) or any(not isinstance(mandatory.get(key, {}), dict)
            for key in ("confidentiality", "integrity", "clearance")):
        return False
    for field, members in (("common_dependencies", "dependencies"), ("evidence", "args")):
        entries = finding.get(field, [])
        if not isinstance(entries, list) or any(not isinstance(entry, dict) or
                not isinstance(entry.get(members, []), list) or
                any(not isinstance(key, str) for key in entry.get(members, [])) for entry in entries):
            return False
    return True


def _cluster(node):
    """Explicit grouping is presentation metadata, never a security boundary."""
    for field in ("cluster", "pc", "group"):
        value = node.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return "shared"


def _physical_route_changed(channel, changed_atoms):
    via = channel.get("protection_via", [])
    return (any(("present", (key,)) in changed_atoms for key in [channel.get("source"), *via, channel.get("target")]) or
            any((predicate, (key,)) in changed_atoms for key in via
                for predicate in ("healthy", "transport_enabled", "failure_mode")))


def _layer_projection(model, names, errors, changed_atoms, diagnostics, channel_violations):
    """Three sparse directional arrows per explicitly declared F/L/S channel.

    ``value`` and ``effective_value`` are identical evaluated truth values;
    ``declared_value`` retains the layer declaration. Missing pairs are absent
    from this list, not FALSE. UI matrices must preserve that distinction.
    ``via_protection`` is a route declaration (dashed style), not a claim that
    the mechanism works. ``route`` retains the ordered protection components.
    Existing ``graph.edges`` remains unchanged for structural/access overlays.
    """
    channels = model.get("fls_channels", [])
    if not isinstance(channels, list):
        diagnostics.append({"code": "INVALID_FLS_CHANNELS", "message": "Ожидается список явных направленных каналов F/L/S."})
        return []
    if not channels:
        return []
    evaluated = {}
    if not errors:
        # Core evaluator owns transport/failure/unknown semantics. The display
        # must not independently reinterpret a protection device's enabled flag.
        from .fls import evaluate_channels
        evaluated = {entry["id"]: entry for entry in evaluate_channels(model)}
    result = []
    seen_channels = set()
    for channel in channels:
        if not isinstance(channel, dict):
            diagnostics.append({"code": "INVALID_FLS_CHANNEL", "message": "Запись канала не является объектом."})
            continue
        identifier, source, target = channel.get("id"), channel.get("source"), channel.get("target")
        if (not isinstance(identifier, str) or not identifier or identifier in seen_channels
                or not isinstance(source, str) or not isinstance(target, str)
                or source not in names or target not in names):
            diagnostics.append({"code": "INVALID_FLS_CHANNEL", "channel": identifier,
                                "message": "Не указан ID канала или его конечные узлы отсутствуют."})
            continue
        seen_channels.add(identifier)
        item = evaluated.get(identifier, {})
        declared = item.get("layers", channel.get("layers", {}))
        declared = declared if isinstance(declared, dict) else {}
        via = channel.get("protection_via", [])
        via = list(via) if isinstance(via, list) and all(isinstance(key, str) for key in via) else []
        route = item.get("route", [source, *via, target])
        effective = item.get("effective_layers", {})
        for layer in _LAYER_LEGEND:
            raw_value = _value(declared.get(layer, "UNKNOWN"))
            raw_value = "TRUE" if raw_value is True else "FALSE" if raw_value is False else raw_value
            raw_value = raw_value if raw_value in ("TRUE", "FALSE", "UNKNOWN") else "UNKNOWN"
            value = _value(effective.get(layer, "UNKNOWN")) if not errors else "UNKNOWN"
            value = value if value in ("TRUE", "FALSE", "UNKNOWN") else "UNKNOWN"
            changed = layer == "physical" and _physical_route_changed(
                {"source": source, "target": target, "protection_via": via}, changed_atoms)
            result.append({"id": "layer:" + json.dumps([identifier, layer], ensure_ascii=False, separators=(",", ":")),
                "channel_id": identifier, "original_channel_id": channel.get("original_channel_id", identifier),
                "direction": channel.get("direction", "forward"), "source": source, "target": target,
                "layer": layer, "value": value, "effective_value": value, "declared_value": raw_value,
                "via_protection": bool(via), "protection_via": via, "route": list(route),
                "blocked": value == "FALSE", "changed": bool(changed),
                "witness": not errors and value == "TRUE" and bool(channel_violations.get(identifier)),
                "violations": sorted(channel_violations.get(identifier, [])) if not errors else [],
                "origin": _origin(channel.get("provenance", [])) or ["declared"],
                "label": _LAYER_LEGEND[layer]["name"]})
    return sorted(result, key=lambda edge: (edge["channel_id"], list(_LAYER_LEGEND).index(edge["layer"])))


def build_graph(model, analysis=None):
    """Return all declared nodes and edges, plus explicit semantic overlays.

    The model's node inventory includes tombstones needed to show removals. Raw
    edges are copied exactly, never reconstructed from names or numerical IDs.
    Layout is intentionally left to the frontend: the attached HTML's layout
    uses non-unique numerical IDs and cannot be used as global node positions.
    """
    analysis = analysis if analysis is not None else analyze(model)
    errors = validate_model(model)
    if not isinstance(model, dict):
        model = {}
    names = model.get("nodes", {})
    if not isinstance(names, dict):
        names = {}
    names = {key: value for key, value in names.items() if isinstance(key, str) and isinstance(value, dict)}
    diagnostics = []
    if errors:
        diagnostics.append({"code": "MODEL_ERROR", "message": "Граф показан без подтверждения семантических переходов: модель содержит ошибки."})
    # A malformed source file can be diagnosed by the analyzer without making
    # the visual adapter fail a second time while constructing the error view.
    valid_fact_shape = isinstance(model.get("facts", []), list) and all(
        isinstance(f, dict) and isinstance(f.get("predicate"), str) and isinstance(f.get("args", []), list)
        and all(isinstance(arg, str) for arg in f.get("args", [])) for f in model.get("facts", []))
    facts = FactBase(model if valid_fact_shape else {"facts": [], "completeness": []})
    engine = Engine(model) if not errors else None
    required = {r.get("id"): r for r in model.get("requirements", []) if isinstance(r, dict) and isinstance(r.get("id"), str)} if isinstance(model.get("requirements", []), list) else {}
    changes = [c for c in model.get("diff", []) if isinstance(c, dict)
               and isinstance(c.get("predicate"), str) and isinstance(c.get("args", []), list)
               and all(isinstance(arg, str) for arg in c.get("args", []))] if isinstance(model.get("diff", []), list) else []
    changed_atoms = {_atom(change) for change in changes}
    changes_by_node = defaultdict(list)
    for change in changes:
        for key in change.get("args", []):
            if key in names:
                changes_by_node[key].append({field: deepcopy(change.get(field)) for field in ("predicate", "args", "before", "after", "actions") if field in change})

    affected, causes, unknowns, violators = defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set)
    witness_transitions = defaultdict(set)
    display_findings = []
    invalid_display_findings = 0
    report_results = analysis.get("results", []) if isinstance(analysis, dict) else None
    if not isinstance(report_results, list):
        diagnostics.append({"code": "INVALID_ANALYSIS_REPORT", "message": "Некорректная структура сохраненного отчета."})
        invalid_display_findings += 1
        report_results = []
    for finding in report_results:
        if not _display_finding_valid(finding):
            diagnostics.append({"code": "INVALID_DISPLAY_FINDING", "message": "Некорректная находка сохраненного отчета не интерпретируется как доказательство."})
            invalid_display_findings += 1
            continue
        identifier = finding.get("id", "unknown_check")
        status = finding.get("status", "NOT_CHECKED")
        witness = finding.get("witness") or {}
        confirmed_path = status == "FAIL" and witness.get("certain") is True
        checker = finding.get("checker")
        subject = finding.get("subject")
        offender = None
        mandatory = finding.get("mandatory") or {}
        forbidden_mandatory = (checker == "mandatory_access" and _value(mandatory.get("allowed")) == "FALSE"
                               and _value(mandatory.get("actual")) == "TRUE")
        if not errors and confirmed_path and (checker == "forbidden_operation" or forbidden_mandatory):
            offender = subject
        elif not errors and confirmed_path and checker in {"authentication", "protection"}:
            offender = required.get(identifier, {}).get("bypass_subject")
        if offender not in names:
            offender = None
        if offender:
            violators[offender].add(identifier)
        cause_keys = {key for key in finding.get("cause_components", []) if key in names}
        if status == "FAIL":
            for shared in finding.get("common_dependencies", []):
                cause_keys.update(key for key in shared.get("dependencies", []) if key in names)
            if checker == "recovery":
                for entry in finding.get("evidence", []):
                    if entry.get("predicate") in {"key_accessible", "readable"} and entry.get("value") == "FALSE":
                        cause_keys.update(key for key in entry.get("args", []) if key in names)
            if finding.get("object") in names:
                affected[finding["object"]].add(identifier)
            if checker in {"label_flow", "clearance"}:
                for key in (finding.get("source") or required.get(identifier, {}).get("source"), subject):
                    if key in names:
                        affected[key].add(identifier)
            for key in cause_keys:
                causes[key].add(identifier)
            if offender:
                for edge in witness.get("edges", []):
                    if edge.get("id"):
                        witness_transitions[edge["id"]].add(identifier)
        if status in {"UNKNOWN", "REQUIRES_EVIDENCE", "NOT_CHECKED"}:
            for key in (finding.get("object"), subject):
                if key in names:
                    unknowns[key].add(identifier)
        name = finding.get("name")
        if not name or name in {checker, identifier}:
            name = _CHECKER_NAMES.get(checker, name or identifier)
        display_findings.append({
            "id": identifier, "rule_id": finding.get("rule_id", identifier), "name": name,
            "status": status, "checker": checker, "object": finding.get("object"), "subject": subject,
            "offender": offender, "operation": finding.get("operation"),
            "source": finding.get("source") or required.get(identifier, {}).get("source"),
            "mandatory": deepcopy(mandatory),
            "path": list(witness.get("nodes", [])) if witness.get("certain") is True else [],
            "path_is_violation": bool(offender), "causes": sorted(cause_keys),
            "unknowns": deepcopy(finding.get("unknowns", [])),
            "message": _message(dict(finding, source=finding.get("source") or required.get(identifier, {}).get("source")), names, offender, sorted(cause_keys)),
        })

    nodes = []
    for key in sorted(names):
        source = names[key]
        state_values = {predicate: _value(facts.boolean(predicate, [key])) if not errors else "UNKNOWN"
                        for predicate in ("present", "enabled", "healthy")}
        nodes.append({"key": key, "name": source.get("name", key), "pc": source.get("pc"), "cluster": _cluster(source),
                      "types": deepcopy(source.get("types", ["unknown"])), **state_values,
                      "available": _value(engine.availability.get(key, "UNKNOWN")) if engine else "UNKNOWN",
                      "is_violator": bool(violators[key]), "violations": sorted(violators[key]),
                      "affected": sorted(affected[key]), "causes": sorted(causes[key]), "unknowns": sorted(unknowns[key]),
                      "changed": bool(changes_by_node[key]), "changes": changes_by_node[key],
                      **{field: deepcopy(source[field]) for field in ("security_label", "integrity_label", "clearance") if field in source}})
    nodes_by_key = {node["key"]: node for node in nodes}
    edges = []
    source_graph = model.get("source_graph", model.get("raw_graph", {}))
    if not isinstance(source_graph, dict):
        source_graph = {}
    raw_edges = source_graph.get("edges", [])
    pair_occurrences = Counter()
    for offset, raw in enumerate(raw_edges if isinstance(raw_edges, list) else []):
        if isinstance(raw, dict):
            source, target = raw.get("source"), raw.get("target")
            provenance = raw.get("provenance", [])
        elif isinstance(raw, (list, tuple)) and len(raw) == 2:
            source, target = raw
            provenance = []
        else:
            diagnostics.append({"code": "INVALID_RAW_EDGE", "index": offset})
            continue
        if not isinstance(source, str) or not isinstance(target, str) or source not in names or target not in names:
            diagnostics.append({"code": "UNKNOWN_EDGE_ENDPOINT", "source": source, "target": target})
            continue
        value = _value(conjunction([nodes_by_key[source]["present"], nodes_by_key[target]["present"]]))
        occurrence = pair_occurrences[(source, target)]
        pair_occurrences[(source, target)] += 1
        identifier = "structural:" + json.dumps([source, target], ensure_ascii=False, separators=(",", ":"))
        if occurrence:
            identifier += f":duplicate:{occurrence}"
        edges.append({"id": identifier, "source": source, "target": target,
                      "kind": "structural", "value": value, "blocked": value == "FALSE", "witness": False,
                      "changed": any(("present", (k,)) in changed_atoms for k in (source, target)),
                      "violations": [], "origin": _origin(provenance) or ["imported"],
                      "label": "Исходная связь; сама по себе не означает доступ"})
    if not source_graph:
        diagnostics.append({"code": "NO_STRUCTURAL_SOURCE", "message": "Исходная топология не приложена. Показаны все узлы и явно заданные отношения модели."})

    transitions = model.get("transitions", []) if isinstance(model.get("transitions", []), list) else []
    evaluated = {}
    def availability_changed(key, seen=None):
        seen = set() if seen is None else set(seen)
        if key in seen:
            return False
        seen.add(key)
        if any((p, (key,)) in changed_atoms for p in ("present", "enabled", "healthy")):
            return True
        equation = model.get("dependencies", {}).get(key, {}) if isinstance(model.get("dependencies", {}), dict) else {}
        if not isinstance(equation, dict):
            return False
        return any(availability_changed(dep, seen) for refs in equation.values() if isinstance(refs, list) for dep in refs if isinstance(dep, str))

    def condition_changed(condition):
        if _atom(condition) in changed_atoms:
            return True
        predicate, args = condition.get("predicate"), condition.get("args", [])
        if args and predicate == "available":
            return availability_changed(args[0])
        if args and predicate == "transport":
            return any((p, (args[0],)) in changed_atoms for p in ("present", "healthy", "transport_enabled", "failure_mode"))
        if args and predicate == "fls_channel":
            return any(channel.get("id") == args[0] and _physical_route_changed(channel, changed_atoms)
                       for channel in model.get("fls_channels", []) if isinstance(channel, dict))
        return False
    if engine:
        # One exact engine traversal per fixed context evaluates every declared
        # transition in that context. No independent interpretation of ACLs.
        contexts = {}
        for transition in transitions:
            context = (transition["subject"], transition["operation"], transition.get("scenario", "default"), transition.get("kind", "access"))
            contexts.setdefault(context, transition["target"])
        for (subject, operation, scenario, kind), target in sorted(contexts.items()):
            result = engine.reachability(subject, target, operation, scenario, kind)
            evaluated.update({entry["id"]: entry for entry in result["evaluated_transitions"]})
    for transition in transitions:
        if (not isinstance(transition, dict) or not isinstance(transition.get("id"), str)
                or not isinstance(transition.get("source"), str) or not isinstance(transition.get("target"), str)
                or transition["source"] not in names or transition["target"] not in names):
            continue
        entry = evaluated.get(transition.get("id"), transition)
        value = _value(entry.get("value", "UNKNOWN")) if engine else "UNKNOWN"
        evaluated_conditions = entry.get("evaluated_conditions", []) if engine else []
        edge_changed = any(condition_changed(condition) for condition in evaluated_conditions)
        identifier = transition.get("id", "unknown_transition")
        edges.append({"id": f"transition:{identifier}", "transition_id": identifier,
                      "source": transition["source"], "target": transition["target"],
                      "kind": transition.get("kind", "access"), "value": value, "blocked": value == "FALSE",
                      "witness": bool(witness_transitions[identifier]), "violations": sorted(witness_transitions[identifier]),
                      "changed": edge_changed, "subject": transition.get("subject"), "operation": transition.get("operation"),
                      "scenario": transition.get("scenario", "default"), "conditions": deepcopy(evaluated_conditions),
                      **({"channel_id": transition["channel"]} if "channel" in transition else {}),
                      "origin": _origin(transition.get("provenance", [])),
                      "label": f"{transition.get('operation', 'операция')} · {_name(names, transition.get('subject'))}"})

    # Explicit typed relations explain controls, copies, and dependencies even
    # in compact fixtures without a raw graph. They are never invented from a
    # component name or taken as operation transitions.
    relation_endpoints = {
        "physical": (0, 1), "channel": (0, 1), "stores": (0, 1), "executes": (0, 1),
        "owns": (0, 1), "authenticates": (0, 1), "cover": (2, 0), "logger": (0, 1),
        "backup": (0, 1), "key_required": (0, 1), "independent": (0, 1), "has_role": (0, 1),
    }
    relation_labels = {"physical": "Физическое соединение", "channel": "Канал передачи", "stores": "Хранит", "executes": "Исполняет",
                       "owns": "Владелец", "authenticates": "Аутентификация", "cover": "Покрывает защитой", "logger": "Регистрация события",
                       "backup": "Резервная копия", "key_required": "Необходимый ключ", "independent": "Независимость", "has_role": "Полномочие"}
    relation_seen = set()
    for fact in model.get("facts", []) if valid_fact_shape else []:
        predicate, args = fact.get("predicate"), fact.get("args", [])
        if predicate not in relation_endpoints or len(args) != len(PREDICATES[predicate]):
            continue
        source_index, target_index = relation_endpoints[predicate]
        source, target = args[source_index], args[target_index]
        atom = _atom(fact)
        if source not in names or target not in names or atom in relation_seen:
            continue
        relation_seen.add(atom)
        declared_value = _value(facts.boolean(predicate, args)) if not errors else "UNKNOWN"
        states = [declared_value, nodes_by_key[source]["present"], nodes_by_key[target]["present"]]
        mechanism = source if predicate == "cover" else target if predicate == "logger" else None
        if mechanism:
            states.append(_value(engine.availability.get(mechanism, "UNKNOWN")) if engine else "UNKNOWN")
        value = _value(conjunction(states))
        relation_changed = (atom in changed_atoms or any(("present", (key,)) in changed_atoms for key in (source, target))
                            or bool(mechanism and availability_changed(mechanism)))
        edges.append({"id": "relation:" + predicate + ":" + json.dumps(args, ensure_ascii=False, separators=(",", ":")), "source": source, "target": target,
                      "kind": predicate, "value": value, "declared_value": declared_value, "blocked": value == "FALSE", "witness": False,
                      "changed": relation_changed, "violations": [], "origin": _origin(fact.get("provenance", [])),
                      "label": relation_labels[predicate], "relation_args": list(args)})
    dependencies = model.get("dependencies", {})
    if isinstance(dependencies, dict):
        for source, equation in sorted(dependencies.items()):
            if source not in names or not isinstance(equation, dict):
                continue
            for mode, targets in sorted(equation.items()):
                if not isinstance(targets, list):
                    continue
                for target in targets:
                    if not isinstance(target, str) or target not in names:
                        continue
                    edges.append({"id": f"dependency:{source}:{mode}:{target}", "source": source, "target": target,
                                  "kind": "dependency", "value": "TRUE" if not errors else "UNKNOWN", "blocked": False,
                                  "witness": False, "changed": False, "violations": [], "origin": ["declared"],
                                  "label": "Обязательная зависимость" if mode == "all" else "Альтернативная зависимость", "mode": mode})
    channel_violations = defaultdict(set)
    for transition in transitions:
        if (isinstance(transition, dict) and isinstance(transition.get("id"), str)
                and isinstance(transition.get("channel"), str)):
            channel_violations[transition["channel"]].update(witness_transitions[transition["id"]])
    layer_edges = _layer_projection(model, names, errors, changed_atoms, diagnostics, channel_violations)
    clusters = defaultdict(list)
    for node in nodes:
        clusters[node["cluster"]].append(node["key"])
    cluster_records = [{"id": identifier, "name": "Общие ресурсы" if identifier == "shared" else identifier,
                        "node_keys": keys} for identifier, keys in sorted(clusters.items())]
    layer_values = {layer: {value: sum(edge["layer"] == layer and edge["effective_value"] == value
                                      for edge in layer_edges) for value in ("TRUE", "FALSE", "UNKNOWN")}
                    for layer in _LAYER_LEGEND}
    counts = Counter(finding["status"] for finding in display_findings)
    return {"schema_version": 1, "state": model.get("state"), "profile": model.get("profile"),
            "nodes": nodes, "edges": edges, "findings": display_findings, "diagnostics": diagnostics,
            "layer_edges": layer_edges, "layer_legend": deepcopy(_LAYER_LEGEND), "clusters": cluster_records,
            "summary": {"node_count": len(nodes), "structural_edges": sum(e["kind"] == "structural" for e in edges),
                        "semantic_edges": sum(e["kind"] != "structural" for e in edges),
                        "channel_count": len({edge["channel_id"] for edge in layer_edges}),
                        "layer_edge_count": len(layer_edges), "cluster_count": len(cluster_records),
                        "layer_counts": {layer: sum(edge["layer"] == layer for edge in layer_edges) for layer in _LAYER_LEGEND},
                        "layer_values": layer_values,
                        "violators": sorted(key for key, checks in violators.items() if checks),
                        "fail_count": counts["FAIL"], "unknown_count": counts["UNKNOWN"],
                        "unresolved_count": invalid_display_findings + sum(counts[s] for s in ("UNKNOWN", "REQUIRES_EVIDENCE", "NOT_CHECKED", "MODEL_ERROR")),
                        "absent_count": sum(n["present"] == "FALSE" for n in nodes),
                        "unknown_presence_count": sum(n["present"] == "UNKNOWN" for n in nodes)},
            "legend": {"structural": "Исходная связь, не право доступа", "violator": "Доказанный запрещённый доступ субъекта",
                       "witness": "Подтверждённый путь запрещённой операции", "blocked": "Переход заблокирован в этом состоянии",
                       "absent": "Объект отсутствует", "unknown": "Недостаточно данных", "changed": "Факт изменён действием"}}
