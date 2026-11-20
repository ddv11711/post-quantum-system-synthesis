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
        return f"{_name(names, offender)} может {operation} «{target}», хотя это запрещено политикой."
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
    required = {r.get("id"): r for r in model.get("requirements", []) if isinstance(r, dict)} if isinstance(model.get("requirements", []), list) else {}
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
    for finding in analysis.get("results", []):
        if not isinstance(finding, dict):
            continue
        identifier = finding.get("id", "unknown_check")
        status = finding.get("status", "NOT_CHECKED")
        witness = finding.get("witness") or {}
        confirmed_path = status == "FAIL" and witness.get("certain") is True
        checker = finding.get("checker")
        subject = finding.get("subject")
        offender = None
        if not errors and confirmed_path and checker == "forbidden_operation":
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
        display_findings.append({
            "id": identifier, "rule_id": finding.get("rule_id", identifier), "name": finding.get("name", identifier),
            "status": status, "checker": checker, "object": finding.get("object"), "subject": subject,
            "offender": offender, "operation": finding.get("operation"),
            "path": list(witness.get("nodes", [])) if witness.get("certain") is True else [],
            "path_is_violation": bool(offender), "causes": sorted(cause_keys),
            "unknowns": deepcopy(finding.get("unknowns", [])),
            "message": _message(finding, names, offender, sorted(cause_keys)),
        })

    nodes = []
    for key in sorted(names):
        source = names[key]
        state_values = {predicate: _value(facts.boolean(predicate, [key])) if not errors else "UNKNOWN"
                        for predicate in ("present", "enabled", "healthy")}
        nodes.append({"key": key, "name": source.get("name", key), "pc": source.get("pc"),
                      "types": deepcopy(source.get("types", ["unknown"])), **state_values,
                      "available": _value(engine.availability.get(key, "UNKNOWN")) if engine else "UNKNOWN",
                      "is_violator": bool(violators[key]), "violations": sorted(violators[key]),
                      "affected": sorted(affected[key]), "causes": sorted(causes[key]), "unknowns": sorted(unknowns[key]),
                      "changed": bool(changes_by_node[key]), "changes": changes_by_node[key]})
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
        if not isinstance(transition, dict) or transition.get("source") not in names or transition.get("target") not in names:
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
                    if target not in names:
                        continue
                    edges.append({"id": f"dependency:{source}:{mode}:{target}", "source": source, "target": target,
                                  "kind": "dependency", "value": "TRUE" if not errors else "UNKNOWN", "blocked": False,
                                  "witness": False, "changed": False, "violations": [], "origin": ["declared"],
                                  "label": "Обязательная зависимость" if mode == "all" else "Альтернативная зависимость", "mode": mode})
    counts = Counter(finding["status"] for finding in display_findings)
    return {"schema_version": 1, "state": model.get("state"), "profile": model.get("profile"),
            "nodes": nodes, "edges": edges, "findings": display_findings, "diagnostics": diagnostics,
            "summary": {"node_count": len(nodes), "structural_edges": sum(e["kind"] == "structural" for e in edges),
                        "semantic_edges": sum(e["kind"] != "structural" for e in edges),
                        "violators": sorted(key for key, checks in violators.items() if checks),
                        "fail_count": counts["FAIL"], "unknown_count": counts["UNKNOWN"],
                        "unresolved_count": sum(counts[s] for s in ("UNKNOWN", "REQUIRES_EVIDENCE", "NOT_CHECKED", "MODEL_ERROR")),
                        "absent_count": sum(n["present"] == "FALSE" for n in nodes),
                        "unknown_presence_count": sum(n["present"] == "UNKNOWN" for n in nodes)},
            "legend": {"structural": "Исходная связь, не право доступа", "violator": "Доказанный запрещённый доступ субъекта",
                       "witness": "Подтверждённый путь запрещённой операции", "blocked": "Переход заблокирован в этом состоянии",
                       "absent": "Объект отсутствует", "unknown": "Недостаточно данных", "changed": "Факт изменён действием"}}
