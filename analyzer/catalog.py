"""Lossless catalogue extraction and deliberately conservative coverage accounting.

Catalogue paragraphs are data, never instructions.  A checker mapping records a
formal *fragment*: importing text, or passing one fragment, cannot certify the
whole source requirement or establish its legal applicability.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree
from zipfile import ZipFile


FIELD_LABELS = {
    "Применимость": "applicability",
    "Нужные данные": "required_data",
    "Нарушение или ошибка": "violation",
    "Когда вывод неопределён": "unknown_condition",
    "Исправление": "repair",
    "Основание": "basis",
    "Режим": "mode",
    "Тип результата": "result_type",
}
RULE_HEADING = re.compile(r"^([A-Z]{2}\d{3})\s+(.+)$")
SECTION_HEADING = re.compile(r"^(\d{1,2})\s+([А-ЯЁ].+)$")
LABEL_RE = re.compile("(" + "|".join(map(re.escape, FIELD_LABELS)) + r"):\s*")


# Explicitly reviewed catalogue-to-checker mappings.  These are NOT keyword
# classifiers: each ID denotes only the formal fragment specified below.
MAPPING_IDS = {
    "forbidden_operation": "FT007 FT019 FT020 FT022 FT031 FT046 FT069 FT073 FT080 FT097 FT099 FT101 FT106 FT114 FT115 FT128 FT129 NT002 NT006 NT008 NT009 NT011 HW004 HW005 HW007 HW010 PR001 PR004 PR005 PR006 PR008 PR009 DT001 DT002 DT003 DT004 DT009 CR024 CR026 CR028 CR037 BK004 BK007 BK011 BK019 BK024 BK034",
    "required_operation": "ST009 FT086 FT121 NT006 BK029 BK030 BK036",
    "required_function": "ST002 ST006 ST009 FT055 FT062 FT086 FT089 FT090 FT110 FT134 HW001 HW002 HW003 HW009 CR029 BK032 BK036",
    "protection": "MD009 ST002 ST004 FT002 FT003 FT014 FT016 FT032 FT033 FT034 FT035 FT036 FT037 FT040 FT042 FT044 FT055 FT057 FT059 FT060 FT067 FT070 FT071 FT074 FT088 FT100 FT102 FT107 FT108 FT117 FT118 FT125 FT131 FT143 FT144 FT146 FT148 NT007 NT010 HW004 HW005 HW009 HW010 PR002 PR003 PR007 DT001 DT002 DT003 DT004 CR007 CR011 CR012 CR024 CR026 CR031 CR033 CR036 CR038 BK005 BK011 BK017 BK018 BK033 BK034 BK040",
    "authentication": "ST005 FT010 FT011 FT012 FT018 FT022 FT036 FT037 FT043 FT079 FT147 NT003 NT004 NT007 NT010 HW010 BK014 BK021",
    "logging": "FT029 FT064 FT065 FT067 FT076 FT081 CR015 CR035 CR036 BK013 BK016 BK037",
    "redundancy": "ST008 FT109 FT123 FT127 FT134 DT008 BK036",
    "recovery": "FT078 FT111 FT112 DT005 DT006 DT007 DT008 CR029 BK030 BK036",
    "configuration": "FT045 FT052 FT055 FT056 FT058 FT061 FT064 FT066 FT068 FT070 FT071 FT074 FT083 FT085 FT103 FT113 FT115 FT116 FT117 FT121 FT123 FT126 FT127 FT133 NT001 NT003 NT004 NT005 NT011 HW002 HW003 HW006 HW007 HW008 PR001 PR003 PR007 DT005 DT010 CR019 CR020 CR025 CR030 CR033 BK025 BK026 BK027 BK028 BK040",
    "incompatible_roles": "FT021 FT114 BK003 BK004 BK038",
    "authorized_change": "FT007 FT008 FT054 FT084 FT142 HW007 BK012 BK024",
    "crypto": "FT016 FT035 FT036 FT037 FT043 NT005 NT007 PR003 DT004 CR027 CR028 CR030 BK005 BK017 BK026 BK040 CR045",
    "quantum": "CR040 CR041 CR044 DT011 DT012",
}

UNSUPPORTED_REASONS = {
    "CR039": "Параметры сценария обязательны для quantum checker, но отдельного проверяющего модуля согласованности всей модели нарушителя и горизонта нет.",
    "CR042": "Ядро не реализует предъявление поддельной подписи, принятие её цепочкой доверия и переход к новой личности/полномочиям; пассивный quantum checker этого не доказывает.",
    "CR043": "Не реализована композиция раскрытия ключа обёртки и расшифрования зависимых хранимых данных в квантовом сценарии.",
    "CR046": "Не реализован анализ композиции гибридных криптографических алгоритмов и семантики AND/OR проверок подписей.",
    "CR047": "Quantum checker выводит normative_approval=NOT_CHECKED, но отдельный модуль проверки неправильных утверждений о нормативной допустимости отсутствует.",
    "ST010": "Отзыв прав и изменение действующих сеансов во времени не моделируются; доступны атомарные снимки ACL с явно заданными фактами.",
    "ST011": "Переходы со сменой личности и получением новых ролей явно отвергаются валидатором; динамическая семантика таких действий не поддержана.",
    "ST012": "Поддержаны атомарные совместимые изменения; предусловия и безопасность последовательности промежуточных состояний не проверяются.",
    "RP008": "Оптимизатор проверяет атомарный конечный снимок; безопасность промежуточных состояний последовательного плана не реализована.",
}


FORMALIZATIONS = {
    "forbidden_operation": {
        "condition": "CanPerform(subject, object, operation, scenario) AND Forbidden(subject, object, operation, scenario)",
        "input_facts": ["context-preserving transitions", "actual ACL", "subject foothold", "component availability", "immutable forbidden operation"],
        "completeness_scope": "transition relation for this subject/operation/scenario and finite node domain; required only for proving absence",
        "explanation": "A confirmed actual operation contradicts an explicitly applicable prohibition; a raw graph edge is not access.",
        "repair_templates": ["revoke a mutable actual ACL", "close a witnessed bypass while preserving required operations"],
        "covered_scope": "Explicitly enumerated forbidden operations; no automatic propagation to undeclared copies, contexts or interfaces.",
    },
    "required_operation": {
        "condition": "RequiredOperation(subject, object, operation, scenario) AND NOT CanPerform(subject, object, operation, scenario)",
        "input_facts": ["required operation", "actual transitions and ACL", "complete context boundary"],
        "completeness_scope": "all possible actual transitions for the required context",
        "explanation": "Loss of an operation is proved only when the possible transition graph has no path and its scope is complete.",
        "repair_templates": ["restore a permitted route or ACL", "restore required dependency"],
        "covered_scope": "Enumerated required operations; latency, throughput and temporal service guarantees require separate evidence.",
    },
    "required_function": {
        "condition": "RequiredFunction(component) AND NOT Available(component)",
        "input_facts": ["present", "enabled", "healthy", "dependencies in AND/OR groups", "explicit external operating evidence"],
        "completeness_scope": "component dependencies and every alternative dependency group",
        "explanation": "Availability uses grounded fixed-point dependencies; a self-supporting cycle remains unknown.",
        "repair_templates": ["restore or enable component", "restore an explicitly permitted alternative dependency"],
        "covered_scope": "Boolean operational availability; no physical performance model or inferred independence.",
    },
    "protection": {
        "condition": "RequiredControl(object, control) AND NOT ExistsAvailableCoveringMechanism(object, control)",
        "input_facts": ["required object/control", "cover(object, control, mechanism)", "mechanism availability"],
        "completeness_scope": "full candidate mechanisms and coverage for this object/control",
        "explanation": "A product name is insufficient; one working covering alternative suffices, absence requires a complete candidate scope.",
        "repair_templates": ["enable permitted mechanism", "restore covering mechanism", "repair declared coverage"],
        "covered_scope": "Explicit control coverage; adequacy, efficacy, certification and equivalence are independent inputs.",
    },
    "authentication": {
        "condition": "RequiredAuthentication(object, control) AND NOT ExistsAvailableCoveringMechanism(object, control)",
        "input_facts": ["required authentication control", "all allowed authentication alternatives", "coverage and availability"],
        "completeness_scope": "all authentication mechanisms for this protected operation; bypass paths require separate forbidden-operation checks",
        "explanation": "A missing password is not a bypass when a confirmed permitted alternative supplies authentication.",
        "repair_templates": ["restore authentication mechanism", "close a separately witnessed bypass"],
        "covered_scope": "Declared authentication coverage plus separately declared bypass checks; no inferred identity or privilege transition.",
    },
    "logging": {
        "condition": "RequiredLogging(event) AND EventPossible(event) AND NOT ExistsAvailableLoggerCovering(event)",
        "input_facts": ["event_possible", "logger coverage", "logger availability and dependencies"],
        "completeness_scope": "complete logger alternatives for this event",
        "explanation": "An enabled independent alternative logger can supply coverage without changing access permissions.",
        "repair_templates": ["enable logger", "restore event delivery dependency", "restore permitted coverage"],
        "covered_scope": "Explicit possible events and logger coverage; timestamps, retention and event-field fidelity need configuration/evidence checks.",
    },
    "redundancy": {
        "condition": "RequiredRedundancy(object) AND NOT IndependentAvailableAlternatives(object)",
        "input_facts": ["replica membership", "availability", "independence assertions", "declared shared failure dependencies"],
        "completeness_scope": "replicas and relevant failure domains",
        "explanation": "Two replicas are not proof of independence; a declared common dependency is evaluated in the named failure scenario.",
        "repair_templates": ["restore an independent permitted replica", "remove a declared shared dependency by an allowed action"],
        "covered_scope": "Declared independence and finite dependency/failure scenarios; diversity of product names alone is not independence.",
    },
    "recovery": {
        "condition": "RequiredRecovery(object) AND NOT ExistsUsableBackupWithAvailableKeys(object)",
        "input_facts": ["backup membership", "readable backup", "backup availability", "necessary key and key availability"],
        "completeness_scope": "all permitted copies, tools and required keys declared for the recovery scope",
        "explanation": "A readable backup is insufficient when an indispensable recovery key is unavailable.",
        "repair_templates": ["restore permitted copy", "restore recoverable key availability"],
        "covered_scope": "Explicit copy/key recoverability; age/RTO/performance must be supplied as independent configuration/evidence facts.",
    },
    "configuration": {
        "condition": "RequiredConfiguration(object, parameter, expected) AND Actual(object, parameter) != expected",
        "input_facts": ["explicit expected value", "actual parameter or integrity/trusted-boot fact", "fact provenance"],
        "completeness_scope": "specific actual parameter; missing measurement is UNKNOWN",
        "explanation": "Compares explicit observed configuration with the accepted expectation; it does not manufacture a measurement from a component name.",
        "repair_templates": ["change a permitted mutable configuration parameter"],
        "covered_scope": "Equality or explicit Boolean observed condition; no automatic scanning, expiration arithmetic or vulnerability matching.",
    },
    "incompatible_roles": {
        "condition": "Incompatible(role_a, role_b) AND HasRole(subject, role_a) AND HasRole(subject, role_b)",
        "input_facts": ["has_role", "explicit incompatible role pair"],
        "completeness_scope": "effective role assignments for the subject",
        "explanation": "Tests a declared incompatible pair, including shared subjects only when their actual identity is known.",
        "repair_templates": ["remove one permitted mutable role assignment"],
        "covered_scope": "Explicit pairwise incompatibility; no inferred administrative authority or organizational independence.",
    },
    "authorized_change": {
        "condition": "Changed(change) AND NOT Approved(change)",
        "input_facts": ["changed", "approved", "scope and provenance of the recorded change"],
        "completeness_scope": "approval evidence for this change; no document means UNKNOWN",
        "explanation": "Confirmed lack of approval of a confirmed change is a finding; collecting evidence is not an automatic repair.",
        "repair_templates": ["revert a permitted mutable configuration effect; historical approval is immutable"],
        "covered_scope": "Explicit change/approval facts; procedural sequence, impact assessment and historical attestations remain external.",
    },
    "crypto": {
        "condition": "RequiredCrypto(channel, property) AND NOT Protected(channel, property)",
        "input_facts": ["declared flow segment", "required cryptographic property", "concrete protection/configuration facts"],
        "completeness_scope": "every explicitly required segment, including any declared alternate mode",
        "explanation": "Checks the nominated segment and property; a VPN vertex does not establish cryptographic protection.",
        "repair_templates": ["restore protection on a nominated segment", "change compatible endpoint modes together"],
        "covered_scope": "Explicit segment protection; algorithm strength, certification and whole-flow inventory remain separate conditions.",
    },
    "quantum": {
        "condition": "Susceptible(algorithm, function, bits) AND material_available(attacker, channel) AND observes(attacker, channel) AND quantum_capable(attacker, horizon) AND horizon_valid(channel, horizon)",
        "input_facts": ["crypto_algorithm", "crypto_function", "crypto_bits", "material_available", "observes", "quantum_capable", "horizon_valid"],
        "completeness_scope": "specific scenario/function/material; unsupported algorithms or absent inputs remain UNKNOWN",
        "explanation": "Passive disclosure is separate from active read, write and administration; no ACL is modified by the scenario.",
        "repair_templates": ["replace explicitly mutable compatible crypto configuration; normative acceptability requires separate evidence"],
        "covered_scope": "Passive disclosure in the declared educational threat model for the explicitly supported algorithms; no active signature forgery, hybrid-composition analysis, cryptanalytic proof or legal certification.",
    },
}


def _paragraphs(path: Path) -> list[str]:
    if path.suffix.lower() == ".docx":
        with ZipFile(path) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        return ["".join(t.text or "" for t in p.findall(".//w:t", ns))
                for p in root.findall(".//w:p", ns)]
    if path.suffix.lower() == ".txt":
        return path.read_text(encoding="utf-8-sig").splitlines()
    raise ValueError("Catalogue must be DOCX or UTF-8 TXT")


def _fields(paragraphs: list[str]) -> dict[str, str]:
    text = "\n".join(paragraphs)
    matches = list(LABEL_RE.finditer(text))
    fields = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        fields[FIELD_LABELS[match.group(1)]] = text[match.end():end].strip()
    return fields


def _mapping(rule: dict[str, Any]) -> dict[str, Any]:
    ids = rule["rule_id"]
    checkers = [checker for checker, rule_ids in MAPPING_IDS.items()
                if ids in rule_ids.split()]
    fields = rule["fields"]
    needs_evidence = "документ или внешнее свидетельство" in fields.get("mode", "")
    if ids in UNSUPPORTED_REASONS:
        status = "unsupported"
        reason = UNSUPPORTED_REASONS[ids]
    elif checkers:
        status = "implemented"
        reason = "Исполняются перечисленные формальные фрагменты при явном задании их предикатов; весь исходный пункт автоматически не подтверждается."
    elif needs_evidence:
        status = "requires_evidence"
        reason = "Требуется документ или внешнее свидетельство из поля «Нужные данные»: " + fields.get("required_data", "не указано")
    elif ids.startswith(("MD", "ST", "RP", "RS")):
        status = "unsupported"
        reason = "Метаправило «" + rule["title"] + "»: отдельного проверяющего модуля для полного исходного условия нет. Поведенческие тесты ядра не являются PASS этого пункта для входной системы. Нужны: " + fields.get("required_data", "не указано")
    else:
        status = "requires_additional_data"
        reason = "Нет готового полного преобразования этого предметного условия в предикаты ядра. Нужны явно заданные данные и отдельная формализация: " + fields.get("required_data", "не указано")
    return {
        "support_status": status,
        "implementation_scope": "formal_fragment_only" if checkers else "none",
        "whole_rule_implemented": False,
        "mapping_provenance": {"file": "analyzer/catalog.py", "kind": "declared", "transformation": "explicit reviewed rule-ID to finite checker mapping", "version": "1"},
        "reason": reason,
        "checkers": [{"checker": name, **FORMALIZATIONS[name],
                      "test_refs": ["tests/test_engine.py", "tests/test_catalog.py"]}
                     for name in checkers],
        "uncovered_conditions": "Применимость, исходные нужные данные и условия вне covered_scope каждого фрагмента требуют отдельной проверки. " + fields.get("unknown_condition", ""),
        "evidence_required_by_source": needs_evidence,
        "evidence_checker": "evidence" if needs_evidence else None,
    }


def load_catalog(path: str | Path) -> dict[str, Any]:
    """Read all source fields without evaluating requirements or legacy node IDs."""
    path = Path(path)
    paragraphs = _paragraphs(path)
    rules: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    section = None
    current = None
    for number, paragraph in enumerate(paragraphs):
        match = RULE_HEADING.fullmatch(paragraph.strip())
        section_match = SECTION_HEADING.fullmatch(paragraph.strip())
        if match:
            if current is not None:
                current["fields"] = _fields(current["source_paragraphs"][1:])
                rules.append(current)
            current = {
                "rule_id": match.group(1), "title": match.group(2),
                "section": dict(section) if section else None,
                "source_paragraphs": [paragraph],
                "provenance": {"file": str(path), "location": f"word/document.xml:p[{number + 1}]" if path.suffix.lower() == ".docx" else f"line:{number + 1}",
                               "state": "catalogue", "original": paragraph,
                               "transformation": "OOXML text extraction" if path.suffix.lower() == ".docx" else "UTF-8 line extraction",
                               "kind": "imported"},
            }
        elif section_match and " — " not in paragraph:
            if current is not None:
                current["fields"] = _fields(current["source_paragraphs"][1:])
                rules.append(current)
                current = None
            section = {"number": int(section_match.group(1)), "title": section_match.group(2)}
            sections.append(section)
        elif paragraph.startswith("Приложение"):
            if current is not None:
                current["fields"] = _fields(current["source_paragraphs"][1:])
                rules.append(current)
                current = None
        elif current is not None:
            current["source_paragraphs"].append(paragraph)
    if current is not None:
        current["fields"] = _fields(current["source_paragraphs"][1:])
        rules.append(current)
    counts = Counter(r["rule_id"] for r in rules)
    duplicates = sorted(k for k, n in counts.items() if n != 1)
    if duplicates:
        raise ValueError("Duplicate catalogue rule IDs: " + ", ".join(duplicates))
    if not rules:
        raise ValueError("No rule headings found")
    text = "\n".join(paragraphs)
    version = re.search(r"версия\s+([\d.]+)", text)
    date = re.search(r"(\d{1,2}) ноября (\d{4}) года", text)
    snapshot_date = f"{date.group(2)}-11-{int(date.group(1)):02d}" if date else None
    for rule in rules:
        rule["normative_snapshot_date"] = snapshot_date
        rule["applicability"] = {"value": "UNKNOWN", "condition": rule["fields"].get("applicability", ""),
                                 "source": "catalogue", "automatic_profile_activation": False}
        rule["formalization"] = _mapping(rule)
    return {
        "schema_version": "1.0", "title": paragraphs[0],
        "version": version.group(1) if version else None,
        "date": snapshot_date,
        "source": {"file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "format": path.suffix.lower()[1:], "paragraph_count": len(paragraphs)},
        "rule_count": len(rules), "section_count": len(sections),
        "sections": sections, "rules": rules,
        "fls_definition": None,
        "fls_note": "FLS/F/L/S не определено в предоставленном каталоге; цвета графа не типизируют безопасность.",
        "source_paragraphs": paragraphs,
        "legacy_appendix": "Приложения сохранены как исходный текст; числовые ID старого графа не переносятся в новый граф.",
        "legal_scope": "Основания и даты воспроизведены из приложенного каталога; актуальность законодательства заново не утверждается.",
    }


def coverage(catalog: dict[str, Any], analysis: dict[str, Any] | None = None,
             applicability: dict[str, str] | None = None) -> dict[str, Any]:
    """Account for every ID; PASS requires explicit complete scope and applicability.

    A finding can link ``catalog_rule_ids``.  This records evaluated fragments,
    but cannot itself prove applicability or complete coverage of a source rule.
    Explicit ``catalog_scope='complete'`` is a reviewed caller assertion.
    """
    applicability = applicability or {}
    results = (analysis or {}).get("results", [])
    entries = []
    for rule in catalog["rules"]:
        rule_id = rule["rule_id"]
        formalization = rule["formalization"]
        linked = [r for r in results if r.get("rule_id") == rule_id or
                  rule_id in r.get("catalog_rule_ids", [])]
        applies = str(applicability.get(rule_id, "UNKNOWN")).upper()
        if applies not in {"TRUE", "FALSE", "UNKNOWN"}:
            raise ValueError(f"Invalid applicability for {rule_id}: {applies}")
        reason = formalization["reason"]
        if applies == "FALSE":
            status = "NOT_APPLICABLE"
            reason = "Неприменимость явно подтверждена для этого правила и состояния."
        elif applies == "UNKNOWN":
            status = "UNKNOWN"
            reason = "Применимость исходного пункта не подтверждена; частные проверки и необходимость свидетельств показаны отдельно."
        elif (analysis or {}).get("model_errors") or any(r.get("status") == "MODEL_ERROR" for r in linked):
            status = "MODEL_ERROR"
            reason = "Связанная проверка обнаружила ошибку модели."
        elif any(r.get("status") == "FAIL" for r in linked):
            status = "FAIL"
            reason = "Подтверждён достаточный факт нарушения явно применимого формального условия; остальные неизвестности сохраняются."
        elif linked and all(r.get("status") == "PASS" and r.get("catalog_scope") == "complete" for r in linked):
            status = "PASS"
            reason = "Все связанные проверки выполнены, их полная область исходного пункта явно заявлена."
        elif any(r.get("status") == "UNKNOWN" for r in linked):
            status = "UNKNOWN"
            reason = "Неизвестны существенные входные факты связанной проверки."
        elif any(r.get("status") == "REQUIRES_EVIDENCE" for r in linked):
            status = "REQUIRES_EVIDENCE"
            reason = "Связанная проверка требует внешнего документного свидетельства."
        elif formalization["support_status"] == "requires_evidence":
            status = "REQUIRES_EVIDENCE"
        elif formalization["support_status"] == "requires_additional_data":
            status = "UNKNOWN"
        else:
            status = "NOT_CHECKED"
            if linked:
                reason = "Проверены только перечисленные формальные фрагменты; полнота проверки исходного пункта не заявлена."
        entries.append({
            "rule_id": rule_id, "title": rule["title"], "section": rule["section"],
            "support_status": formalization["support_status"], "status": status,
            "applicability": applies, "reason": reason,
            "checkers": [c["checker"] for c in formalization["checkers"]],
            "whole_rule_implemented": formalization["whole_rule_implemented"],
            "requires_evidence": formalization["evidence_required_by_source"],
            "evaluated_fragments": [{k: result.get(k) for k in ("id", "rule_id", "checker", "status", "object", "reason")}
                                    for result in linked],
            "uncovered_conditions": formalization["uncovered_conditions"],
        })
    return {"catalogue_date": catalog.get("date"), "rule_count": len(entries),
            "summary": dict(sorted(Counter(e["status"] for e in entries).items())),
            "support_summary": dict(sorted(Counter(e["support_status"] for e in entries).items())),
            "rules": entries,
            "note": "Support counts concern executable fragments, not whole regulatory compliance. Unknown applicability is never not-applicable."}


def write_registry(source: str | Path, output: str | Path) -> dict[str, Any]:
    catalog = load_catalog(source)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return catalog
