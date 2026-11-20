"""Named, reproducible scenarios for the local test UI.

Scenario success means the engine reproduced the expected outcome, including
expected FAIL/UNKNOWN results. It is deliberately separate from system safety.
Only the fixed scenarios below may be run; request data never selects a path.
"""
from copy import deepcopy
import json
from pathlib import Path
from threading import Lock
from time import perf_counter

from .engine import analyze
from .importers import compare_sources, load_html, load_xlsx
from .profiles import apply_profile, comparison_model, imported_model
from .repairs import find_repairs
from .transitions import apply_actions
from .visualization import build_graph

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "data" / "sources" / "Shablon1"
EXAMPLES = ROOT / "examples"
_REPAIR_LOCK = Lock()  # Z3's default context is shared within this Python process.

_SCENARIOS = [
    {"id": "source_comparison", "title": "Сверка HTML и Excel", "category": "Исходные данные",
     "description": "Размеры графов, отсутствующие объекты и неоднозначные ссылки администратора.",
     "expected_summary": {}, "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Источники рассматриваются как независимые описания. Рёбра не определяют права доступа."]},
    {"id": "baseline", "title": "Базовая конфигурация", "category": "Четыре ПК",
     "description": "Все 12 локальных требований выполняются в явно заданном учебном профиле.",
     "expected_summary": {"PASS": 12}, "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Применяется examples/demo_profile.json; это учебные допущения, а не извлечённые ACL."]},
    {"id": "changed", "title": "Отсутствующие компоненты", "category": "Четыре ПК",
     "description": "Потеря фильтрации и сохранение аутентификации через альтернативный механизм.",
     "expected_summary": {"PASS": 11, "UNKNOWN": 1}, "expected_summary_closed": {"PASS": 11, "FAIL": 1},
     "can_repair": True, "uses_inventory_assumption": True,
     "assumptions": ["HTML — исходное состояние, XLSX — изменённое. Отсутствующая строка означает UNKNOWN до явного принятия полноты перечня."]},
    {"id": "experiment", "title": "Обход NAS и совместное исправление", "category": "Четыре ПК",
     "description": "Два пути запрещённого чтения NAS и выключенный регистратор. Проверка исправления сохраняет доступ всех четырёх ПК.",
     "expected_summary": {"PASS": 9, "FAIL": 2, "UNKNOWN": 1}, "expected_summary_closed": {"PASS": 9, "FAIL": 3},
     "can_repair": True, "uses_inventory_assumption": True,
     "assumptions": ["Изменения experiment_actions.json заданы отдельно и не были обнаружены в XLSX.",
                     "Поиск использует конечный каталог атомарных действий; стоимость каждого равна 1."]},
    {"id": "quantum", "title": "Пассивный квантовый сценарий", "category": "Криптография",
     "description": "Раскрытие наблюдаемого потока не создаёт активные права чтения или записи.",
     "expected_summary": {"FAIL": 2, "PASS": 1, "REQUIRES_EVIDENCE": 1},
     "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Алгоритм, наблюдение, материалы и условный горизонт явно заданы в quantum_profile.json.",
                     "Один ожидаемый FAIL — контрольное требование активного read; пассивное раскрытие его не удовлетворяет."]},
    {"id": "dependency_cycle", "title": "Цикл зависимостей", "category": "Изолированные модели",
     "description": "Компоненты не могут подтвердить работоспособность друг друга без внешнего основания.",
     "expected_summary": {"UNKNOWN": 1}, "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Изолированная фикстура, не описание реального ПК."]},
    {"id": "keyed_backup", "title": "Копия без ключа", "category": "Изолированные модели",
     "description": "Резервная копия не обеспечивает восстановление без необходимого доступного ключа.",
     "expected_summary": {"FAIL": 1}, "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Изолированная фикстура с полным перечнем копий и необходимых ключей."]},
    {"id": "common_dependency", "title": "Общая причина отказа", "category": "Изолированные модели",
     "description": "Две реплики с общей обязательной зависимостью не подтверждают независимое резервирование.",
     "expected_summary": {"FAIL": 1}, "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Изолированная фикстура: обе реплики зависят от одного источника питания."]},
    {"id": "configuration_and_duties", "title": "Конфигурация и полномочия", "category": "Изолированные модели",
     "description": "Целостность, загрузка, совмещение ролей, несогласованное изменение и защита канала.",
     "expected_summary": {"FAIL": 5, "REQUIRES_EVIDENCE": 1, "NOT_CHECKED": 1},
     "can_repair": False, "uses_inventory_assumption": False,
     "assumptions": ["Ожидаемые свидетельства и неподдержанный модуль показаны отдельно от нарушений."]},
]
_BY_ID = {item["id"]: item for item in _SCENARIOS}


def scenario_catalog():
    return {"scenarios": deepcopy(_SCENARIOS),
            "note": "Тест пройден, если результат совпал с ожиданием. Ожидаемые FAIL и UNKNOWN не означают ошибку теста.",
            "defaults": {"repair": False, "closed_inventory": False},
            "repair_limits": {"max_candidates": 64, "timeout_seconds": 10}}


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _state(model):
    # Full source edges are retained in the compact graph payload while model
    # provenance and raw_data are not repeated for each displayed state.
    analysis = analyze(model)
    return {"model": {key: value for key, value in model.items() if key not in {"source_graph", "comparison"}},
            "analysis": analysis, "graph": build_graph(model, analysis)}


def _expected_real(state, closed):
    expected = {f"pc{pc}_{name}_required": "PASS" for pc in range(1, 5) for name in ("nas", "os")}
    expected.update(pc1_filtering="PASS", pc2_auth="PASS", pc1_logging="PASS", nas_forbidden="PASS")
    if state in {"changed", "experiment"}:
        expected["pc1_filtering"] = "FAIL" if closed else "UNKNOWN"
    if state == "experiment":
        expected.update(pc1_logging="FAIL", nas_forbidden="FAIL")
    if state == "repaired" and not closed:
        expected["pc1_filtering"] = "UNKNOWN"
    return expected


def run_scenario(scenario_id, *, repair=False, closed_inventory=False, sources_dir=None):
    """Execute a trusted named scenario with explicitly selected assumptions."""
    if scenario_id not in _BY_ID:
        raise KeyError(scenario_id)
    if not isinstance(repair, bool) or not isinstance(closed_inventory, bool):
        raise ValueError("Параметры repair и closed_inventory должны быть boolean.")
    descriptor = _BY_ID[scenario_id]
    source_folder = Path(sources_dir) if sources_dir is not None else SOURCES
    if repair and not descriptor["can_repair"]:
        raise ValueError("Для этого сценария каталог исправлений не задан.")
    # Ignore neither scope nor consent: unrelated options have no effect and
    # are reported as unused, while changed-state completeness defaults open.
    effective_closed = closed_inventory if descriptor["uses_inventory_assumption"] else False
    started = perf_counter()
    expectations = []
    report = {"kind": "analysis_bundle", "schema_version": 1, "display_mode": "fresh_analysis",
              "notice": "Сценарий выполнен сейчас через публичный API анализатора.", "states": {}, "assumptions": []}

    def expect(label, expected, actual):
        expectations.append({"label": label, "expected": expected, "actual": actual, "passed": expected == actual})

    def verify_state(name, expected):
        analysis = report["states"][name]["analysis"]
        expect(f"{name}: статусы требований", expected, {item["id"]: item["status"] for item in analysis["results"]})
        expect(f"{name}: согласованность модели", [], analysis["model_errors"])

    if scenario_id in {"dependency_cycle", "keyed_backup", "common_dependency", "configuration_and_duties"}:
        model = _read(EXAMPLES / "fixtures" / (scenario_id + ".json"))
        expected_values = _read(EXAMPLES / "fixtures" / "expected.json")[scenario_id]
        report["states"]["fixture"] = _state(model)
        expect("Число требований фикстуры", len(expected_values), len(model["requirements"]))
        verify_state("fixture", dict(zip([r["id"] for r in model["requirements"]], expected_values)))
        report["assumptions"] = model.get("assumptions", [])
    else:
        html = load_html(next(file for file in source_folder.iterdir() if file.suffix.lower() in {".html", ".htm"}), "html_baseline")
        if scenario_id == "source_comparison":
            xlsx = load_xlsx(next(source_folder.glob("*.xlsx")), "xlsx_description")
            comparison = compare_sources(html, xlsx)
            report["states"] = {"html": _state(imported_model(html)), "xlsx": _state(imported_model(xlsx))}
            report["comparison"] = comparison
            expect("HTML: узлы и рёбра", [231, 1100], [len(html["nodes"]), len(html["edges"])])
            expect("XLSX: узлы и рёбра", [229, 1088], [len(xlsx["nodes"]), len(xlsx["edges"])])
            expect("Объекты без строки XLSX", ["1:59", "2:90"], comparison["missing_in_xlsx"])
            expect("Совпадающие рёбра", 1088, comparison["common_edges_count"])
            expect("Неоднозначные ссылки администратора", 61, len(comparison["ambiguous_references"]))
            expect("Источники независимы", "independent_descriptions", comparison["mode"])
            verify_state("html", {})
            verify_state("xlsx", {})
            report["assumptions"] = descriptor["assumptions"]
        elif scenario_id == "quantum":
            model = apply_profile(imported_model(html), EXAMPLES / "quantum_profile.json")
            report["states"]["quantum"] = _state(model)
            verify_state("quantum", {"passive_confidentiality": "FAIL", "active_read_not_created": "FAIL",
                                     "write_not_created": "PASS", "crypto_document": "REQUIRES_EVIDENCE"})
            report["assumptions"] = model["assumptions"]
        else:
            baseline = apply_profile(imported_model(html), (source_folder / "demo_profile.json" if (source_folder / "demo_profile.json").exists() else EXAMPLES / "demo_profile.json"))
            report["states"]["baseline"] = _state(baseline)
            verify_state("baseline", _expected_real("baseline", effective_closed))
            model = baseline
            if scenario_id in {"changed", "experiment"}:
                xlsx = load_xlsx(next(source_folder.glob("*.xlsx")), "xlsx_changed")
                comparison = compare_sources(html, xlsx, effective_closed, as_states=True)
                model = comparison_model(baseline, xlsx, comparison)
                report["comparison"] = comparison
                report["states"]["changed"] = _state(model)
                verify_state("changed", _expected_real("changed", effective_closed))
            if scenario_id == "experiment":
                spec = _read((source_folder / "experiment_actions.json" if (source_folder / "experiment_actions.json").exists() else EXAMPLES / "experiment_actions.json"))
                model = apply_actions(model, spec["actions"], new_state="declared_experiment")
                model["assumptions"].append({"kind": "demo_assumption", "description": spec["description"],
                                             "file": "examples/experiment_actions.json"})
                report["states"]["experiment"] = _state(model)
                verify_state("experiment", _expected_real("experiment", effective_closed))
            report["assumptions"] = deepcopy(model.get("assumptions", []))
            if repair:
                snapshot = deepcopy(model)
                with _REPAIR_LOCK:
                    found = find_repairs(model, max_candidates=64, timeout_seconds=10)
                report["repair"] = {k: v for k, v in found.items() if k not in {"repaired_model", "verification"}}
                expect("Исходное состояние не изменено", snapshot, model)
                # Keep the equality check in the test result without repeating
                # whole snapshots in every expected/actual payload.
                last = expectations[-1]
                last["expected"], last["actual"] = "неизменён", "неизменён" if last["passed"] else "изменён"
                if scenario_id == "changed" and not effective_closed:
                    expect("Неизвестность не считается устранимым нарушением", "NO_TARGET_VIOLATIONS", found["status"])
                else:
                    expect("Статус поиска", "OPTIMAL_REPAIR", found["status"])
                    expected_count = (4 if effective_closed else 3) if scenario_id == "experiment" else 1
                    expect("Минимум [число действий, стоимость]", [expected_count, expected_count], found.get("objective_value"))
                    expect("Минимальность доказана в объявленном каталоге", True, found.get("optimality_proven"))
                if "repaired_model" in found:
                    repaired = json.loads(json.dumps(found["repaired_model"], ensure_ascii=False))
                    report["states"]["repaired"] = _state(repaired)
                    verify_state("repaired", _expected_real("repaired", effective_closed))

    return {"scenario_id": scenario_id, "title": descriptor["title"],
            "duration_ms": round((perf_counter() - started) * 1000, 2),
            "options": {"repair": repair, "closed_inventory": effective_closed},
            "test": {"passed": all(item["passed"] for item in expectations), "expectations": expectations},
            "report": report}
