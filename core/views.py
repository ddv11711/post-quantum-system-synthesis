"""Small Django adapter for the public analyzer; no policy is invented here."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

from django.conf import settings
from django.http import FileResponse, Http404
from django.views.decorators.http import require_GET
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST

from analyzer.engine import analyze
from analyzer.importers import ImportFormatError, load_html, load_xlsx
from analyzer.profiles import imported_model
from analyzer.repairs import find_repairs, validate_repair, preserve_protected_resources
from analyzer.scenarios import _REPAIR_LOCK

MAX_UPLOAD_BYTES = 32 * 1024 * 1024


DOCUMENTS_DIR = settings.BASE_DIR / "documents" / "normative"


def landing(request):
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)

    documents = [
        {
            "filename": file.name,
            "title": file.stem,
        }
        for file in DOCUMENTS_DIR.iterdir()
        if file.is_file() and file.suffix.lower() == ".pdf"
    ]

    documents.sort(key=lambda item: item["title"].casefold())

    return render(request, "core/landing.html", {
        "documents": documents
    })


@require_GET
def download_normative(request, filename):
    # Разрешаем скачивать только PDF из установленной папки.
    if filename != Path(filename).name:
        raise Http404("Недопустимое имя файла")

    file_path = DOCUMENTS_DIR / filename

    if (
        file_path.suffix.lower() != ".pdf"
        or not file_path.is_file()
        or not file_path.resolve().is_relative_to(DOCUMENTS_DIR.resolve())
    ):
        raise Http404("Документ не найден")

    return FileResponse(
        open(file_path, "rb"),
        as_attachment=True,
        filename=file_path.name,
        content_type="application/pdf",
    )


@ensure_csrf_cookie
def index(request):
    return render(request, "core/index.html")


@ensure_csrf_cookie
def test_lab(request):
    return redirect("analysis")


def _model_shape(model):
    if not isinstance(model, dict) or not isinstance(model.get("nodes"), dict):
        raise ValueError("Модель должна содержать объект nodes и списки facts, requirements.")
    for field in ("facts", "requirements", "transitions", "completeness"):
        entries = model.get(field, [])
        if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
            raise ValueError(f"Поле {field} должно быть списком объектов.")
    if any(not isinstance(node, dict) for node in model["nodes"].values()):
        raise ValueError("Каждая запись nodes должна быть объектом.")
    if not isinstance(model.get("dependencies", {}), dict):
        raise ValueError("Поле dependencies должно быть объектом.")
    if len(model["nodes"]) > 5000 or len(model.get("transitions", [])) > 20000 or len(model.get("facts", [])) > 100000:
        raise ValueError("Превышен размер интерактивной модели; используйте CLI.")


def _graph_state(model, analysis=None):
    """Keep source semantics and the presentation graph separate."""
    from analyzer.visualization import build_graph
    analysis = analyze(model) if analysis is None else analysis
    return {"model": model, "analysis": analysis, "graph": build_graph(model, analysis)}


def _json_input(payload):
    if not isinstance(payload, dict):
        raise ValueError("Корневое значение JSON должно быть объектом.")
    if payload.get("kind") == "analysis_bundle":
        states = payload.get("states")
        if not isinstance(states, dict) or not states or len(states) > 32:
            raise ValueError("Отчет должен содержать от 1 до 32 состояний.")
        display_states = {}
        for name, state in states.items():
            if not isinstance(state, dict) or not isinstance(state.get("analysis"), dict):
                raise ValueError("Каждое состояние отчета должно содержать analysis.")
            if not isinstance(state["analysis"].get("results", []), list):
                raise ValueError("Поле analysis.results должно быть списком.")
            display_states[name] = dict(state)
            if isinstance(state.get("model"), dict):
                _model_shape(state["model"])
                if not isinstance(state.get("graph"), dict):
                    display_states[name]["graph"] = _graph_state(state["model"], state["analysis"])["graph"]
        # An existing report is shown, never confused with a freshly verified model.
        return {**payload, "states": display_states, "display_mode": "saved_report", "notice": "Загружен сохраненный отчет. Результаты показаны без повторного вычисления."}
    model = payload.get("model", payload)
    _model_shape(model)
    return {"kind": "analysis_bundle", "display_mode": "fresh_analysis",
            "states": {"uploaded": _graph_state(model)},
            "assumptions": model.get("assumptions", []),
            "notice": "Модель повторно проверена. Профиль, политика и допущения взяты из JSON."}


@require_POST
def analyze_upload(request):
    """Accept one HTML/XLSX structural file, a semantic JSON model, or saved report."""
    try:
        if request.content_type == "application/json":
            if int(request.META.get("CONTENT_LENGTH") or 0) > MAX_UPLOAD_BYTES:
                return JsonResponse({"error": "Файл превышает 32 MiB."}, status=413)
            return JsonResponse(_json_input(json.loads(request.body)), json_dumps_params={"ensure_ascii": False})
        upload = request.FILES.get("file")
        if upload is None:
            return JsonResponse({"error": "Выберите один файл HTML, XLSX или JSON."}, status=400)
        if upload.size > MAX_UPLOAD_BYTES:
            return JsonResponse({"error": "Файл превышает 32 MiB."}, status=413)
        filename = Path(upload.name).name
        suffix = Path(filename).suffix.lower()
        if suffix not in {".html", ".htm", ".xlsx", ".json"}:
            return JsonResponse({"error": "Поддерживаются HTML, XLSX и JSON."}, status=400)
        if suffix == ".json":
            result = _json_input(json.loads(upload.read()))
        else:
            with TemporaryDirectory(prefix="component-analyzer-") as directory:
                path = Path(directory) / filename
                with path.open("wb") as output:
                    for chunk in upload.chunks():
                        output.write(chunk)
                if suffix == ".xlsx":
                    with ZipFile(path) as archive:
                        entries = archive.infolist()
                        if len(entries) > 2048 or sum(item.file_size for item in entries) > MAX_UPLOAD_BYTES:
                            raise ValueError("Распакованный XLSX превышает лимит 32 MiB или 2048 элементов.")
                    graph = load_xlsx(path, state="uploaded-xlsx")
                else:
                    graph = load_html(path, state="uploaded-html")
                graph["metadata"]["uploaded_filename"] = filename
                model = imported_model(graph)
                result = {"kind": "analysis_bundle", "display_mode": "fresh_analysis",
                          "states": {"imported": _graph_state(model)},
                          "import_metadata": graph["metadata"], "import_issues": graph["issues"],
                          "assumptions": [],
                          "notice": "Строгий импорт: исходные связи не определяют ACL, операции или требования. Без семантического профиля защищенность не установлена; отсутствие находок не означает PASS."}
        return JsonResponse(result, json_dumps_params={"ensure_ascii": False})
    except RequestDataTooBig:
        return JsonResponse({"error": "Превышен лимит тела запроса; передайте JSON как загруженный файл."}, status=413)
    except (ImportFormatError, ValueError, TypeError, KeyError, UnicodeError, BadZipFile) as exc:
        return JsonResponse({"error": str(exc)}, status=400, json_dumps_params={"ensure_ascii": False})


@require_POST
def repair_model(request):
    """Repair only the explicitly supplied model and its declared action space."""
    try:
        if request.content_type == "application/json":
            if int(request.META.get("CONTENT_LENGTH") or 0) > MAX_UPLOAD_BYTES:
                return JsonResponse({"error": "Модель превышает 32 MiB."}, status=413)
            payload = json.loads(request.body)
        else:
            upload = request.FILES.get("file")
            if upload is None:
                return JsonResponse({"error": "Передайте модель для исправления."}, status=400)
            if upload.size > MAX_UPLOAD_BYTES:
                return JsonResponse({"error": "Модель превышает 32 MiB."}, status=413)
            payload = json.loads(upload.read())
        if not isinstance(payload, dict) or set(payload) != {"model"}:
            raise ValueError("Ожидается объект с единственным полем model.")
        model = payload["model"]
        _model_shape(model)
        before = analyze(model)
        with _REPAIR_LOCK:
            repair = find_repairs(model, max_candidates=64, timeout_seconds=10)
        states = {"before": _graph_state(model, before)}
        verified = None
        if repair.get("status") in {"OPTIMAL_REPAIR", "VERIFIED_CANDIDATE"} and "repaired_model" in repair:
            changed = repair["repaired_model"]
            verified = analyze(changed)
            errors = validate_repair(before, verified, repair["targets"]) + preserve_protected_resources(model, changed, repair["targets"])
            if errors:
                repair = {**repair, "status": "VERIFICATION_FAILED", "reason": "; ".join(errors)}
            else:
                states["repaired"] = _graph_state(changed, verified)
        result = {
            "kind": "analysis_bundle", "display_mode": "fresh_analysis", "states": states,
            "repair": {key: value for key, value in repair.items() if key not in {"repaired_model", "verification"}},
            "assumptions": model.get("assumptions", []),
            "notice": "Исправление выполнено на копии модели и повторно проверено." if "repaired" in states else
                      "Подтверждённого исправления нет. Исходный граф сохранён; результат поиска показан отдельно.",
        }
        return JsonResponse(result, json_dumps_params={"ensure_ascii": False})
    except RequestDataTooBig:
        return JsonResponse({"error": "Модель слишком велика для тела JSON; передайте её загруженным файлом."}, status=413)
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400, json_dumps_params={"ensure_ascii": False})
