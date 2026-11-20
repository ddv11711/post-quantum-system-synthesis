"""Small Django adapter for the public analyzer; no policy is invented here."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import FileResponse, Http404, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_GET, require_http_methods

from analyzer.engine import analyze
from analyzer.model import validate_model
from analyzer.importers import ImportFormatError, load_html, load_xlsx
from analyzer.profiles import imported_model
from analyzer.repairs import find_repairs, validate_repair, preserve_protected_resources
from analyzer.scenarios import _REPAIR_LOCK
from analyzer.reporting import analysis_scope

MAX_UPLOAD_BYTES = 32 * 1024 * 1024


DOCUMENTS_DIR = settings.BASE_DIR / "documents" / "normative"


@ensure_csrf_cookie
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
@require_http_methods(['GET', 'POST'])
def index(request):
    if request.method == 'GET':
        return render(request, "core/index.html")
    # A real multipart navigation carries the selected file across pages.
    # Use exactly the public upload pipeline, without retaining files in sessions.
    response = analyze_upload(request)
    payload = json.loads(response.content)
    context = {}
    if response.status_code == 200:
        context['initial_report'] = payload
    else:
        context['initial_error'] = payload.get('error', 'Не удалось загрузить файл.')
    try:
        upload = request.FILES.get('file')
        context['initial_filename'] = upload.name if upload is not None else ''
    except RequestDataTooBig:
        context['initial_filename'] = ''
    return render(request, "core/index.html", context, status=response.status_code)


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
    if (len(model["nodes"]) > 5000 or len(model.get("transitions", [])) > 20000
            or len(model.get("facts", [])) > 100000 or len(model.get("requirements", [])) > 10000):
        raise ValueError("Превышен размер интерактивной модели; используйте CLI.")


def _graph_state(model, analysis=None):
    """Keep source semantics and the presentation graph separate."""
    from analyzer.visualization import build_graph
    analysis = analyze(model) if analysis is None else analysis
    return {"model": model, "analysis": analysis, "graph": build_graph(model, analysis),
            "scope": analysis_scope(model, analysis)}


def _json_input(payload):
    if not isinstance(payload, dict):
        raise ValueError("Корневое значение JSON должно быть объектом.")
    if payload.get('kind') == 'structural_profile':
        from analyzer.structural_profiles import PROFILE_ID, compile_mandate_flows
        if set(payload) != {'kind', 'profile', 'graph'} or payload['profile'] != PROFILE_ID:
            raise ValueError('Выберите поддерживаемый профиль для исходного графа.')
        model = compile_mandate_flows(payload['graph'])
        _model_shape(model)
        filename = payload['graph'].get('metadata', {}).get('uploaded_filename', '')
        if not isinstance(filename, str):
            raise ValueError('Имя исходного файла должно быть строкой.')
        return {'kind': 'analysis_bundle', 'display_mode': 'fresh_analysis',
                'filename': filename, 'states': {'imported': _graph_state(model)},
                'assumptions': model['assumptions'], 'profile': model['detected_profile'],
                'notice': 'Выбран профиль мандатных потоков. Проверены прямые передачи между узлами с метками. '
                          'Стрелки трактуются как потоки данных; права доступа и допуски этим профилем не проверяются.'}
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
    from analyzer.portable import is_portable, load_portable
    if is_portable(model):
        model = load_portable(model)
        if 'repair_policy' in model and not validate_model(model):
            from analyzer.remediation import attach_repair_catalog
            model = attach_repair_catalog(model, model['repair_policy'])
    _model_shape(model)
    return {"kind": "analysis_bundle", "display_mode": "fresh_analysis",
            "states": {"uploaded": _graph_state(model)},
            "assumptions": model.get("assumptions", []),
                  "notice": "Модель проверена. Требования построены по явно заданным типам, политике и меткам."}


def _structural_input(graph):
    from analyzer.structural_profiles import detect_mandate_profile
    profile = detect_mandate_profile(graph)
    # In the confirmed cluster-workbook convention, non-marker arrows are data
    # transfers. Keep other structural formats strict, and never choose one of
    # conflicting mandate assignments merely to obtain a result.
    if (graph.get('format') == 'xlsx' and graph['metadata'].get('scope_column') == 'Кластер'
            and profile and profile['can_apply']):
        result = _json_input({'kind': 'structural_profile', 'profile': profile['id'], 'graph': graph})
        result.update(import_metadata=graph['metadata'], import_issues=graph['issues'], profile_applied='automatic')
        result['notice'] = ('Распознан Excel с мандатами. Стрелки означают передачу данных; номера мандатов задают порядок уровней. '
                            'Проверены прямые потоки между размеченными узлами. Связи без меток и неоднозначные ссылки требуют уточнения.')
        return result
    model = imported_model(graph)
    missing = ['Не задан смысл стрелок: взаимодействие, передача данных или разрешение конкретной операции.',
               'Не выбрана политика или профиль, определяющий допустимые и запрещённые действия.']
    if profile:
        missing.append('В графе обнаружены мандаты. Для их проверки выберите профиль и подтвердите трактовку связей.')
    else:
        missing.append('Для проверки безопасности нужны типы узлов, права, метки или требования к компонентам.')
    model['requirements'] = [{'id': 'import:semantic-readiness', 'checker': 'semantic_readiness',
                              'name': 'Данные для проверки безопасности', 'missing': missing}]
    return {'kind': 'analysis_bundle', 'display_mode': 'fresh_analysis',
            'states': {'imported': _graph_state(model)}, 'available_profiles': [profile] if profile else [],
            'import_metadata': graph['metadata'], 'import_issues': graph['issues'], 'assumptions': [],
            'notice': 'Граф загружен. Проверка безопасности не выполнена: исходные связи не задают права и требования. '
                      'Выберите подходящий профиль или загрузите данные с явной политикой.'}


@require_POST
def analyze_upload(request):
    """Accept one HTML/XLSX structural file, a semantic JSON model, or saved report."""
    try:
        if request.content_type == "application/json":
            if int(request.META.get("CONTENT_LENGTH") or 0) > MAX_UPLOAD_BYTES:
                return JsonResponse({"error": "Файл превышает 32 MiB."}, status=413)
            return JsonResponse(_json_input(json.loads(request.body)), json_dumps_params={"ensure_ascii": False})
        if len(request.FILES.getlist('file')) > 1:
            return JsonResponse({'error': 'Загрузите один граф за раз.'}, status=400)
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
                    from analyzer.portable_files import is_portable_workbook, load_portable_workbook
                    if is_portable_workbook(path):
                        result = _json_input(load_portable_workbook(path))
                        result['filename'] = filename
                        return JsonResponse(result, json_dumps_params={"ensure_ascii": False})
                    graph = load_xlsx(path, state="uploaded-xlsx")
                else:
                    graph = load_html(path, state="uploaded-html")
                graph["metadata"]["uploaded_filename"] = filename
                result = _structural_input(graph)
        if not result.get('filename'):
            result['filename'] = filename
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
        from analyzer.portable import is_portable, load_portable
        if is_portable(model):
            model = load_portable(model)
            if 'repair_policy' in model and not validate_model(model):
                from analyzer.remediation import attach_repair_catalog
                model = attach_repair_catalog(model, model['repair_policy'])
        _model_shape(model)
        before = analyze(model)
        with _REPAIR_LOCK:
            repair = find_repairs(model, max_candidates=512, timeout_seconds=15)
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


def _portable_example(name='security'):
    filenames = {'security': 'mixed_security.json', 'fls': 'fls_clusters.json'}
    if name not in filenames:
        raise ValueError('Неизвестный пример графа.')
    path = Path(__file__).resolve().parents[1] / 'examples' / 'portable' / filenames[name]
    return json.loads(path.read_text(encoding='utf-8'))


@require_POST
def graph_example(request):
    """An explicitly named example goes through the same path as uploaded graphs."""
    try:
        options = json.loads(request.body or b'{}')
        if not isinstance(options, dict) or set(options) - {'example'}:
            raise ValueError('Укажите только имя примера в поле example.')
        name = options.get('example', 'security')
        if not isinstance(name, str):
            raise ValueError('Имя примера должно быть строкой.')
        result = _json_input(_portable_example(name))
    except (ValueError, UnicodeError) as exc:
        return JsonResponse({'error': str(exc)}, status=400)
    result['filename'] = 'Пример: ПК1, ПК2 и три уровня связи' if name == 'fls' else 'Пример: права, метки и защита'
    result['example'] = True
    return JsonResponse(result, json_dumps_params={'ensure_ascii': False})


@require_GET
def download_example(request):
    try:
        payload = _portable_example(request.GET.get('example', 'security'))
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)
    if request.GET.get('format') == 'xlsx':
        from analyzer.portable_files import portable_workbook
        response = HttpResponse(portable_workbook(payload), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="security-graph.xlsx"'
    else:
        response = JsonResponse(payload, json_dumps_params={'ensure_ascii': False, 'indent': 2})
        response['Content-Disposition'] = 'attachment; filename="security-graph.json"'
    return response
