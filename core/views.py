"""Small Django adapter for the public analyzer; no policy is invented here."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.core.files.storage import FileSystemStorage
from django.utils.text import get_valid_filename
from django.urls import reverse
from django.contrib import messages
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
from .template_registry import list_templates, resolve_template, find_matching_template_for_workbook

MAX_UPLOAD_BYTES = 32 * 1024 * 1024


DOCUMENTS_DIR = settings.BASE_DIR / "documents" / "normative"
IMPORTED_DOCUMENTS_DIR = settings.BASE_DIR / "documents" / "imported"
MAX_NORMATIVE_PDF_BYTES = 20 * 1024 * 1024
MAX_NORMATIVE_PDF_FILES = 10


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
        "documents": documents,
        "imported_documents": _list_imported_pdfs(),
        "templates": list_templates(),
    })


def _list_imported_pdfs():
    """User-added documents are stored separately from built-in normative PDFs."""
    if not IMPORTED_DOCUMENTS_DIR.exists():
        return []
    root = IMPORTED_DOCUMENTS_DIR.resolve()
    files = [
        file for file in IMPORTED_DOCUMENTS_DIR.iterdir()
        if file.is_file() and file.suffix.casefold() == ".pdf"
        and file.resolve().is_relative_to(root)
    ]
    files.sort(key=lambda file: (-file.stat().st_mtime_ns, file.name.casefold()))
    return [{"filename": f.name, "title": f.name} for f in files]


def _upload_response(request, message, *, saved=None, status=200):
    if "application/json" in request.headers.get("Accept", ""):
        if saved is None:
            return JsonResponse({"error": message}, status=status, json_dumps_params={"ensure_ascii": False})
        return JsonResponse({"message": message, "saved": saved}, json_dumps_params={"ensure_ascii": False})
    if saved is None:
        messages.error(request, message)
    else:
        messages.success(request, message)
    return redirect(reverse("home") + "#normative")


@require_POST
def import_normative_pdfs(request):
    """Save up to 10 genuine PDF uploads to the isolated documents/imported folder."""
    try:
        files = request.FILES.getlist("files")
    except RequestDataTooBig:
        return _upload_response(request, "Превышен размер запроса.", status=413)
    if not files:
        return _upload_response(request, "Выберите хотя бы один PDF-файл.", status=400)
    if len(files) > MAX_NORMATIVE_PDF_FILES:
        return _upload_response(request, "За один раз можно загрузить не более 10 документов.", status=400)

    validated = []
    for upload in files:
        original = Path(upload.name.replace("\\", "/")).name
        if not original.lower().endswith(".pdf"):
            return _upload_response(request, "Поддерживаются только файлы PDF.", status=400)
        if upload.size > MAX_NORMATIVE_PDF_BYTES:
            return _upload_response(request, "Размер каждого PDF не должен превышать 20 МБ.", status=413)
        if upload.size < 5:
            return _upload_response(request, "Файл не является корректным PDF.", status=400)
        upload.seek(0)
        signature = upload.read(5)
        upload.seek(0)
        if signature != b"%PDF-":
            return _upload_response(request, "Файл не является корректным PDF.", status=400)
        # Keep friendly Cyrillic names, but never accept path separators or traversal.
        name = get_valid_filename(original)
        stem = Path(name).stem[:135].rstrip("._") or "document"
        validated.append((stem + ".pdf", upload))

    IMPORTED_DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    storage = FileSystemStorage(location=IMPORTED_DOCUMENTS_DIR)
    saved_names = []
    try:
        for name, upload in validated:
            saved_names.append(storage.save(name, upload))
    except OSError:
        for name in saved_names:
            storage.delete(name)
        return _upload_response(request, "Не удалось сохранить PDF на сервере.", status=500)

    saved = [{
        "filename": name,
        "title": name,
        "url": reverse("download-imported", kwargs={"filename": name}),
        "deleteUrl": reverse("delete-imported-normative", kwargs={"filename": name}),
    } for name in saved_names]
    message = "Документ успешно импортирован." if len(saved) == 1 else f"Импортировано документов: {len(saved)}."
    return _upload_response(request, message, saved=saved)


@require_GET
def download_imported(request, filename):
    """Only serve uploaded PDFs from the isolated user-document directory."""
    if filename != Path(filename).name or Path(filename).suffix.lower() != ".pdf":
        raise Http404("Недопустимое имя файла")
    path = IMPORTED_DOCUMENTS_DIR / filename
    if not path.is_file() or not path.resolve().is_relative_to(IMPORTED_DOCUMENTS_DIR.resolve()):
        raise Http404("Документ не найден")
    return FileResponse(open(path, "rb"), as_attachment=True,
                        filename=path.name, content_type="application/pdf")


@require_POST
def delete_imported_normative_pdf(request, filename):
    """Delete a previously uploaded imported PDF only from the isolated folder."""
    if filename != Path(filename).name or Path(filename).suffix.lower() != ".pdf":
        return JsonResponse({"error": "Недопустимое имя файла"}, status=400, json_dumps_params={"ensure_ascii": False})
    path = IMPORTED_DOCUMENTS_DIR / filename
    if not path.is_file() or not path.resolve().is_relative_to(IMPORTED_DOCUMENTS_DIR.resolve()):
        return JsonResponse({"error": "Документ не найден"}, status=404, json_dumps_params={"ensure_ascii": False})
    try:
        path.unlink()
    except OSError:
        return JsonResponse({"error": "Не удалось удалить документ."}, status=500, json_dumps_params={"ensure_ascii": False})
    return JsonResponse({
        "message": "Документ удалён.",
        "filename": filename,
    }, json_dumps_params={"ensure_ascii": False})


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
    """Support both existing templates and independently uploaded graphs."""
    context = {'selected_template': '', 'uploaded_mode': False}
    if request.method == 'POST':
        # Landing page only: if the selected XLSX is exactly the data of an
        # installed template, reuse its explicit policy and verification path.
        # Additional requirement attachments are a UI mock and never change
        # the selected template, model, rules, findings, or repair actions.
        upload = request.FILES.get('file')
        if (request.POST.get('match_existing_template') == '1'
                and upload is not None and upload.name.lower().endswith('.xlsx')
                and 0 < upload.size <= MAX_UPLOAD_BYTES):
            matched_template = find_matching_template_for_workbook(upload)
            if matched_template is not None:
                context['selected_template'] = matched_template.name
                context['initial_filename'] = upload.name
                # main.js uses the same scenario API as the template cards,
                # including the established repair behavior for template #1.
                return render(request, 'core/index.html', context)

        # The teammate's direct multipart import remains available without
        # storing files on disk or in the session.
        response = analyze_upload(request)
        payload = json.loads(response.content)
        if response.status_code == 200:
            context['initial_report'] = payload
            # Preserve only the main XLSX file *in the current page response* so
            # the user can simulate a repair without reuploading a 40+ MiB
            # expanded JSON model. Additional requirement files are not included.
            source = request.FILES.get('file')
            if (source and source.name.lower().endswith('.xlsx')
                    and source.size <= 5 * 1024 * 1024
                    and any(state.get('model', {}).get('profile') == 'mandate-flows-v1'
                            for state in payload.get('states', {}).values())):
                import base64
                source.seek(0)
                context['initial_repair_source'] = {
                    'filename': source.name,
                    'content': base64.b64encode(source.read()).decode('ascii'),
                }
        else:
            context['initial_error'] = payload.get('error', 'Не удалось загрузить файл.')
        try:
            upload = request.FILES.get('file')
        except RequestDataTooBig:
            upload = None
        context['initial_filename'] = upload.name if upload else ''
        context['uploaded_mode'] = True
        return render(request, 'core/index.html', context, status=response.status_code)

    source = request.GET.get('source')
    template_name = request.GET.get('template')
    if source == 'upload':
        context['uploaded_mode'] = True
    elif template_name:
        template = resolve_template(template_name)
        if template is None:
            return redirect('home')
        context['selected_template'] = template.name
    # Direct /analysis/ shows the analyser with an upload field; no
    # hidden demo or arbitrary default template is executed.
    return render(request, 'core/index.html', context)


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


def _compact_analysis_state(state):
    """Send graph and findings only; the browser already has the source model.

    Large mandate models can exceed 40 MiB due to provenance. Repair responses
    must not duplicate the raw source graph/model in both before/after states.
    """
    analysis = state['analysis']
    fields = ('state', 'profile', 'summary', 'model_errors', 'timing')
    finding_fields = ('id', 'rule_id', 'name', 'checker', 'status', 'subject', 'object',
                      'operation', 'reason', 'cause_components')
    compact = {
        'graph': state['graph'],
        'analysis': {**{key: analysis[key] for key in fields if key in analysis},
                     'results': [{key: item[key] for key in finding_fields if key in item}
                                 for item in analysis.get('results', [])]},
    }
    if state.get('scope') is not None:
        compact['scope'] = state['scope']
    model = state.get('model', {})
    if model.get('profile') == 'mandate-flows-v1':
        compact['model'] = {key: model[key] for key in ('profile', 'profile_coverage', 'detected_profile') if key in model}
    return compact


def _enable_mandate_repair(report):
    """Advertise the action only for a compiled model with confirmed flow FAILs."""
    for state in report.get('states', {}).values():
        if (state.get('model', {}).get('profile') == 'mandate-flows-v1'
                and any(entry.get('status') == 'FAIL' and entry.get('checker') == 'label_flow'
                        for entry in state.get('analysis', {}).get('results', []))):
            report['repair_capability'] = {'type': 'mandate_flow', 'simulation': True}
            break
    return report


def _repair_mandate_report(report):
    """Return a separately verified hypothetical repair for eligible flow models."""
    from analyzer.mandate_repairs import repair_mandate_flows
    from analyzer.structural_profiles import PROFILE_ID

    key = next((name for name in ('imported', 'uploaded', 'before') if name in report.get('states', {})), None)
    if key is None:
        raise ValueError('Нет исходной модели для исправления.')
    base = report['states'][key]
    model = base.get('model', {})
    if model.get('profile') != PROFILE_ID:
        raise ValueError('Для этой модели не задан поддерживаемый профиль исправления.')
    outcome = repair_mandate_flows(model, base['analysis'])
    compact_result = {
        **{field: value for field, value in report.items() if field != 'states'},
        'states': {'before': _compact_analysis_state(base)},
        'repair': {k: v for k, v in outcome.items() if k not in {'repaired_model', 'verification'}},
        'repair_capability': {'type': 'mandate_flow', 'simulation': True},
    }
    if outcome.get('status') == 'VERIFIED_CANDIDATE' and 'repaired_model' in outcome:
        compact_result['states']['repaired'] = _compact_analysis_state(
            _graph_state(outcome['repaired_model'], outcome['verification']))
        compact_result['notice'] = ('Моделирование: запрещённые потоки отключены в копии графа, '
                                    'все ранее выполненные требования проверены повторно. '
                                    'Исходный файл не изменён.')
    else:
        compact_result['notice'] = ('Исправление не подтверждено: исходное состояние сохранено. '
                                    'Непроверенные потоки не считаются исправленными.')
    return compact_result


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
        return _enable_mandate_repair({'kind': 'analysis_bundle', 'display_mode': 'fresh_analysis',
                'filename': filename, 'states': {'imported': _graph_state(model)},
                'assumptions': model['assumptions'], 'profile': model['detected_profile'],
                'notice': 'Выбран профиль мандатных потоков. Проверены прямые передачи между узлами с метками. '
                          'Стрелки трактуются как потоки данных; права доступа и допуски этим профилем не проверяются.'})
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
        _enable_mandate_repair(result)
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


MAX_ADDITIONAL_REQUIREMENT_FILES = 5
MAX_ADDITIONAL_REQUIREMENT_BYTES = 10 * 1024 * 1024


def _transient_requirements(request):
    """Validate non-persistent attachments; never write them to disk, DB or session.

    The analyzer evaluates machine-readable requirements in the primary model.
    Arbitrary PDF/DOCX/TXT cannot safely become executable security rules here.
    """
    uploaded = request.FILES.getlist("additional_requirements")
    if not uploaded:
        return []
    if len(uploaded) > MAX_ADDITIONAL_REQUIREMENT_FILES:
        raise ValueError("Можно приложить не более 5 документов с дополнительными требованиями.")
    documents = []
    for attachment in uploaded:
        filename = Path(attachment.name.replace("\\", "/")).name
        ext = Path(filename).suffix.lower()
        if ext not in {".pdf", ".docx", ".txt"}:
            raise ValueError("Дополнительные требования: поддерживаются только PDF, DOCX и TXT.")
        if not 0 < attachment.size <= MAX_ADDITIONAL_REQUIREMENT_BYTES:
            raise ValueError("Дополнительные требования: документ пустой или превышает 10 МБ.")
        marker = attachment.read(5)
        attachment.seek(0)
        if ext == ".pdf" and marker != b"%PDF-":
            raise ValueError("Дополнительные требования: выбранный PDF имеет неверный формат.")
        if ext == ".docx" and not marker.startswith(b"PK"):
            raise ValueError("Дополнительные требования: выбранный DOCX имеет неверный формат.")
        documents.append({"filename": filename, "size_bytes": attachment.size})
    return documents


def _annotate_transient_requirements(result, documents):
    if documents:
        result["additional_requirements"] = {
            "documents": documents,
            "persisted": False,
            "applied_to_automatic_checks": False,
        }
        result["notice"] = (result.get("notice", "").strip() + " "
            "Дополнительные документы получены только для текущего запроса и не сохранены. "
            "Их содержание не преобразовано в формальные правила и не учитывалось при автоматической проверке.").strip()
    return result


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
        ephemeral_documents = _transient_requirements(request)
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
                        unpacked = sum(item.file_size for item in entries)
                        if len(entries) > 2048 or unpacked > 96 * 1024 * 1024:
                            raise ValueError("Распакованный XLSX превышает допустимый размер или 2048 элементов.")
                        if unpacked > MAX_UPLOAD_BYTES:
                            from analyzer.security_workbook import has_security_extension
                            if not has_security_extension(path):
                                raise ValueError("Обычный XLSX превышает лимит 32 MiB.")
                    from analyzer.portable_files import is_portable_workbook, load_portable_workbook
                    if is_portable_workbook(path):
                        result = _json_input(load_portable_workbook(path))
                        result['filename'] = filename
                        return JsonResponse(_annotate_transient_requirements(result, ephemeral_documents), json_dumps_params={"ensure_ascii": False})
                    from analyzer.security_workbook import has_security_extension, read_security_extension
                    if has_security_extension(path):
                        graph = load_xlsx(path, state="uploaded-xlsx")
                        restored_model = read_security_extension(path, imported_graph=graph)
                        result = _json_input({'model': restored_model})
                        result['filename'] = filename
                        result['notice'] = ('Повторный анализ: формализованные параметры безопасности и требования '
                                            'прочитаны из Excel, результаты проверок вычислены заново. '
                                            'Сведения в файле являются данными модели, а не подтверждением '
                                            'реального изменения оборудования.')
                        return JsonResponse(_annotate_transient_requirements(result, ephemeral_documents),
                                            json_dumps_params={"ensure_ascii": False})
                    graph = load_xlsx(path, state="uploaded-xlsx")
                else:
                    graph = load_html(path, state="uploaded-html")
                graph["metadata"]["uploaded_filename"] = filename
                result = _structural_input(graph)
        if not result.get('filename'):
            result['filename'] = filename
        return JsonResponse(_annotate_transient_requirements(result, ephemeral_documents), json_dumps_params={"ensure_ascii": False})
    except RequestDataTooBig:
        return JsonResponse({"error": "Превышен лимит тела запроса; передайте JSON как загруженный файл."}, status=413)
    except (ImportFormatError, ValueError, TypeError, KeyError, UnicodeError, BadZipFile) as exc:
        return JsonResponse({"error": str(exc)}, status=400, json_dumps_params={"ensure_ascii": False})


@require_POST
def repair_model(request):
    """Repair a declared model, or re-import the source XLSX for flow simulation."""
    try:
        source = request.FILES.get('source_file')
        if source is not None:
            if not source.name.lower().endswith('.xlsx') or source.size > MAX_UPLOAD_BYTES:
                raise ValueError('Для повторного анализа передайте исходный XLSX размером не более 32 МБ.')
            with TemporaryDirectory(prefix='component-repair-') as directory:
                path = Path(directory) / Path(source.name).name
                with path.open('wb') as target:
                    for chunk in source.chunks():
                        target.write(chunk)
                with ZipFile(path) as archive:
                    items = archive.infolist()
                    if len(items) > 2048 or sum(item.file_size for item in items) > MAX_UPLOAD_BYTES:
                        raise ValueError('Распакованный XLSX превышает ограничения безопасности.')
                graph = load_xlsx(path, state='uploaded-xlsx')
                graph['metadata']['uploaded_filename'] = source.name
                report = _structural_input(graph)
                report['filename'] = source.name
                result = _repair_mandate_report(report)
                return JsonResponse(result, json_dumps_params={'ensure_ascii': False})
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
        if model.get('profile') == 'mandate-flows-v1' and not model.get('action_catalog'):
            report = {'kind': 'analysis_bundle', 'states': {'uploaded': _graph_state(model)}}
            return JsonResponse(_repair_mandate_report(report), json_dumps_params={'ensure_ascii': False})
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
