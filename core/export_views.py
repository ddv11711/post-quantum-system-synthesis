"""Download verified XLSX repair simulations without storing original uploads."""
from io import BytesIO
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile, BadZipFile

from django.http import FileResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.core.exceptions import RequestDataTooBig

from analyzer.importers import load_xlsx, ImportFormatError
from analyzer.xlsx_repair_export import export_verified_model_workbook
from analyzer.scenarios import run_scenario
from .template_registry import resolve_template, template_files
from .analysis_configuration import template_analysis_config
from .views import MAX_UPLOAD_BYTES, _structural_input


def _export_mandate(source):
    from analyzer.mandate_repairs import repair_mandate_flows
    graph = load_xlsx(source, state='export-source')
    graph['metadata']['uploaded_filename'] = source.name
    report = _structural_input(graph)
    snapshot = report['states'].get('imported') or report['states'].get('uploaded')
    if not snapshot or snapshot['model'].get('profile') != 'mandate-flows-v1':
        raise ValueError('В этой таблице нет поддерживаемого профиля для переноса исправлений в Excel.')
    outcome = repair_mandate_flows(snapshot['model'], snapshot['analysis'])
    if outcome.get('status') != 'VERIFIED_CANDIDATE' or not outcome.get('independently_rechecked'):
        raise ValueError('Не найдены подтверждённые исправления мандатных потоков.')
    return export_verified_model_workbook(source, snapshot['model'], outcome['repaired_model'],
                                          mandate_result=outcome, description='Подтверждённое исправление мандатных потоков')


def _export_declared_scenario(source, folder, config):
    """A declared scenario is used only when specified by template metadata."""
    run = run_scenario(config['scenario'], repair=True,
                       closed_inventory=config['closed_inventory'], sources_dir=folder)
    report = run['report']
    repair = report.get('repair', {})
    if repair.get('status') not in {'OPTIMAL_REPAIR', 'VERIFIED_CANDIDATE'} or 'repaired' not in report.get('states', {}):
        raise ValueError('Не найдены подтверждённые исправления для выбранного профиля.')
    # The scenario runner has already independently checked all requirements;
    # the exporter repeats the check after serialising the model.
    before_state = report['states'].get(config['scenario'])
    if not isinstance(before_state, dict) or not isinstance(before_state.get('model'), dict):
        raise ValueError('Сценарий не предоставляет исходное состояние для экспорта.')
    before = before_state['model']
    after = report['states']['repaired']['model']
    # run_scenario() removes the heavy "comparison" field from each display
    # state, but keeps the full, provenance-bearing comparison at report level.
    # The XLSX exporter needs that comparison to restore the complete, verified
    # topology of a reinstated component (including shared/global endpoints).
    comparison = report.get('comparison')
    if isinstance(comparison, dict) and comparison.get('mode') == 'html_baseline_xlsx_changed':
        expected_hash = (comparison.get('sources') or {}).get('xlsx', {}).get('sha256')
        if not expected_hash or sha256(Path(source).read_bytes()).hexdigest() != expected_hash:
            raise ValueError('Исходный Excel не совпадает с таблицей проверенного сценария.')
        before = {**before, 'comparison': comparison}
    return export_verified_model_workbook(source, before, after,
                                          description='Исправления по явно заданному профилю ' + config['scenario'])


def _check_archive(upload):
    if not upload.name.lower().endswith('.xlsx') or upload.size <= 0 or upload.size > MAX_UPLOAD_BYTES:
        raise ValueError('Загрузите исходный Excel (.xlsx) размером до 32 МБ.')
    upload.seek(0)
    try:
        with ZipFile(upload) as package:
            members = package.infolist()
            if len(members) > 2048 or sum(item.file_size for item in members) > 64 * 1024 * 1024:
                raise ValueError('Excel содержит слишком много данных.')
    except BadZipFile as exc:
        raise ValueError('Файл не является корректным Excel.') from exc
    finally:
        upload.seek(0)


@require_POST
def export_repaired_xlsx(request):
    """Recompute+verify on the server; never trust browser-supplied repair IDs."""
    try:
        template_name = request.POST.get('template')
        upload = request.FILES.get('source_file')
        if bool(template_name) == bool(upload):
            raise ValueError('Выберите либо шаблон, либо исходный XLSX.')
        with TemporaryDirectory(prefix='repair-export-') as tmp:
            if template_name:
                folder = resolve_template(template_name)
                if folder is None:
                    raise ValueError('Неизвестный шаблон.')
                source = template_files(folder)['.xlsx']
                config = template_analysis_config(folder)
                if config['mode'] == 'declared_scenario':
                    payload, info = _export_declared_scenario(source, folder, config)
                else:
                    payload, info = _export_mandate(source)
            else:
                _check_archive(upload)
                # Preserve the original file only for the lifetime of request;
                # do not store it in the database, session or document library.
                source = Path(tmp) / 'uploaded.xlsx'
                with source.open('wb') as destination:
                    for part in upload.chunks():
                        destination.write(part)
                payload, info = _export_mandate(source)
        original = Path(upload.name if upload else source.name).stem
        mode = info['mode']
        name = original + '_после_исправления.xlsx'
        response = FileResponse(BytesIO(payload), as_attachment=True, filename=name,
                                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['X-Export-Mode'] = mode
        response['X-Export-Changed-Cells'] = str(info.get('cells', 0))
        response['X-Export-Added-Rows'] = str(info.get('added_rows', 0))
        response['X-Export-Changed-Facts'] = str(info.get('facts', 0))
        return response
    except RequestDataTooBig:
        return JsonResponse({'error': 'Слишком большой запрос для экспорта.'}, status=413)
    except (ValueError, TypeError, OSError, ImportFormatError, KeyError, BadZipFile) as exc:
        return JsonResponse({'error': str(exc)}, status=400, json_dumps_params={'ensure_ascii': False})
