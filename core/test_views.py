"""HTTP adapter for the fixed local scenario catalogue; no shell execution."""
import json

from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

from analyzer.scenarios import scenario_catalog as catalogue, run_scenario as execute_scenario
from .template_registry import resolve_template, template_files


def _display_state(state):
    """Retain full graph and outcomes without repeating source-model evidence."""
    analysis = state['analysis']
    fields = ('state', 'profile', 'summary', 'model_errors', 'timing')
    result_fields = ('id', 'rule_id', 'name', 'checker', 'status', 'subject', 'object',
                     'operation', 'reason', 'cause_components')
    return {
        'graph': state['graph'],
        'analysis': {**{key: analysis[key] for key in fields if key in analysis},
                     'results': [{key: finding[key] for key in result_fields if key in finding}
                                 for finding in analysis.get('results', [])]},
    }


@require_POST
def security_scenario(request):
    """One explicit educational example for the simplified graph-only page.

    The complete XLSX inventory is a fixed, disclosed scenario assumption,
    not a conclusion from uploading a spreadsheet. Advanced APIs retain their
    independent strict defaults.
    """
    try:
        if int(request.META.get('CONTENT_LENGTH') or 0) > 4096:
            return JsonResponse({'error': 'Параметры запроса превышают 4 KiB.'}, status=413)
        if request.content_type != 'application/json':
            return JsonResponse({'error': 'Передайте параметры JSON.'}, status=415)
        payload = json.loads(request.body or b'{}')
        if not isinstance(payload, dict) or set(payload) - {'repair', 'template'} or not isinstance(payload.get('repair', False), bool):
            return JsonResponse({'error': 'Допустим только булев параметр repair.'}, status=400)
        template = resolve_template(payload.get('template', 'Шаблон №1'))
        if template is None:
            return JsonResponse({'error': 'Шаблон не найден. Выберите шаблон на главной странице.'}, status=400)
        # Only the original tutorial has the explicit four-PC assumptions and
        # repair catalogue. Other templates must analyze their own inventory,
        # not overlay that tutorial onto unrelated identifiers and clusters.
        if template.name != 'Шаблон №1':
            if payload.get('repair', False):
                return JsonResponse({'error': 'Для этого шаблона не задан каталог разрешённых исправлений.'}, status=400)
            from analyzer.importers import load_xlsx
            from .views import _structural_input
            path = template_files(template)['.xlsx']
            graph = load_xlsx(path, state='template-xlsx')
            graph['metadata']['uploaded_filename'] = path.name
            report = _structural_input(graph)
            report['filename'] = f'{template.name} · {path.name}'
            report['template'] = template.name
            return JsonResponse(report, json_dumps_params={'ensure_ascii': False})
        execution = execute_scenario('experiment', repair=payload.get('repair', False),
                                     closed_inventory=True, sources_dir=template)
        source = execution['report']
        report = {
            'kind': 'analysis_bundle', 'schema_version': 1, 'display_mode': 'fresh_analysis',
            'scenario': {'id': 'experiment', 'title': template.name if 'template' in payload else 'Четыре ПК и общий сетевой диск',
                         'closed_inventory': True, 'educational': True},
            'states': {'before': _display_state(source['states']['experiment'])},
            'assumptions': source.get('assumptions', []),
            'duration_ms': execution['duration_ms'],
            'notice': 'Учебный пример: Excel считается полным перечнем объектов. Права и изменения заданы явно в демонстрационном профиле.',
        }
        if 'repair' in source:
            repair = source['repair']
            fields = ('status', 'selected', 'objective_value', 'optimality_proven', 'checked_sets',
                      'limits', 'reason', 'targets', 'independently_rechecked')
            report['repair'] = {key: repair[key] for key in fields if key in repair}
            after = source['states'].get('repaired')
            if after and repair.get('status') in {'OPTIMAL_REPAIR', 'VERIFIED_CANDIDATE'}:
                actual = after['analysis']
                by_id = {finding['id']: finding['status'] for finding in actual['results']}
                targets = repair.get('targets', [])
                original_ids = {finding['id'] for finding in source['states']['experiment']['analysis']['results']}
                verified = (repair.get('independently_rechecked') is True and not actual.get('model_errors')
                            and targets and original_ids <= by_id.keys()
                            and all(status == 'PASS' for status in by_id.values())
                            and all(by_id.get(key) == 'PASS' for key in targets))
                if verified:
                    report['states']['repaired'] = _display_state(after)
                else:
                    report['repair']['status'] = 'VERIFICATION_FAILED'
                    report['repair']['reason'] = 'Целевые требования не подтверждены после повторного анализа.'
        return JsonResponse(report, json_dumps_params={'ensure_ascii': False})
    except RequestDataTooBig:
        return JsonResponse({'error': 'Слишком большой запрос.'}, status=413)
    except (ValueError, TypeError, UnicodeError) as exc:
        return JsonResponse({'error': str(exc)}, status=400, json_dumps_params={'ensure_ascii': False})
    except OSError:
        return JsonResponse({'error': 'Данные учебного сценария недоступны. Проверьте examples и data/sources.'}, status=503)


@require_GET
def scenario_catalog(request):
    return JsonResponse(catalogue(), json_dumps_params={"ensure_ascii": False})


@require_POST
def run_scenario(request, scenario_id):
    try:
        if int(request.META.get("CONTENT_LENGTH") or 0) > 4096:
            return JsonResponse({"error": "Параметры запроса превышают 4 KiB."}, status=413)
        if request.content_type != "application/json":
            return JsonResponse({"error": "Передайте параметры JSON."}, status=415)
        payload = json.loads(request.body or b"{}")
        if not isinstance(payload, dict) or set(payload) - {"repair", "closed_inventory"}:
            return JsonResponse({"error": "Допустимы только параметры repair и closed_inventory."}, status=400)
        if any(not isinstance(value, bool) for value in payload.values()):
            return JsonResponse({"error": "Параметры должны быть true или false."}, status=400)
        if scenario_id not in {item["id"] for item in catalogue()["scenarios"]}:
            return JsonResponse({"error": "Тестовый сценарий не найден."}, status=404)
        return JsonResponse(execute_scenario(scenario_id, **payload), json_dumps_params={"ensure_ascii": False})
    except RequestDataTooBig:
        return JsonResponse({"error": "Слишком большой запрос."}, status=413)
    except (ValueError, TypeError, UnicodeError) as exc:
        return JsonResponse({"error": str(exc)}, status=400, json_dumps_params={"ensure_ascii": False})
    except OSError:
        return JsonResponse({"error": "Файлы тестового сценария недоступны. Проверьте examples и data/sources."}, status=503)
