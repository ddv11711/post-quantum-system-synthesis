"""Reproducible import → compare → analyze → repair → independently recheck."""
import argparse
from copy import deepcopy
from importlib.metadata import version
import json
from pathlib import Path
import platform
from time import perf_counter

from .catalog import load_catalog, coverage
from .engine import analyze
from .export import write_json, export_matrices, text_report
from .importers import load_html, load_xlsx, compare_sources
from .profiles import imported_model, apply_profile, comparison_model
from .repairs import find_repairs
from .transitions import apply_actions
from .visualization import build_graph

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT/'data/sources'


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _environment():
    return {'python': platform.python_version(), 'platform': platform.platform(),
            'packages': {p: version(p) for p in ('openpyxl', 'z3-solver', 'pytest', 'Django')},
            'method': 'one actual run, perf_counter wall time; not a speedup benchmark'}


def _sources(args):
    started = perf_counter()
    html = load_html(args.html, 'html_baseline')
    html_seconds = perf_counter()-started
    started = perf_counter()
    xlsx = load_xlsx(args.xlsx, 'xlsx_changed')
    return html, xlsx, {'html_import_seconds': html_seconds, 'xlsx_import_seconds': perf_counter()-started}


def demo(args):
    started = perf_counter()
    out = Path(args.out)
    html, xlsx, timings = _sources(args)
    comparison = compare_sources(html, xlsx, args.closed_inventory, as_states=True)
    strict = imported_model(html)
    strict_analysis = analyze(strict)
    baseline = apply_profile(strict, args.profile)
    changed = comparison_model(baseline, xlsx, comparison)
    experiment_spec = read_json(args.experiment)
    experiment = apply_actions(changed, experiment_spec['actions'], new_state='declared_experiment')
    experiment.setdefault('assumptions', []).append({'kind': 'demo_assumption', 'description': experiment_spec['description'], 'file': str(args.experiment)})
    models = {'baseline': baseline, 'changed': changed, 'experiment': experiment}
    reports = {k: analyze(m) for k, m in models.items()}
    repair = find_repairs(experiment, max_candidates=args.max_candidates, timeout_seconds=args.timeout)
    if 'repaired_model' in repair:
        models['repaired'] = repair['repaired_model']
        reports['repaired'] = analyze(read_json_roundtrip(models['repaired']))
    catalog = load_catalog(args.catalog)
    # Regulatory applicability is not inferred from a PC name or profile title.
    coverage_report = coverage(catalog, reports.get('repaired', reports['experiment']))
    strict_coverage = coverage(catalog, strict_analysis)
    write_json(out/'imports/html.json', html)
    write_json(out/'imports/xlsx.json', xlsx)
    write_json(out/'comparison.json', comparison)
    write_json(out/'strict_model.json', strict)
    write_json(out/'strict_analysis.json', strict_analysis)
    write_json(out/'strict_coverage.json', strict_coverage)
    for name, model in models.items():
        write_json(out/f'{name}_model.json', model)
        write_json(out/f'{name}_analysis.json', reports[name])
        write_json(out/f'{name}_matrices.json', export_matrices(model))
        write_json(out/f'{name}_diff.json', model.get('diff', []))
    write_json(out/'repair.json', repair)
    write_json(out/'coverage.json', coverage_report)
    timings.update({name: report['timing'] for name, report in reports.items()})
    timings['repair_seconds'] = repair['elapsed_seconds']
    timings['total_seconds_before_report_export'] = perf_counter()-started
    metrics = {'environment': _environment(), 'timings': timings,
               'sizes': {'html_nodes': len(html['nodes']), 'html_edges': len(html['edges']),
                         'xlsx_nodes': len(xlsx['nodes']), 'xlsx_edges': len(xlsx['edges']),
                         'catalog_rules': len(catalog['rules']), 'catalog_sections': len(catalog['sections']),
                         'checks': len(reports['baseline']['results'])},
               'search_limits': repair['limits'], 'checked_sets': repair['checked_sets']}
    write_json(out/'metrics.json', metrics)
    # Preserve complete display topology while avoiding repeated raw_data and
    # full edge provenance in the compact models included in the UI bundle.
    states = {k: {'model': {f: v for f, v in m.items() if f not in {'source_graph', 'comparison'}},
                  'analysis': reports[k], 'graph': build_graph(m, reports[k])} for k, m in models.items()}
    bundle = {'kind': 'analysis_bundle', 'schema_version': 1, 'states': states,
              'comparison': comparison, 'repair': {k: v for k, v in repair.items() if k not in {'repaired_model', 'verification'}},
              'coverage': coverage_report, 'assumptions': experiment['assumptions'], 'metrics': metrics,
              'strict_summary': {'analysis': strict_analysis['summary'], 'catalog': strict_coverage['summary'],
                                 'reason': 'Source files provide no policy, ACLs, operations or control coverage; no safety conclusion'}}
    write_json(out/'report.json', bundle)
    (out/'report.txt').write_text(text_report(bundle), encoding='utf-8')
    print(text_report(bundle))
    print('Artifacts:', out.resolve())
    return 0 if not any(a.get('model_errors') for a in reports.values()) else 2


def read_json_roundtrip(value):
    return json.loads(json.dumps(value, ensure_ascii=False))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Детерминированный логический анализ компонентных систем')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('import', help='independent source descriptions and differences')
    d = sub.add_parser('demo', help='explicit local profile and atomic repair experiment')
    for item in (p, d):
        item.add_argument('--html', default=SOURCES/'graf-svyazey-pk.html', type=Path)
        item.add_argument('--xlsx', default=SOURCES/'Четыре_конфигурации_ПК_уязвим.xlsx', type=Path)
        item.add_argument('--closed-inventory', action='store_true', help='explicitly assume XLSX fully enumerates present components')
        item.add_argument('--out', default=ROOT/'results/demo' if item is d else ROOT/'results/import', type=Path)
    p.add_argument('--as-states', action='store_true', help='HTML baseline, XLSX changed; otherwise independent descriptions')
    d.add_argument('--catalog', default=SOURCES/'katalog_pravil_logicheskogo_analizatora.docx', type=Path)
    d.add_argument('--profile', default=ROOT/'examples/demo_profile.json', type=Path)
    d.add_argument('--experiment', default=ROOT/'examples/experiment_actions.json', type=Path)
    d.add_argument('--max-candidates', default=4096, type=int)
    d.add_argument('--timeout', default=30.0, type=float)
    a = sub.add_parser('analyze', help='analyze a model or strictly import HTML/XLSX')
    a.add_argument('input', type=Path)
    a.add_argument('--profile', type=Path)
    a.add_argument('--out', type=Path, default=ROOT/'results/analysis')
    r = sub.add_parser('repair', help='search declared actions, recheck all supported requirements')
    r.add_argument('model', type=Path)
    r.add_argument('--actions', type=Path)
    r.add_argument('--max-candidates', default=4096, type=int)
    r.add_argument('--timeout', default=30.0, type=float)
    r.add_argument('--out', type=Path, default=ROOT/'results/repair.json')
    c = sub.add_parser('catalog', help='extract catalog and honest checker coverage')
    c.add_argument('--source', type=Path, default=SOURCES/'katalog_pravil_logicheskogo_analizatora.docx')
    c.add_argument('--out', type=Path, default=ROOT/'results/catalog')
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            return demo(args)
        if args.command == 'import':
            h, x, timing = _sources(args)
            comp = compare_sources(h, x, args.closed_inventory, as_states=args.as_states)
            for name, obj in [('html', h), ('xlsx', x), ('comparison', comp), ('timing', timing)]:
                write_json(args.out/f'{name}.json', obj)
            print(json.dumps({'html': h['metadata'], 'xlsx': x['metadata'], 'missing_in_xlsx': comp['missing_in_xlsx'], 'mode': comp['mode']}, ensure_ascii=False, indent=2))
        elif args.command == 'analyze':
            ext = args.input.suffix.lower()
            model = imported_model(load_html(args.input)) if ext == '.html' else imported_model(load_xlsx(args.input)) if ext == '.xlsx' else read_json(args.input)
            if args.profile:
                model = apply_profile(model, args.profile)
            report = analyze(model)
            write_json(args.out/'model.json', model)
            write_json(args.out/'analysis.json', report)
            if not report['model_errors']:
                write_json(args.out/'matrices.json', export_matrices(model))
            print(json.dumps(report['summary'], ensure_ascii=False))
            return 2 if report['model_errors'] else 0
        elif args.command == 'repair':
            report = find_repairs(read_json(args.model), read_json(args.actions) if args.actions else None,
                                  max_candidates=args.max_candidates, timeout_seconds=args.timeout)
            write_json(args.out, report)
            print(report['status'])
        elif args.command == 'catalog':
            catalog = load_catalog(args.source)
            write_json(args.out/'registry.json', catalog)
            report = coverage(catalog)
            write_json(args.out/'coverage.json', report)
            print(json.dumps(report['summary']))
    except (ValueError, KeyError, OSError, TypeError) as exc:
        parser.exit(2, f'MODEL/INPUT ERROR: {exc}\n')
    return 0
