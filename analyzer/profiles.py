"""Import facts and explicit semantic overlays are kept separately in exports."""
from copy import deepcopy
import json
from pathlib import Path

from .model import empty_model, fact


def imported_model(graph):
    model = empty_model(graph.get('state', graph['metadata'].get('state', 'imported')), 'strict')
    model['source_graph'] = deepcopy(graph)
    model['nodes'] = {k: dict(deepcopy(n), types=['unknown']) for k, n in graph['nodes'].items()}
    model['facts'] = [fact('present', [k], 'TRUE', n.get('provenance', []))
                      for k, n in model['nodes'].items()]
    model['import_issues'] = deepcopy(graph.get('issues', []))
    return model


def apply_profile(model, path):
    profile = json.loads(Path(path).read_text(encoding='utf-8'))
    def bind_state(value):
        if isinstance(value, dict):
            if value.get('state') == 'profile_binding':
                value['template_state'] = value['state']
                value['state'] = model['state']
            for item in value.values():
                bind_state(item)
        elif isinstance(value, list):
            for item in value:
                bind_state(item)
    bind_state(profile)
    changed = deepcopy(model)
    changed['profile'] = profile['profile']
    changed['assumptions'] = deepcopy(profile.get('assumptions', []))
    for key, attrs in profile.get('nodes', {}).items():
        if key not in changed['nodes']:
            raise ValueError(f'profile references absent inventory object {key}; use explicit comparison for historical objects')
        changed['nodes'][key].update(deepcopy(attrs))
        changed['nodes'][key]['semantic_type_provenance'] = [{'file': str(path), 'json_key': f'nodes.{key}.types',
            'state': model['state'], 'raw_value': attrs.get('types'), 'kind': 'demo_assumption' if profile['profile'].startswith(('demo', 'quantum')) else 'declared',
            'transformation': 'explicit semantic type binding; not inferred from names or colors'}]
    for field in ('facts', 'requirements', 'transitions', 'completeness', 'mutable', 'action_catalog'):
        changed.setdefault(field, []).extend(deepcopy(profile.get(field, [])))
    changed['dependencies'].update(deepcopy(profile.get('dependencies', {})))
    changed.setdefault('dependency_provenance', {}).update({key: [{'file': str(path),
        'json_key': f'dependencies.{key}', 'state': model['state'], 'raw_value': expression,
        'kind': 'demo_assumption' if profile['profile'].startswith(('demo', 'quantum')) else 'declared',
        'transformation': 'explicit complete dependency equation'}]
        for key, expression in profile.get('dependencies', {}).items()})
    if 'policy' in profile:
        changed['policy'] = deepcopy(profile['policy'])
    if 'normative_profile' in profile:
        changed['normative_profile'] = deepcopy(profile['normative_profile'])
    changed['profile_source'] = str(path)
    return changed


def comparison_model(baseline, changed_graph, comparison):
    if comparison.get('mode') != 'html_baseline_xlsx_changed':
        raise ValueError('comparison_model requires explicit as_states comparison')
    model = deepcopy(baseline)
    model['parent_state'] = baseline['state']
    model['state'] = changed_graph.get('state', changed_graph['metadata'].get('state', 'changed'))
    model['source_graph'] = deepcopy(changed_graph)
    model['import_issues'] = deepcopy(changed_graph.get('issues', []))
    model['assumptions'].extend(deepcopy(comparison['assumptions']))
    model['diff'] = []
    for entry in comparison['presence_changes']:
        key = entry['key']
        provenance = [{'file': changed_graph['metadata'].get('file'), 'state': model['state'],
                       'raw_value': None, 'method': entry['reason'], 'kind': 'declared',
                       'assumption': comparison['assumptions']}]
        model['facts'] = [f for f in model['facts'] if (f['predicate'], f['args']) != ('present', [key])]
        model['facts'].append(fact('present', [key], entry['changed'], provenance))
        model['diff'].append({'predicate': 'present', 'args': [key], 'before': 'TRUE',
                              'after': entry['changed'], 'provenance': provenance})
    for key in comparison.get('missing_in_html', []):
        model['nodes'][key] = dict(deepcopy(changed_graph['nodes'][key]), types=['unknown'])
        model['facts'].append(fact('present', [key], 'TRUE', changed_graph['nodes'][key]['provenance']))
    # The semantic overlay is an explicit scenario invariant; raw edge changes
    # never become ACL, authentication, or transport facts by inference.
    model['comparison'] = deepcopy(comparison)
    return model
