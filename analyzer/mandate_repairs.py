"""Verified, linear-size repair simulation for independent mandate-flow checks.

A user explicitly starts this simulation by pressing "Исправить нарушения".
It never changes the source workbook, the labels, the policy or any real system.
Only a definitely enabled, individually checked forbidden flow may be disabled.
The entire repaired model is re-analysed and all established PASS checks retained.
"""
from copy import deepcopy
from collections import Counter
from time import perf_counter

from .engine import analyze
from .model import FactBase, validate_model
from .structural_profiles import PROFILE_ID
from .transitions import apply_actions
from .repair_validation import preserve_protected_resources, validate_repair


def repair_mandate_flows(model, before=None):
    started = perf_counter()
    before = before if before is not None else analyze(model)
    failures = [item for item in before.get('results', []) if item.get('status') == 'FAIL']
    targets = [item['id'] for item in failures]
    result = {
        'status': 'NO_TARGET_VIOLATIONS', 'targets': targets, 'selected': [],
        'checked_sets': 0, 'optimality_proven': False,
        'method': 'independent_mandate_flows',
        'scope': 'simulate disabling only the individually verified forbidden data flows',
    }

    def finish(status, **kwargs):
        result.update(status=status, elapsed_seconds=perf_counter() - started, **kwargs)
        return result

    if model.get('profile') != PROFILE_ID or before.get('model_errors') or validate_model(model):
        return finish('MODEL_ERROR', reason='The model is not a valid mandate-flow model.')
    if not failures:
        return finish('NO_TARGET_VIOLATIONS', reason='No confirmed violations; unknown flows are not repaired.')
    if any(item.get('checker') != 'label_flow' for item in failures):
        return finish('NO_VALID_REPAIR_IN_ACTION_SPACE', reason='Unsupported violations require an explicit repair policy.')

    requirements = {req['id']: req for req in model['requirements']}
    transitions = {tr['id']: tr for tr in model['transitions']}
    if len(transitions) != len(model['transitions']):
        return finish('MODEL_ERROR', reason='Duplicate transition identifiers.')
    facts = FactBase(model)
    scenario_counts = Counter(tr.get('scenario') for tr in model['transitions'])
    actions = []
    # The profile creates one isolated semantic scenario for each individual
    # source edge. A completeness statement is required, so disabling the
    # edge proves absence of that flow instead of creating UNKNOWN.
    complete_contexts = {
        tuple(entry.get('args_prefix', []))
        for entry in model.get('completeness', [])
        if entry.get('predicate') == 'transitions' and entry.get('complete') is True
    }
    for identifier in sorted(targets):
        req, transition = requirements.get(identifier), transitions.get(identifier)
        if not req or not transition or req.get('scenario') != identifier or transition.get('scenario') != identifier:
            return finish('NO_VALID_REPAIR_IN_ACTION_SPACE', reason='Missing independent transition for failed flow.')
        context = (req['subject'], req['operation'], req['scenario'], req['kind'])
        if context not in complete_contexts or (
            transition.get('subject'), transition.get('operation'),
            transition.get('scenario'), transition.get('kind')
        ) != context:
            return finish('NO_VALID_REPAIR_IN_ACTION_SPACE', reason='The flow scope is not explicitly complete.')
        if (transition['source'] != req['source'] or transition['target'] != req['object']
                or transition.get('value') != 'TRUE'
                or transition.get('conditions') != [{'predicate': 'transition_enabled', 'args': [identifier]}]
                or facts.boolean('transition_enabled', [identifier]) != 'TRUE'):
            return finish('NO_VALID_REPAIR_IN_ACTION_SPACE', reason='The original flow cannot be safely disabled.')
        if scenario_counts[identifier] != 1:
            return finish('NO_VALID_REPAIR_IN_ACTION_SPACE', reason='Multiple alternatives require a different repair strategy.')
        actions.append({
            'id': 'disable-forbidden-flow:' + identifier,
            'operation': 'revoke_access',
            'object': transition['target'], 'cost': 1,
            'preconditions': [{'predicate': 'transition_enabled', 'args': [identifier], 'value': 'TRUE'}],
            'effects': [{'predicate': 'transition_enabled', 'args': [identifier], 'value': 'FALSE'}],
            'targets': [identifier],
            'provenance': [{'kind': 'user_requested_simulation', 'profile': PROFILE_ID,
                            'transformation': 'disable a confirmed violating isolated flow, without altering labels'}],
        })

    # Only the atoms specifically selected by the user's repair request are
    # mutable in this derived simulation. The original model stays unchanged.
    editable = deepcopy(model)
    permitted = {(item['predicate'], tuple(item['args'])) for item in editable.get('mutable', [])}
    for identifier in sorted(targets):
        key = ('transition_enabled', (identifier,))
        if key not in permitted:
            editable.setdefault('mutable', []).append({'predicate': key[0], 'args': list(key[1])})
    try:
        changed = apply_actions(editable, actions, new_state=str(model['state']) + ':repair')
        independent = analyze(changed)
        errors = validate_repair(before, independent, targets)
        errors += preserve_protected_resources(model, changed, targets)
    except (ValueError, KeyError, TypeError) as exc:
        return finish('VERIFICATION_FAILED', reason=str(exc), checked_sets=1)
    if errors:
        return finish('VERIFICATION_FAILED', reason='; '.join(errors[:8]), checked_sets=1)
    return finish('VERIFIED_CANDIDATE', selected=[a['id'] for a in actions],
                  checked_sets=1, objective_value=[len(actions), len(actions)],
                  independently_rechecked=True, repaired_model=changed, verification=independent)
