"""Z3 selects atomic action sets; Python independently checks every candidate."""
from __future__ import annotations

from copy import deepcopy
from time import perf_counter
import json

import z3

from .engine import analyze
from .model import FactBase, validate_model
from .transitions import apply_actions


def _key(fact):
    return fact['predicate'], tuple(fact['args'])


def generate_candidates(model, report=None):
    """Instantiate the declared finite action space around failed checks.

    Templates are executable, exact effects, not permissions to invent facts.
    Dependencies of relevant actions are included to permit joint repairs.
    """
    report = report or analyze(model)
    failures = {r['id'] for r in report['results'] if r['status'] == 'FAIL'}
    catalog = {a['id']: a for a in model.get('action_catalog', [])}
    used = set()
    def collect(value):
        if isinstance(value, dict):
            if 'predicate' in value and 'args' in value:
                used.add(_key(value))
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    for finding in report['results']:
        if finding['id'] in failures:
            collect(finding.get('evidence', []))
            collect(finding.get('witness'))
            collect(finding.get('derivation', []))
    selected = {i for i, a in catalog.items() if failures.intersection(a.get('targets', [])) or
                any(_key(e) in used for e in a.get('effects', []))}
    while True:
        more = {i for k in selected for i in catalog[k].get('requires', []) if i in catalog}
        if more <= selected:
            break
        selected |= more
    candidates = [deepcopy(catalog[i]) for i in sorted(selected)]
    for a in candidates:
        a['generation'] = {'failed_requirements': sorted(failures.intersection(a.get('targets', []))),
                           'matching_evidence_facts': [{'predicate': p, 'args': list(args)} for p, args in sorted({_key(e) for e in a.get('effects', [])} & used)],
                           'method': 'declared templates matched to failed checks, witness conditions, dependency proofs; prerequisite closure'}
    return candidates


def validate_repair(before, after, targets):
    """Targets must PASS; retain every check and every established PASS/FAIL."""
    errors = []
    if after.get('model_errors'):
        errors.append('MODEL_ERROR after actions')
    old = {r['id']: r for r in before['results']}
    new = {r['id']: r for r in after['results']}
    for target in targets:
        if new.get(target, {}).get('status') != 'PASS':
            errors.append(f'target {target} did not become PASS')
    for rid, prev in old.items():
        status = new.get(rid, {}).get('status')
        if status is None:
            errors.append(f'requirement disappeared: {rid}')
        elif status == 'FAIL' and prev['status'] != 'FAIL':
            errors.append(f'new violation: {rid}')
        elif prev['status'] == 'PASS' and status != 'PASS':
            errors.append(f'lost established compliance: {rid}')
        elif prev['status'] == 'FAIL' and status not in {'PASS', 'FAIL'}:
            errors.append(f'lost essential certainty: {rid}')
    return errors


def preserve_protected_resources(original, changed, targets):
    """Making the protected object disappear is not remediation."""
    before, after = FactBase(original), FactBase(changed)
    errors = []
    for req in original.get('requirements', []):
        for obj in [req.get('object'), req.get('subject'), req.get('bypass_subject')]:
            if obj and before.boolean('present', [obj]) == 'TRUE' and after.boolean('present', [obj]) != 'TRUE':
                errors.append(f'protected target resource or subject disappeared or became unknown: {obj}')
    return errors


def find_repairs(model, actions=None, targets=None, *, max_candidates=4096, timeout_seconds=30):
    """Exact lexicographic minimum in a finite declared action space.

    Invalid models are blocked by their exact Boolean assignment. No invalid
    subset implies that its supersets are invalid. Only actions enter Z3.
    """
    started = perf_counter()
    before = analyze(model)
    targets = sorted(targets if targets is not None else
                     [r['id'] for r in before['results'] if r['status'] == 'FAIL'])
    actions = deepcopy(actions if actions is not None else ([] if before.get('model_errors') else generate_candidates(model, before)))
    result = {'state': model.get('state') if isinstance(model, dict) else None, 'targets': targets, 'actions': actions,
              'objective': ['number_of_actions', 'sum_declared_costs'],
              'constraints': ['snapshot preconditions TRUE', 'declared mutable effects only',
                              'compatible atomic effects', 'targets PASS', 'no new FAIL',
                              'no loss of established compliance or essential certainty',
                              'protected target resources retain confirmed presence',
                              'full supported-profile reanalysis for all PCs'],
              'limits': {'max_candidates': max_candidates, 'timeout_seconds': timeout_seconds},
              'checked_sets': 0, 'rejected': [], 'optimality_proven': False,
              'plan_semantics': 'atomic compatible batch; intermediate states not certified'}

    def finish(status, **extra):
        result.update(status=status, elapsed_seconds=perf_counter()-started, **extra)
        return result

    if before.get('model_errors'):
        return finish('MODEL_ERROR', reason='inconsistent input is not a safe or repairable baseline')
    known = {r['id']: r['status'] for r in before['results']}
    if any(t not in known or known[t] != 'FAIL' for t in targets):
        return finish('INVALID_TARGET', reason='targets must be existing FAIL requirements')
    if not targets:
        return finish('NO_TARGET_VIOLATIONS', reason='UNKNOWN is not certified compliance')
    action_schema_model = dict(model, action_catalog=actions)
    if not isinstance(actions, list) or any(not isinstance(a, dict) for a in actions) or validate_model(action_schema_model):
        return finish('INVALID_ACTION_SPACE', reason='malformed action catalogue')
    ids = [a.get('id') for a in actions]
    if len(set(ids)) != len(ids) or any(not i for i in ids):
        return finish('INVALID_ACTION_SPACE', reason='action IDs must be unique and nonempty')
    if any(not isinstance(a.get('cost', 1), int) or a.get('cost', 1) < 0 for a in actions):
        return finish('INVALID_ACTION_SPACE', reason='cost must be a nonnegative integer')

    opt = z3.Optimize()
    opt.set(priority='lex')
    variables = [z3.Bool(f'action_{i}') for i in range(len(actions))]
    by_id = dict(zip(ids, variables))
    for i, a in enumerate(actions):
        for other in a.get('requires', []):
            opt.add(z3.Implies(variables[i], by_id.get(other, z3.BoolVal(False))))
        for other in a.get('excludes', []):
            if other in by_id:
                opt.add(z3.Not(z3.And(variables[i], by_id[other])))
        for j in range(i):
            left = {_key(e): e['value'] for e in a.get('effects', [])}
            right = {_key(e): e['value'] for e in actions[j].get('effects', [])}
            if any(left[k] != right[k] for k in left.keys() & right.keys()):
                opt.add(z3.Not(z3.And(variables[i], variables[j])))
    count = z3.Sum([z3.If(v, 1, 0) for v in variables]) if variables else z3.IntVal(0)
    cost = z3.Sum([z3.If(v, a.get('cost', 1), 0) for v, a in zip(variables, actions)]) if variables else z3.IntVal(0)
    count_obj = opt.minimize(count)
    cost_obj = opt.minimize(cost)
    while result['checked_sets'] < max_candidates:
        remaining = timeout_seconds - (perf_counter() - started)
        if remaining <= 0:
            return finish('SEARCH_LIMIT', reason='wall_clock_timeout')
        opt.set(timeout=max(1, int(remaining*1000)))
        status = opt.check()
        if status == z3.unsat:
            return finish('NO_VALID_REPAIR_IN_ACTION_SPACE', optimality_proven=True)
        if status != z3.sat:
            return finish('SEARCH_LIMIT', reason=f'z3: {opt.reason_unknown()}')
        assignment = opt.model()
        selected_bits = [z3.is_true(assignment.eval(v, model_completion=True)) for v in variables]
        selected = [a for a, bit in zip(actions, selected_bits) if bit]
        result['checked_sets'] += 1
        try:
            changed = apply_actions(model, selected, new_state=f"{model['state']}:repair")
            after = analyze(changed)
            errors = validate_repair(before, after, targets) + preserve_protected_resources(model, changed, targets)
        except (ValueError, KeyError, TypeError) as exc:
            errors = [str(exc)]
        if not errors:
            # A fresh JSON round trip avoids trusting cached results or objects.
            independent = analyze(json.loads(json.dumps(changed, ensure_ascii=False)))
            errors = validate_repair(before, independent, targets)
            if not errors:
                proven = (str(opt.lower(count_obj)) == str(opt.upper(count_obj)) and
                          str(opt.lower(cost_obj)) == str(opt.upper(cost_obj)))
                return finish('OPTIMAL_REPAIR' if proven else 'VERIFIED_CANDIDATE',
                              optimality_proven=proven, selected=[a['id'] for a in selected],
                              objective_value=[len(selected), sum(a.get('cost', 1) for a in selected)],
                              repaired_model=changed, verification=independent,
                              independently_rechecked=True)
        result['rejected'].append({'actions': [a['id'] for a in selected], 'reasons': errors})
        opt.add(z3.Or([v != z3.BoolVal(bit) for v, bit in zip(variables, selected_bits)]))
    return finish('SEARCH_LIMIT', reason='candidate_budget')
