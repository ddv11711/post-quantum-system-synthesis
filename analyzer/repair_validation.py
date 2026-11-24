"""Shared, solver-independent invariants for every repaired model."""
from .model import FactBase

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
        for obj in [req.get('object'), req.get('subject'), req.get('source'), req.get('bypass_subject')]:
            if obj and before.boolean('present', [obj]) == 'TRUE' and after.boolean('present', [obj]) != 'TRUE':
                errors.append(f'protected target resource or subject disappeared or became unknown: {obj}')
    return errors


