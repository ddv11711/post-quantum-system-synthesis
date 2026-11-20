"""Compile an explicit repair policy into a finite catalogue of exact effects.

No names, machine numbers, security labels or missing facts grant permission to
change the model. Each operation names the edges, ACL tuples or nodes its owner
allows changing. UNKNOWN values are never supplied by a repair action.
"""
from collections import defaultdict
from copy import deepcopy
import json

from .engine import analyze
from .model import FactBase, OPERATIONS, validate_model


def _atom(record):
    return record['predicate'], tuple(record.get('args', []))


def _strings(value, name):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f'{name} must be a list of nonempty exact identifiers')
    return value


def _path_transitions(model, requirement):
    """All declared alternatives in this context, not just its first witness."""
    flow = requirement.get('checker') == 'label_flow'
    subject, operation = requirement.get('subject'), requirement.get('operation', 'write' if flow else None)
    context = (subject, operation, requirement.get('scenario', 'default'), requirement.get('kind', 'flow' if flow else 'access'))
    transitions = [edge for edge in model.get('transitions', []) if
                   (edge['subject'], edge['operation'], edge.get('scenario', 'default'), edge.get('kind', 'access')) == context]
    forward, reverse = defaultdict(set), defaultdict(set)
    for edge in transitions:
        forward[edge['source']].add(edge['target'])
        reverse[edge['target']].add(edge['source'])

    def visit(start, adjacency):
        seen, pending = set(), [start]
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            pending.extend(adjacency.get(key, set()) - seen)
        return seen

    from_start = visit(requirement.get('source') or subject, forward)
    to_target = visit(requirement.get('object'), reverse)
    return [edge for edge in transitions if edge['source'] in from_start and edge['target'] in to_target]


def _action_targets(model, report, atom):
    requirements = {entry['id']: entry for entry in model.get('requirements', [])}
    targets = []
    for finding in report['results']:
        requirement = requirements.get(finding['id'], {})
        if requirement.get('checker') in {'forbidden_operation', 'required_operation', 'mandatory_access', 'label_flow'} and atom[0] in {'acl', 'transition_enabled'}:
            if any(any(_atom(condition) == atom for condition in edge.get('conditions', []))
                   for edge in _path_transitions(model, requirement)):
                targets.append(finding['id'])
        elif any(entry.get('predicate') and _atom(entry) == atom for entry in finding.get('evidence', [])):
            targets.append(finding['id'])
    return sorted(targets)


def attach_repair_catalog(model, policy):
    """Return a copy with only the repairs authorized by ``allowed_operations``.

    ``revoke_access`` accepts portable ``edges``, native ``transitions``, and/or
    exact ``acl`` records (subject, object, operation). ``enable_control`` and
    ``restore_component`` accept ``nodes``. Entries may declare nonnegative
    integer ``cost``. Unknown operations/identifiers are rejected; known but
    uncertain or already-correct facts are reported as skipped.

    The policy creates the precise mutable atoms required by these actions; it
    does not change any fact. It replaces the action catalogue, so an unrelated
    catalogue cannot silently enlarge this policy's authorized action space.
    """
    if validate_model(model):
        raise ValueError('Cannot compile a repair policy for an inconsistent model')
    if not isinstance(policy, dict) or set(policy) - {'allowed_operations'}:
        raise ValueError('repair_policy accepts only allowed_operations')
    entries = policy.get('allowed_operations', [])
    if not isinstance(entries, list):
        raise ValueError('repair_policy.allowed_operations must be a list')
    result = deepcopy(model)
    result['repair_policy'] = deepcopy(policy)
    result['action_catalog'] = []
    result['repair_generation'] = {'skipped': []}
    facts = FactBase(model)
    declared = {_atom(entry) for entry in model.get('facts', [])}
    mutable = {_atom(entry) for entry in result.get('mutable', [])}
    transitions = {edge['id']: edge for edge in model.get('transitions', [])}
    portable = defaultdict(list)
    for edge in transitions.values():
        if edge.get('portable_edge_id'):
            portable[edge['portable_edge_id']].append(edge['id'])
    report = analyze(model)
    generated = {}

    def add(operation, predicate, args, old, new, cost, index):
        atom = predicate, tuple(args)
        actual = facts.get(predicate, args)
        if atom not in declared or actual != old:
            result['repair_generation']['skipped'].append({
                'operation': operation, 'predicate': predicate, 'args': args,
                'reason': 'fact_not_explicit' if atom not in declared else 'unknown_fact' if actual == 'UNKNOWN' else 'already_satisfied',
                'value': actual,
            })
            return
        if predicate == 'transition_enabled' and not any(
                _atom(condition) == atom for condition in transitions[args[0]].get('conditions', [])):
            result['repair_generation']['skipped'].append({
                'operation': operation, 'predicate': predicate, 'args': args,
                'reason': 'transition_does_not_use_enabled_fact',
            })
            return
        effect = {'predicate': predicate, 'args': list(args), 'value': new}
        identifier = operation + ':' + json.dumps([predicate, args], ensure_ascii=False, separators=(',', ':'))
        action = {
            'id': identifier, 'operation': operation, 'cost': cost,
            'object': args[1] if predicate == 'acl' else transitions[args[0]]['target'] if predicate == 'transition_enabled' else args[0],
            'preconditions': [{'predicate': predicate, 'args': list(args), 'value': old}],
            'effects': [effect], 'targets': _action_targets(model, report, atom),
            'generated_by': 'repair_policy',
            'provenance': [{'kind': 'declared', 'state': model.get('state'), 'file': 'repair_policy',
                            'json_key': f'allowed_operations[{index}]', 'raw_value': deepcopy(entries[index]),
                            'transformation': 'explicit authorization of one known mutable fact'}],
        }
        # Repeated authorization never creates two independent ways to perform
        # the same edit; retain its cheapest declared implementation.
        if identifier not in generated or generated[identifier]['cost'] > cost:
            generated[identifier] = action
        if atom not in mutable:
            result.setdefault('mutable', []).append({'predicate': predicate, 'args': list(args)})
            mutable.add(atom)

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError('Each allowed operation must be an object')
        operation = entry.get('operation')
        allowed = {'operation', 'cost', 'edges', 'transitions', 'acl'} if operation == 'revoke_access' else {'operation', 'cost', 'nodes'}
        if operation not in {'revoke_access', 'enable_control', 'restore_component'} or set(entry) - allowed:
            raise ValueError('Unsupported repair operation or fields; security policy, labels and clearance cannot be changed')
        cost = entry.get('cost', 1)
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
            raise ValueError('Repair cost must be a nonnegative integer')
        if operation == 'revoke_access':
            edge_ids = _strings(entry.get('edges', []), 'revoke_access.edges')
            transition_ids = set(_strings(entry.get('transitions', []), 'revoke_access.transitions'))
            for edge_id in edge_ids:
                if edge_id not in portable:
                    raise ValueError('Unknown semantic portable edge in repair policy: ' + edge_id)
                transition_ids.update(portable[edge_id])
            for identifier in sorted(transition_ids):
                if identifier not in transitions:
                    raise ValueError('Unknown transition in repair policy: ' + identifier)
                add(operation, 'transition_enabled', [identifier], 'TRUE', 'FALSE', cost, index)
            acl = entry.get('acl', [])
            if not isinstance(acl, list):
                raise ValueError('revoke_access.acl must be a list of exact permission records')
            for permission in acl:
                if not isinstance(permission, dict) or set(permission) != {'subject', 'object', 'operation'}:
                    raise ValueError('ACL authorization needs subject, object and operation')
                args = [permission.get('subject'), permission.get('object'), permission.get('operation')]
                if (any(not isinstance(arg, str) or not arg for arg in args)
                        or any(arg not in model['nodes'] for arg in args[:2]) or args[2] not in OPERATIONS):
                    raise ValueError('Unknown subject or object in ACL repair authorization')
                add(operation, 'acl', args, 'TRUE', 'FALSE', cost, index)
        else:
            predicate = 'enabled' if operation == 'enable_control' else 'present'
            for key in _strings(entry.get('nodes', []), operation + '.nodes'):
                if key not in model['nodes']:
                    raise ValueError('Unknown node in repair policy: ' + key)
                add(operation, predicate, [key], 'FALSE', 'TRUE', cost, index)
    result['action_catalog'] = [generated[key] for key in sorted(generated)]
    return result
