"""Atomic snapshot changes with a fixed policy and an explicit mutable fact set.

This module validates final atomic batches. It does not claim to validate the
intermediate states of a sequential maintenance procedure.
"""
from copy import deepcopy
from .model import FactBase, IMMUTABLE_PREDICATES, DERIVED_PREDICATES, PREDICATES, validate_model
from .logic import UNKNOWN


def _key(entry):
    return entry["predicate"], tuple(entry.get("args", []))


def apply_actions(model, actions, new_state=None):
    if validate_model(model):
        raise ValueError("Cannot change an inconsistent model")
    if new_state is not None and new_state == model.get("state"):
        raise ValueError("A changed snapshot must have a new state identifier")
    actions = list(actions)
    identifiers = [a["id"] for a in actions]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Action identifiers must be unique")
    selected = set(identifiers)
    base = FactBase(model)
    mutable = {_key(item) for item in model.get("mutable", [])}
    effects = {}
    effect_owners = {}
    for action in actions:
        if set(action.get("excludes", [])) & selected:
            raise ValueError("Incompatible actions selected: " + action["id"])
        if not set(action.get("requires", [])) <= selected:
            raise ValueError("Required companion action is missing: " + action["id"])
        if not isinstance(action.get("cost", 1), int) or action.get("cost", 1) < 0:
            raise ValueError("Action cost must be a non-negative integer")
        for precondition in action.get("preconditions", []):
            actual = base.get(precondition["predicate"], precondition.get("args", []))
            expected = precondition.get("value", precondition.get("expected", "TRUE"))
            if actual == UNKNOWN or expected == UNKNOWN or actual != expected:
                raise ValueError("Action precondition is not confirmed: " + action["id"])
        if not action.get("effects"):
            raise ValueError("Action needs explicit fact effects: " + action["id"])
        for effect in action["effects"]:
            key = _key(effect)
            if key[0] in IMMUTABLE_PREDICATES | DERIVED_PREDICATES or key[0] not in PREDICATES:
                raise ValueError("Forbidden mutation of immutable or derived fact: " + key[0])
            if key not in mutable:
                raise ValueError("Effect is outside the explicit mutable fact set: " + str(key))
            original = base.get(*key)
            if original == UNKNOWN or effect.get("value") in (None, "UNKNOWN"):
                raise ValueError("Actions cannot resolve UNKNOWN or destroy certainty: " + str(key))
            if key in effects and effects[key]["value"] != effect["value"]:
                raise ValueError("Conflicting atomic effects: " + str(key))
            effects[key] = effect
            effect_owners.setdefault(key, []).append(action["id"])
    changed = deepcopy(model)
    changed["parent_state"] = model.get("state")
    changed["state"] = new_state or str(model.get("state", "state")) + ":changed"
    changed["actions"] = deepcopy(actions)
    changed["diff"] = []
    # Preserve all old facts in diff; the new snapshot has one new value with the
    # transition's provenance, not a false contradictory append to the old snapshot.
    for key, effect in effects.items():
        old = [item for item in changed.get("facts", []) if _key(item) == key]
        changed["facts"] = [item for item in changed.get("facts", []) if _key(item) != key]
        provenance = [{"kind": "derived", "state": changed["state"], "source_state": model.get("state"),
                       "file": "action_catalog", "json_key": action_id, "raw_value": effect["value"],
                       "transformation": "explicit atomic action effect"}
                      for action_id in effect_owners[key]]
        for action in actions:
            if action["id"] in effect_owners[key]:
                provenance.extend(deepcopy(action.get("provenance", [])))
        changed["facts"].append({"predicate": key[0], "args": list(key[1]), "value": effect["value"],
                                  "provenance": provenance})
        changed["diff"].append({"predicate": key[0], "args": list(key[1]), "before": base.get(*key),
                                "after": effect["value"], "previous_facts": old, "actions": effect_owners[key]})
    errors = validate_model(changed)
    if errors:
        raise ValueError("Action effects create MODEL_ERROR: " + str(errors))
    return changed


def _single(model, identifier, obj, effects, new_state=None):
    action = {"id": identifier, "object": obj, "cost": 1, "effects": effects,
              "provenance": [{"kind": "declared", "state": new_state, "file": "state transition API",
                              "transformation": identifier, "raw_value": effects}]}
    return apply_actions(model, [action], new_state)


def remove_component(model, component, new_state=None):
    """Keep a tombstone in the finite domain so requirements cannot disappear."""
    return _single(model, "remove:" + component, component,
                   [{"predicate": "present", "args": [component], "value": "FALSE"}], new_state)


def disable_component(model, component, new_state=None):
    """Disable the function; transport is separately specified by transitions."""
    return _single(model, "disable:" + component, component,
                   [{"predicate": "enabled", "args": [component], "value": "FALSE"}], new_state)


def fail_component(model, component, mode="fail_closed", new_state=None):
    if mode not in {"fail_open", "fail_closed"}:
        raise ValueError("Failure mode must be fail_open or fail_closed")
    return _single(model, "fail:" + component, component,
                   [{"predicate": "healthy", "args": [component], "value": "FALSE"},
                    {"predicate": "failure_mode", "args": [component], "value": mode}], new_state)


def set_parameter(model, component, parameter, value, new_state=None):
    return _single(model, "parameter:" + component + ":" + parameter, component,
                   [{"predicate": "parameter", "args": [component, parameter], "value": value}], new_state)


def set_acl(model, subject, obj, operation, value, new_state=None):
    return _single(model, "acl:" + subject + ":" + obj + ":" + operation, obj,
                   [{"predicate": "acl", "args": [subject, obj, operation], "value": value}], new_state)


def set_relation(model, predicate, args, value, new_state=None):
    return _single(model, "relation:" + predicate, args[0] if args else None,
                   [{"predicate": predicate, "args": list(args), "value": value}], new_state)
