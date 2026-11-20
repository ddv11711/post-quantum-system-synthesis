"""Finite typed schema, provenance-aware fact index, and consistency checks.

Facts are never overwritten during inference. Different explicit values for the
same ground fact are a model error, rather than an arbitrary source preference.
"""
from collections import defaultdict
from copy import deepcopy
from .logic import TRUE, FALSE, UNKNOWN, truth

OPERATIONS = {"read", "write", "execute", "administer"}
NODE_TYPES = {"component", "subject", "data", "function", "event", "key", "role", "channel", "change", "unknown"}
# "node" accepts any node; other types are checked when a concrete type is known.
PREDICATES = {
    "present": ("node",), "enabled": ("node",), "healthy": ("node",),
    "transport_enabled": ("node",), "failure_mode": ("node",),
    "acl": ("subject", "node", "operation"),
    "physical": ("node", "node"), "channel": ("node", "node"),
    "stores": ("node", "data"), "executes": ("node", "node"),
    "owns": ("subject", "data"), "authenticates": ("subject", "node"),
    "cover": ("node", "label", "node"), "logger": ("event", "node"),
    "event_possible": ("event",), "backup": ("data", "node"),
    "readable": ("node",), "key_required": ("node", "key"),
    "key_accessible": ("key",), "independent": ("node", "node"),
    "integrity": ("node",), "trusted_boot": ("node",),
    "parameter": ("node", "label"), "has_role": ("subject", "role"),
    "changed": ("change",), "approved": ("change",),
    "crypto_protected": ("channel",), "crypto_algorithm": ("channel",),
    "crypto_function": ("channel",), "crypto_bits": ("channel",),
    "material_available": ("subject", "channel"), "observes": ("subject", "channel"),
    "quantum_capable": ("subject", "label"), "horizon_valid": ("channel", "label"),
    "evidence": ("node", "label"), "transition_enabled": ("transition",),
}
SCALAR_PREDICATES = {"parameter", "failure_mode", "crypto_algorithm", "crypto_function", "crypto_bits"}
IMMUTABLE_PREDICATES = {"event_possible", "evidence", "material_available", "observes", "quantum_capable", "horizon_valid", "owns", "approved", "changed"}
DERIVED_PREDICATES = {"available", "can_perform", "reachable", "quantum_exposed", "transport"}


def empty_model(state="initial", profile="strict"):
    return {"state": state, "profile": profile, "nodes": {}, "facts": [],
            "completeness": [], "dependencies": {}, "transitions": [],
            "requirements": [], "policy": {"allowed": []}, "mutable": [], "assumptions": []}


def fact(predicate, args, value="TRUE", provenance=None):
    return {"predicate": predicate, "args": list(args), "value": value,
            "provenance": deepcopy(provenance or [])}


class FactBase:
    def __init__(self, model):
        self.model = model
        self.index = defaultdict(list)
        self.used = {}
        self.missing = {}
        for entry in model.get("facts", []):
            self.index[(entry.get("predicate"), tuple(entry.get("args", [])))].append(entry)

    def complete(self, predicate, args_prefix=()):
        """Only an explicit enclosing scope can license closed-world negation."""
        for entry in self.model.get("completeness", []):
            prefix = tuple(entry.get("args_prefix", []))
            if (entry.get("predicate") == predicate and entry.get("complete") is True
                    and tuple(args_prefix)[:len(prefix)] == prefix):
                self.used[("completeness", predicate, prefix)] = {"completeness": entry}
                return True
        return False

    def get(self, predicate, args=()):
        key = (predicate, tuple(args))
        entries = list(self.index.get(key, []))
        if predicate == "independent" and len(args) == 2 and args[0] != args[1]:
            entries += self.index.get((predicate, tuple(reversed(args))), [])
        if entries:
            for index, entry in enumerate(entries):
                self.used[(predicate, tuple(args), index)] = entry
            values = {str(entry["value"].value if hasattr(entry["value"], "value") else entry["value"]) if not isinstance(entry["value"], bool) else ("TRUE" if entry["value"] else "FALSE") for entry in entries}
            if len(values) != 1:
                return UNKNOWN
            result = next(iter(values))
            if result == "UNKNOWN":
                self.missing[key] = {"predicate": predicate, "args": list(args), "reason": "explicit UNKNOWN"}
            return result
        if predicate not in SCALAR_PREDICATES and (self.complete(predicate, args) or
                (predicate == "independent" and self.complete(predicate, list(reversed(args))))):
            return FALSE
        self.missing[key] = {"predicate": predicate, "args": list(args), "reason": "fact absent; relation scope not closed"}
        return UNKNOWN

    def boolean(self, predicate, args=()):
        value = self.get(predicate, args)
        try:
            return truth(value)
        except ValueError:
            return UNKNOWN  # validation reports invalid Boolean separately

    def candidates(self, predicate, prefix=()):
        prefix = tuple(prefix)
        return sorted({args[len(prefix):] for name, args in self.index
                       if name == predicate and args[:len(prefix)] == prefix})

    def reset_trace(self):
        self.used = {}
        self.missing = {}


def _shape_errors(model):
    """Guard JSON structure before any hash lookup or typed semantic check."""
    errors = []

    def error(path, expected):
        errors.append({"code": "INVALID_MODEL_SHAPE", "path": path, "expected": expected})

    def strings(value, path):
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            error(path, "list of strings")
            return False
        return True

    def records(value, path):
        if not isinstance(value, list):
            error(path, "list of objects")
            return []
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                error(f"{path}/{index}", "object")
        return [(index, item) for index, item in enumerate(value) if isinstance(item, dict)]

    def string_fields(item, fields, path):
        for field in fields:
            if field in item and not isinstance(item[field], str):
                error(path + "/" + field, "string")

    def atom(item, path):
        for field in ("predicate", "args"):
            if field not in item:
                error(path + "/" + field, "required field")
        string_fields(item, ("predicate",), path)
        if "args" in item:
            strings(item["args"], path + "/args")
        for field in ("value", "expected"):
            if field in item and not isinstance(item[field], (str, bool, int, float)):
                error(path + "/" + field, "scalar string, boolean, or number")

    if not isinstance(model, dict):
        return [{"code": "INVALID_MODEL_SHAPE", "path": "$", "expected": "object"}]
    string_fields(model, ("state", "profile"), "$")
    nodes = model.get("nodes", {})
    if not isinstance(nodes, dict):
        error("$/nodes", "object mapping node keys to objects")
    else:
        for key, node in nodes.items():
            if not isinstance(key, str) or not isinstance(node, dict):
                error("$/nodes", "string node keys and object records")
            elif "types" in node:
                strings(node["types"], "$/nodes/" + key + "/types")
    for index, entry in records(model.get("facts", []), "$/facts"):
        atom(entry, f"$/facts/{index}")
        for field in ("predicate", "args", "value"):
            if field not in entry:
                error(f"$/facts/{index}/{field}", "required field")
    for index, entry in records(model.get("mutable", []), "$/mutable"):
        atom(entry, f"$/mutable/{index}")
    for index, entry in records(model.get("completeness", []), "$/completeness"):
        string_fields(entry, ("predicate",), f"$/completeness/{index}")
        if "args_prefix" in entry:
            strings(entry["args_prefix"], f"$/completeness/{index}/args_prefix")
    dependencies = model.get("dependencies", {})
    if not isinstance(dependencies, dict):
        error("$/dependencies", "object mapping component keys to equations")
    else:
        for key, expression in dependencies.items():
            if not isinstance(key, str) or not isinstance(expression, dict):
                error("$/dependencies", "string keys and object equations")
                continue
            for operator, references in expression.items():
                strings(references, f"$/dependencies/{key}/{operator}")
    for index, entry in records(model.get("requirements", []), "$/requirements"):
        path = f"$/requirements/{index}"
        string_fields(entry, ("id", "checker", "object", "subject", "source", "bypass_subject", "operation", "scenario", "kind", "horizon", "predicate"), path)
        if "expected" in entry and not isinstance(entry["expected"], (str, bool, int, float)):
            error(path + "/expected", "scalar expected value")
        for field in ("args", "replicas", "roles", "endpoints"):
            if field in entry:
                strings(entry[field], path + "/" + field)
    for index, entry in records(model.get("transitions", []), "$/transitions"):
        path = f"$/transitions/{index}"
        string_fields(entry, ("id", "source", "target", "subject", "via", "operation", "scenario", "kind"), path)
        for offset, condition in records(entry.get("conditions", []), path + "/conditions"):
            atom(condition, path + f"/conditions/{offset}")
    policy = model.get("policy", {})
    if not isinstance(policy, dict):
        error("$/policy", "object")
    else:
        for index, permission in records(policy.get("allowed", []), "$/policy/allowed"):
            string_fields(permission, ("subject", "object", "operation", "scenario", "kind"), f"$/policy/allowed/{index}")
    for index, action in records(model.get("action_catalog", []), "$/action_catalog"):
        path = f"$/action_catalog/{index}"
        if not action.get("id"):
            error(path + "/id", "required nonempty action identifier")
        string_fields(action, ("id",), path)
        for field in ("requires", "excludes", "targets"):
            if field in action:
                strings(action[field], path + "/" + field)
        for field in ("effects", "preconditions"):
            for offset, condition in records(action.get(field, []), path + "/" + field):
                atom(condition, path + f"/{field}/{offset}")
                if field == "effects" and "value" not in condition:
                    error(path + f"/{field}/{offset}/value", "required effect value")
    return errors


def validate_model(model):
    errors = _shape_errors(model)
    if errors:
        return errors
    nodes = model.get("nodes", {})
    transitions = model.get("transitions", [])
    transition_ids = {item.get("id") for item in transitions}
    seen = {}
    for key, node in nodes.items():
        types = set(node.get("types", ["unknown"]))
        if not types <= NODE_TYPES:
            errors.append({"code": "UNKNOWN_NODE_TYPE", "object": key, "types": sorted(types - NODE_TYPES)})
    for entry in model.get("facts", []):
        name, args = entry.get("predicate"), entry.get("args", [])
        signature = PREDICATES.get(name)
        if signature is None or len(signature) != len(args):
            errors.append({"code": "PREDICATE_SIGNATURE", "fact": entry})
            continue
        key = (name, tuple(sorted(args)) if name == "independent" else tuple(args))
        value = entry.get("value", "UNKNOWN")
        value = "TRUE" if value is True else "FALSE" if value is False else value
        if name not in SCALAR_PREDICATES and value not in ("TRUE", "FALSE", "UNKNOWN"):
            errors.append({"code": "NON_BOOLEAN_FACT", "fact": entry})
        if key in seen and seen[key] != value:
            errors.append({"code": "CONFLICTING_FACTS", "predicate": name, "args": args,
                           "values": [seen[key], value]})
        seen[key] = value
        for argument, expected in zip(args, signature):
            if expected == "label":
                continue
            if expected == "operation":
                if argument not in OPERATIONS:
                    errors.append({"code": "UNSUPPORTED_OPERATION", "operation": argument})
            elif expected == "transition":
                if argument not in transition_ids:
                    errors.append({"code": "UNKNOWN_TRANSITION", "object": argument})
            elif argument not in nodes:
                errors.append({"code": "UNKNOWN_NODE", "object": argument, "fact": entry})
            elif expected != "node":
                actual = set(nodes[argument].get("types", ["unknown"]))
                if "unknown" not in actual and expected not in actual:
                    errors.append({"code": "TYPE_MISMATCH", "object": argument,
                                   "expected": expected, "actual": sorted(actual)})
    seen_ids = set()
    policies = defaultdict(set)
    for req in model.get("requirements", []):
        identifier = req.get("id")
        if req.get("applicable", "TRUE") not in ("TRUE", "FALSE", "UNKNOWN"):
            errors.append({"code": "INVALID_APPLICABILITY", "id": identifier})
        if not identifier or identifier in seen_ids:
            errors.append({"code": "REQUIREMENT_ID", "id": identifier})
        seen_ids.add(identifier)
        if req.get("operation") is not None and req["operation"] not in OPERATIONS:
            errors.append({"code": "UNSUPPORTED_OPERATION", "id": identifier})
        if req.get("checker") in {"required_operation", "forbidden_operation"} and req.get("applicable", "TRUE") == "TRUE":
            key = (req.get("subject"), req.get("object"), req.get("operation"), req.get("scenario", "default"), req.get("kind", "access"))
            policies[key].add(req["checker"])
        for attr in ("object", "subject", "source", "bypass_subject"):
            if req.get(attr) is not None and req[attr] not in nodes:
                errors.append({"code": "UNKNOWN_REQUIREMENT_NODE", "id": identifier, "object": req[attr]})
        required_fields = {
            "forbidden_operation": ["subject", "object", "operation"],
            "required_operation": ["subject", "object", "operation"],
            "required_function": ["object"], "protection": ["object"],
            "authentication": ["object"], "logging": ["object"],
            "redundancy": ["object", "replicas"], "recovery": ["object"],
            "configuration": ["object"], "incompatible_roles": ["subject", "roles"],
            "authorized_change": ["object"], "crypto": ["object"],
            "quantum": ["object", "subject", "horizon"], "evidence": ["object"],
        }
        for field in required_fields.get(req.get("checker"), []):
            if field not in req:
                errors.append({"code": "MISSING_CHECKER_FIELD", "id": identifier, "field": field})
        for field in ("replicas", "roles", "endpoints"):
            if field in req and (not isinstance(req[field], list) or any(key not in nodes for key in req[field])):
                errors.append({"code": "INVALID_CHECKER_DOMAIN", "id": identifier, "field": field})
        if req.get("checker") == "configuration":
            predicate = req.get("predicate", "integrity")
            if predicate not in PREDICATES or len(req.get("args", [req.get("object")])) != len(PREDICATES.get(predicate, ())):
                errors.append({"code": "INVALID_CONFIGURATION_PREDICATE", "id": identifier})
    for permission in model.get("policy", {}).get("allowed", []):
        key = (permission.get("subject"), permission.get("object"), permission.get("operation"),
               permission.get("scenario", "default"), permission.get("kind", "access"))
        for field in ("subject", "object"):
            if permission.get(field) not in nodes:
                errors.append({"code": "UNKNOWN_POLICY_NODE", "field": field, "permission": permission})
        if permission.get("operation") not in OPERATIONS:
            errors.append({"code": "UNSUPPORTED_POLICY_OPERATION", "permission": permission})
        if permission.get("kind", "access") not in {"access", "flow"}:
            errors.append({"code": "UNSUPPORTED_POLICY_KIND", "permission": permission})
        if permission.get("applicable", "TRUE") not in ("TRUE", "FALSE", "UNKNOWN"):
            errors.append({"code": "INVALID_POLICY_APPLICABILITY", "permission": permission})
        if permission.get("applicable", "TRUE") == "TRUE":
            policies[key].add("allowed_operation")
    for key, policies_at_key in policies.items():
        if "forbidden_operation" in policies_at_key and len(policies_at_key) > 1:
            errors.append({"code": "CONTRADICTORY_POLICY", "operation": list(key)})
    completeness_values = {}
    for entry in model.get("completeness", []):
        predicate, prefix = entry.get("predicate"), entry.get("args_prefix", [])
        signature = PREDICATES.get(predicate)
        if predicate == "dependencies":
            signature = ("node",)
        elif predicate == "transitions":
            signature = ("subject", "operation", "label", "kind")
        if signature is None or not isinstance(prefix, list) or len(prefix) > len(signature):
            errors.append({"code": "INVALID_COMPLETENESS_SCOPE", "scope": entry})
            continue
        if not isinstance(entry.get("complete"), bool):
            errors.append({"code": "NON_BOOLEAN_COMPLETENESS", "scope": entry})
        key = (predicate, tuple(prefix))
        if key in completeness_values and completeness_values[key] != entry.get("complete"):
            errors.append({"code": "CONFLICTING_COMPLETENESS", "scope": entry})
        completeness_values[key] = entry.get("complete")
        for arg, expected in zip(prefix, signature):
            if expected in {"node", "subject", "data", "event", "key", "role", "channel", "change"} and arg not in nodes:
                errors.append({"code": "UNKNOWN_COMPLETENESS_NODE", "scope": entry, "object": arg})
            if expected == "operation" and arg not in OPERATIONS:
                errors.append({"code": "UNSUPPORTED_COMPLETENESS_OPERATION", "scope": entry})
            if expected == "kind" and arg not in {"access", "flow"}:
                errors.append({"code": "UNSUPPORTED_COMPLETENESS_KIND", "scope": entry})
    for (predicate, prefix), complete in completeness_values.items():
        if complete:
            for (other_predicate, other_prefix), other_complete in completeness_values.items():
                if predicate == other_predicate and other_complete is False and other_prefix[:len(prefix)] == prefix:
                    errors.append({"code": "CONFLICTING_COMPLETENESS", "predicate": predicate,
                                   "complete_prefix": list(prefix), "incomplete_subscope": list(other_prefix)})
    for component, expression in model.get("dependencies", {}).items():
        if not isinstance(expression, dict):
            errors.append({"code": "INVALID_DEPENDENCY", "object": component})
            continue
        if component not in nodes or set(expression) - {"all", "any"}:
            errors.append({"code": "UNSUPPORTED_DEPENDENCY_EXPRESSION", "object": component})
        for references in expression.values():
            if not isinstance(references, list) or any(node not in nodes for node in references):
                errors.append({"code": "INVALID_DEPENDENCY", "object": component})
    if len(transition_ids) != len(transitions) or None in transition_ids:
        errors.append({"code": "TRANSITION_ID"})
    for entry in transitions:
        if not all(field in entry for field in ("source", "target", "subject", "operation")):
            errors.append({"code": "MISSING_TRANSITION_FIELD", "id": entry.get("id")})
        if entry.get("kind", "access") not in {"access", "flow"}:
            errors.append({"code": "UNSUPPORTED_TRANSITION_KIND", "id": entry.get("id")})
        for attr in ("source", "target", "subject", "via"):
            if entry.get(attr) is not None and entry[attr] not in nodes:
                errors.append({"code": "UNKNOWN_TRANSITION_NODE", "id": entry.get("id"), "object": entry[attr]})
        if entry.get("operation") not in OPERATIONS:
            errors.append({"code": "UNSUPPORTED_OPERATION", "id": entry.get("id")})
        if entry.get("switch_subject") or entry.get("grant_roles"):
            errors.append({"code": "UNSUPPORTED_IDENTITY_TRANSITION", "id": entry.get("id")})
        for condition in entry.get("conditions", []):
            predicate = condition.get("predicate")
            signature = PREDICATES.get(predicate, ("node",) if predicate in {"available", "transport"} else None)
            args = condition.get("args", [])
            if signature is None or len(args) != len(signature):
                errors.append({"code": "UNSUPPORTED_TRANSITION_CONDITION", "id": entry.get("id")})
                continue
            for arg, expected in zip(args, signature):
                if expected in {"node", "subject", "data", "event", "key", "role", "channel", "change"}:
                    if arg not in nodes:
                        errors.append({"code": "UNKNOWN_CONDITION_NODE", "id": entry.get("id"), "object": arg})
                    elif expected != "node":
                        actual = set(nodes[arg].get("types", ["unknown"]))
                        if "unknown" not in actual and expected not in actual:
                            errors.append({"code": "CONDITION_TYPE_MISMATCH", "id": entry.get("id"), "object": arg})
                elif expected == "operation" and arg not in OPERATIONS:
                    errors.append({"code": "UNSUPPORTED_OPERATION", "id": entry.get("id")})
                elif expected == "transition" and arg not in transition_ids:
                    errors.append({"code": "UNKNOWN_TRANSITION", "object": arg})
            if predicate not in SCALAR_PREDICATES and condition.get("expected", condition.get("value", "TRUE")) not in ("TRUE", "FALSE", "UNKNOWN"):
                errors.append({"code": "INVALID_CONDITION_VALUE", "id": entry.get("id")})
        if entry.get("value", "TRUE") not in ("TRUE", "FALSE", "UNKNOWN"):
            errors.append({"code": "INVALID_TRANSITION_VALUE", "id": entry.get("id")})
    return errors
