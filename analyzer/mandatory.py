"""Finite mandatory confidentiality/integrity policy, independent of actual ACL.

Labels are immutable policy inputs. No decision in this module creates, removes,
filters, or otherwise changes an actual transition in the graph.
"""
from copy import deepcopy
from .logic import TRUE, FALSE, UNKNOWN, conjunction, disjunction

LABEL_FIELDS = {"security_label", "integrity_label", "clearance"}
MAC_CHECKERS = {"mandatory_access", "label_flow", "clearance", "semantic_readiness"}


def _known_names(value, *, allow_empty=True):
    return (isinstance(value, list) and (allow_empty or bool(value))
            and all(isinstance(item, str) and bool(item.strip()) for item in value)
            and len(value) == len(set(value)))


def validate_security(model):
    """Diagnose malformed declarations; omitted knowledge remains UNKNOWN."""
    errors = []
    policy = model.get("security_policy", {})
    if not isinstance(policy, dict):
        return [{"code": "INVALID_SECURITY_POLICY", "path": "security_policy", "reason": "expected object"}]

    def invalid(code, path, reason):
        errors.append({"code": code, "path": path, "reason": reason})

    for flag in ("enabled", "integrity_enabled"):
        if flag in policy and not isinstance(policy[flag], bool):
            invalid("INVALID_SECURITY_POLICY", f"security_policy/{flag}", "expected Boolean, not numeric or string")
    for field in ("confidentiality_levels", "integrity_levels", "categories", "integrity_categories"):
        if field in policy and not _known_names(policy[field], allow_empty=not field.endswith("levels")):
            invalid("INVALID_LABEL_ORDER" if field.endswith("levels") else "INVALID_CATEGORY_DOMAIN",
                    f"security_policy/{field}", "expected unique nonempty string names; levels need a nonempty low-to-high total order")

    def validate_label(label, path, dimension="confidentiality", complete=False):
        if not isinstance(label, dict):
            invalid("INVALID_SECURITY_LABEL", path, "expected object; omit a label when unknown")
            return
        for field in ("level", "categories"):
            if complete and field not in label:
                invalid("INCOMPLETE_DECLASSIFICATION_LABEL", path, "exact exception needs both level and categories")
        level = label.get("level")
        levels = policy.get(dimension + "_levels")
        if "level" in label:
            if not isinstance(level, str) or not level.strip():
                invalid("INVALID_SECURITY_LABEL", path + "/level", "expected nonempty string name")
            elif _known_names(levels, allow_empty=False) and level not in levels:
                invalid("UNKNOWN_LABEL_LEVEL", path + "/level", "level is outside the declared finite order")
        if "categories" in label:
            if not _known_names(label["categories"]):
                invalid("INVALID_SECURITY_LABEL", path + "/categories", "expected unique nonempty string names; [] means no compartments")
            else:
                category_domain = policy.get("integrity_categories" if dimension == "integrity" else "categories")
                if _known_names(category_domain) and not set(label["categories"]) <= set(category_domain):
                    invalid("UNKNOWN_LABEL_CATEGORY", path + "/categories", "category outside the declared domain")

    for key, node in model.get("nodes", {}).items():
        for field in LABEL_FIELDS:
            if field in node:
                validate_label(node[field], f"nodes/{key}/{field}", "integrity" if field == "integrity_label" else "confidentiality")
    exceptions = policy.get("declassifications", [])
    if not isinstance(exceptions, list):
        invalid("INVALID_DECLASSIFICATION", "security_policy/declassifications", "expected finite list of exact authorizations")
        return errors
    ids = set()
    decisions = {}
    for index, entry in enumerate(exceptions):
        path = f"security_policy/declassifications/{index}"
        if not isinstance(entry, dict):
            invalid("INVALID_DECLASSIFICATION", path, "expected object")
            continue
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in ids:
            invalid("INVALID_DECLASSIFICATION", path + "/id", "expected unique nonempty identifier")
        else:
            ids.add(identifier)
        for field in ("subject", "source", "target"):
            if not isinstance(entry.get(field), str) or entry[field] not in model.get("nodes", {}):
                invalid("UNKNOWN_DECLASSIFICATION_NODE", path + "/" + field, "exact existing node key required")
        if entry.get("operation") != "write":
            invalid("INVALID_DECLASSIFICATION", path + "/operation", "only explicitly modeled write/copy declassification is supported")
        if not isinstance(entry.get("scenario"), str) or not entry["scenario"].strip():
            invalid("INVALID_DECLASSIFICATION", path + "/scenario", "exact scenario required; wildcard grants are unsupported")
        if entry.get("authorized") not in ("TRUE", "FALSE", "UNKNOWN"):
            invalid("INVALID_DECLASSIFICATION", path + "/authorized", "explicit TRUE, FALSE, or UNKNOWN required")
        validate_label(entry.get("from_label"), path + "/from_label", complete=True)
        validate_label(entry.get("to_label"), path + "/to_label", complete=True)
        from_label, to_label = entry.get("from_label"), entry.get("to_label")
        exact_labels = all(isinstance(lab, dict) and isinstance(lab.get("level"), str) and _known_names(lab.get("categories")) for lab in (from_label, to_label))
        exact_context = all(isinstance(entry.get(field), str) for field in ("subject", "source", "target", "operation", "scenario"))
        if exact_labels and exact_context:
            key = tuple(entry[field] for field in ("subject", "source", "target", "operation", "scenario")) + (from_label["level"], tuple(sorted(from_label["categories"])), to_label["level"], tuple(sorted(to_label["categories"])))
            if key in decisions and decisions[key] != entry.get("authorized"):
                invalid("CONFLICTING_DECLASSIFICATION", path, "same exact transfer has incompatible authorization declarations")
            decisions[key] = entry.get("authorized")
    return errors


def dominates(higher, lower, levels):
    """(rank_h >= rank_l) AND (categories_h superset categories_l), Kleene."""
    higher = higher if isinstance(higher, dict) else {}
    lower = lower if isinstance(lower, dict) else {}
    rank = UNKNOWN
    if (_known_names(levels, allow_empty=False)
            and higher.get("level") in levels and lower.get("level") in levels):
        rank = TRUE if levels.index(higher["level"]) >= levels.index(lower["level"]) else FALSE
    compartments = UNKNOWN
    if _known_names(higher.get("categories")) and _known_names(lower.get("categories")):
        compartments = TRUE if set(higher["categories"]) >= set(lower["categories"]) else FALSE
    return conjunction([rank, compartments])


class MandatoryPolicy:
    def __init__(self, model):
        self.model = model
        self.policy = model.get("security_policy", {})
        self.evidence = []
        self.unknowns = []

    @property
    def enabled(self):
        return TRUE if self.policy.get("enabled") is True else FALSE if self.policy.get("enabled") is False else UNKNOWN

    def _record(self, path, raw, provenance):
        self.evidence.append({"predicate": "mandatory_policy_input", "args": [path], "value": deepcopy(raw),
                              "provenance": deepcopy(provenance), "immutable": True})

    def _label(self, key, field):
        node = self.model.get("nodes", {}).get(key, {})
        label = node.get(field)
        path = f"nodes/{key}/{field}"
        self._record(path, label, node.get("provenance", []))
        if not isinstance(label, dict):
            self.unknowns.append({"predicate": field, "args": [key], "reason": "label has not been supplied"})
            return {}
        for part in ("level", "categories"):
            if part not in label:
                self.unknowns.append({"predicate": field, "args": [key, part], "reason": "label field unknown; missing categories is not the empty set"})
        return label

    def _order(self, dimension):
        field = dimension + "_levels"
        levels = self.policy.get(field)
        self._record("security_policy/" + field, levels, self.policy.get("provenance", []))
        if levels is None:
            self.unknowns.append({"predicate": field, "args": [], "reason": "no order of classification levels has been supplied"})
        return levels

    def _comparison(self, first, second, dimension, rule, first_field=None, second_field=None):
        field = "integrity_label" if dimension == "integrity" else "security_label"
        a = self._label(first, first_field or field)
        b = self._label(second, second_field or field)
        value = dominates(a, b, self._order(dimension))
        return {"value": value, "rule": rule, "dominant": first, "dominated": second,
                "dominant_label": deepcopy(a), "dominated_label": deepcopy(b)}

    def clearance(self, subject, *, required=True):
        if not required and "clearance" not in self.model.get("nodes", {}).get(subject, {}):
            return {"value": TRUE, "rule": "optional clearance ceiling was not declared", "applies": False}
        result = self._comparison(subject, subject, "confidentiality", "current subject label must not exceed its clearance",
                                  first_field="clearance", second_field="security_label")
        result["applies"] = True
        return result

    def access(self, subject, target, operation):
        if operation not in {"read", "write"}:
            self.unknowns.append({"predicate": "mandatory_access", "args": [subject, target, operation],
                                  "reason": "execute/administer have no implicit read/write interpretation"})
            return {"allowed": UNKNOWN, "confidentiality": {"value": UNKNOWN}, "integrity": {"value": UNKNOWN},
                    "clearance": self.clearance(subject, required=False)}
        if operation == "read":
            conf = self._comparison(subject, target, "confidentiality", "Bell-LaPadula: no read up")
        else:
            conf = self._comparison(target, subject, "confidentiality", "Bell-LaPadula: no write down")
        if self.policy.get("integrity_enabled", False):
            if operation == "read":
                integrity = self._comparison(target, subject, "integrity", "strict Biba: no read down")
            else:
                integrity = self._comparison(subject, target, "integrity", "strict Biba: no write up")
        else:
            integrity = {"value": TRUE, "rule": "optional strict Biba profile is not enabled", "applies": False}
        ceiling = self.clearance(subject, required=False)
        value = conjunction([conf["value"], integrity["value"], ceiling["value"]])
        if self.enabled == UNKNOWN:
            value = UNKNOWN
            self.unknowns.append({"predicate": "security_policy", "args": ["enabled"], "reason": "mandatory profile applicability unknown"})
        return {"allowed": value, "confidentiality": conf, "integrity": integrity, "clearance": ceiling}

    def _declassification(self, subject, source, target, operation, scenario, source_label, target_label):
        values, matches = [], []
        for exception in self.policy.get("declassifications", []):
            if (exception["subject"], exception["source"], exception["target"], exception["operation"], exception["scenario"]) != (subject, source, target, operation, scenario):
                continue
            # Exact finite authorization, including both complete labels. An
            # unknown label cannot acquire permission through a loose match.
            full = all(field in label for label in (source_label, target_label) for field in ("level", "categories"))
            if not full:
                values.append(UNKNOWN)
                continue
            same_source = source_label["level"] == exception["from_label"]["level"] and set(source_label["categories"]) == set(exception["from_label"]["categories"])
            same_target = target_label["level"] == exception["to_label"]["level"] and set(target_label["categories"]) == set(exception["to_label"]["categories"])
            if same_source and same_target:
                values.append(exception["authorized"])
                matches.append(exception["id"])
                self._record("security_policy/declassifications/" + exception["id"], exception, exception.get("provenance", []))
        return {"value": disjunction(values), "matching_authorizations": matches,
                "scope": "exact subject, source, target, operation, scenario and both labels; confidentiality only"}

    def flow(self, subject, source, target, operation="write", scenario="default"):
        conf = self._comparison(target, source, "confidentiality", "copy/flow destination must dominate source classification")
        source_label = self.model["nodes"][source].get("security_label", {})
        target_label = self.model["nodes"][target].get("security_label", {})
        exception = self._declassification(subject, source, target, operation, scenario, source_label, target_label)
        conf["without_exception"] = conf["value"]
        conf["value"] = disjunction([conf["value"], exception["value"]])
        if self.policy.get("integrity_enabled", False):
            integrity = self._comparison(source, target, "integrity", "copy/flow source integrity must dominate destination integrity")
        else:
            integrity = {"value": TRUE, "applies": False, "rule": "optional strict Biba profile is not enabled"}
        # An exception never raises the subject's authorized clearance.
        ceiling = self.clearance(subject, required=False)
        allowed = conjunction([conf["value"], integrity["value"], ceiling["value"]])
        if operation != "write":
            allowed = UNKNOWN
            self.unknowns.append({"predicate": "label_flow", "args": [operation], "reason": "only write/copy flow semantics is defined"})
        if self.enabled == UNKNOWN:
            allowed = UNKNOWN
            self.unknowns.append({"predicate": "security_policy", "args": ["enabled"], "reason": "mandatory profile applicability unknown"})
        return {"allowed": allowed, "confidentiality": conf, "integrity": integrity,
                "clearance": ceiling, "declassification": exception,
                "scope": "declared source-to-destination transfer; compile a check for every data-bearing transfer"}
