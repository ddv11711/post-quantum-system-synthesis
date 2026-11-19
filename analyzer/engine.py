"""Exact deterministic checks over a finite three-valued model.

The raw graph has no access semantics. Only explicitly contextualized semantic
transitions participate in access and flow reachability; policy never filters it.
"""
from collections import Counter, defaultdict
from itertools import combinations
from time import perf_counter
from .logic import TRUE, FALSE, UNKNOWN, truth, negate, conjunction, disjunction, exists, forall, witness_path
from .model import FactBase, validate_model

CHECKERS = {
    "forbidden_operation", "required_operation", "required_function", "protection",
    "authentication", "logging", "redundancy", "recovery", "configuration",
    "incompatible_roles", "authorized_change", "crypto", "quantum", "evidence",
}


def _equality(actual, expected):
    if actual == UNKNOWN or expected == UNKNOWN:
        return UNKNOWN
    return TRUE if actual == expected else FALSE


class Engine:
    def __init__(self, model):
        self.model = model
        self.facts = FactBase(model)
        self.nodes = model.get("nodes", {})
        self.availability, self.iterations = self._availability()
        self.cache = {}  # Per immutable analysis snapshot and full context.
        self.derivations = []

    def _availability(self):
        values = {key: UNKNOWN for key in self.nodes}
        base = {key: conjunction(self.facts.boolean(p, [key]) for p in ("present", "enabled", "healthy"))
                for key in self.nodes}
        dependencies = self.model.get("dependencies", {})
        for iteration in range(2 * len(values) + 1):
            next_values = {}
            for key in sorted(values):
                parts = [base[key]]
                expression = dependencies.get(key, {})
                if key not in dependencies and not self.facts.complete("dependencies", [key]):
                    parts.append(UNKNOWN)
                if "all" in expression:
                    parts.append(conjunction(values.get(dep, UNKNOWN) for dep in expression["all"]))
                if "any" in expression:
                    parts.append(disjunction(values.get(dep, UNKNOWN) for dep in expression["any"]))
                next_values[key] = conjunction(parts)
            if values == next_values:
                return values, iteration + 1
            values = next_values
        raise ValueError("Non-monotone availability recurrence is unsupported")

    def availability_proof(self, key, seen=None):
        seen = set() if seen is None else set(seen)
        if key in seen:
            return {"predicate": "available", "args": [key], "value": self.availability.get(key, UNKNOWN),
                    "reason": "cycle reference; not an independent positive premise"}
        seen.add(key)
        base = []
        for predicate in ("present", "enabled", "healthy"):
            value = self.facts.boolean(predicate, [key])
            base.append({"predicate": predicate, "args": [key], "value": value})
        expression = self.model.get("dependencies", {}).get(key, {})
        complete = key in self.model.get("dependencies", {}) or self.facts.complete("dependencies", [key])
        if not complete:
            self.facts.missing[("dependencies", (key,))] = {"predicate": "dependencies", "args": [key], "reason": "dependency equation absent; alternatives may be incomplete"}
        return {"predicate": "available", "args": [key], "value": self.availability.get(key, UNKNOWN),
                "base": base, "dependency_provenance": self.model.get("dependency_provenance", {}).get(key, []),
                "dependencies_complete": complete, "dependencies": {
                    mode: [self.availability_proof(dep, seen) for dep in references]
                    for mode, references in expression.items()}}

    def available(self, key):
        self.derivations.append(self.availability_proof(key))
        return self.availability.get(key, UNKNOWN)

    def transport(self, key):
        """A declared fail-open device may transport despite unhealthy protection."""
        mode = self.facts.get("failure_mode", [key])
        healthy = self.facts.boolean("healthy", [key])
        if mode == "fail_open":
            works = TRUE
        elif mode == "fail_closed":
            works = FALSE
        elif mode == "normal":
            works = healthy
        else:
            # Confirmed normal health is sufficient for transport, but a failed
            # device's unspecified behavior may pass or block its traffic.
            works = TRUE if healthy == TRUE else UNKNOWN
        return conjunction([self.facts.boolean("present", [key]),
                            self.facts.boolean("transport_enabled", [key]), works])

    def condition(self, condition):
        predicate, args = condition["predicate"], condition.get("args", [])
        if predicate == "available":
            value = self.available(args[0])
        elif predicate == "transport":
            value = self.transport(args[0])
        else:
            value = self.facts.get(predicate, args)
        return _equality(value, condition.get("expected", condition.get("value", "TRUE")))

    def reachability(self, subject, target, operation, scenario="default", kind="access", source=None):
        start = source or subject
        cache_key = (subject, target, operation, scenario, kind, start)
        if cache_key in self.cache:
            cached, used, missing, derivations = self.cache[cache_key]
            self.facts.used.update(used)
            self.facts.missing.update(missing)
            self.derivations.extend(derivations)
            return cached
        must, may = defaultdict(set), defaultdict(set)
        edges = defaultdict(list)
        all_evaluated = []
        for transition in sorted(self.model.get("transitions", []), key=lambda e: e["id"]):
            if (transition.get("subject"), transition.get("operation"), transition.get("scenario", "default"), transition.get("kind", "access")) != (subject, operation, scenario, kind):
                continue
            conditions = [{"predicate": "present", "args": [subject]},
                          {"predicate": "present", "args": [transition["source"]]},
                          {"predicate": "present", "args": [transition["target"]]}]
            if transition.get("via"):
                conditions.append({"predicate": "present", "args": [transition["via"]]})
            conditions.extend(transition.get("conditions", []))
            evaluated = [dict(condition, result=self.condition(condition)) for condition in conditions]
            value = conjunction([truth(transition.get("value", "TRUE"))] + [e["result"] for e in evaluated])
            edge = dict(transition, value=value, evaluated_conditions=evaluated)
            all_evaluated.append(edge)
            source_key, target_key = transition["source"], transition["target"]
            if value == TRUE:
                must[source_key].add(target_key)
            if value != FALSE:
                may[source_key].add(target_key)
            edges[(source_key, target_key)].append(edge)
        # An operation needs a semantic transition. Reflexivity alone is not read/execute.
        must_path = witness_path(must, start, target) if start != target else None
        may_path = witness_path(may, start, target) if start != target else None
        if start == target:
            def nonempty_cycle(adjacency):
                for neighbor in sorted(adjacency.get(start, ())):
                    tail = witness_path(adjacency, neighbor, start)
                    if tail:
                        return [start] + tail
                return None
            must_path = nonempty_cycle(must)
            may_path = nonempty_cycle(may)
        complete = self.facts.complete("transitions", [subject, operation, scenario, kind])
        value = TRUE if must_path else FALSE if not may_path and complete else UNKNOWN
        # Explicit absence rules out access to a physically absent target regardless of domain incompleteness.
        if any(self.facts.boolean("present", [node]) == FALSE for node in (target, start, subject)):
            value, must_path, may_path = FALSE, None, None
        path = must_path or may_path
        witness = None
        if path:
            witness_edges = []
            for a, b in zip(path, path[1:]):
                candidates = [e for e in edges[(a, b)] if e["value"] == TRUE] if must_path else [e for e in edges[(a, b)] if e["value"] != FALSE]
                witness_edges.append(candidates[0])
            witness = {"nodes": path, "edges": witness_edges, "certain": bool(must_path)}
        result = {"value": value, "witness": witness, "scope_complete": complete,
                  "unknowns": list(self.facts.missing.values()), "evaluated_transitions": all_evaluated}
        self.cache[cache_key] = result, dict(self.facts.used), dict(self.facts.missing), list(self.derivations)
        return result

    def coverage(self, target, control):
        candidates = self.facts.candidates("cover", [target, control])
        values = [conjunction([self.facts.boolean("cover", [target, control, mechanism]), self.available(mechanism)])
                  for (mechanism,) in candidates]
        return exists(values, self.facts.complete("cover", [target, control]))

    def _mandatory_dependencies(self, key, seen=None):
        seen = set() if seen is None else set(seen)
        if key in seen:
            return set()
        seen.add(key)
        result = {key}
        for dep in self.model.get("dependencies", {}).get(key, {}).get("all", []):
            result |= self._mandatory_dependencies(dep, seen)
        return result

    def check(self, req):
        checker, obj = req["checker"], req.get("object")
        detail = {}
        if checker in {"forbidden_operation", "required_operation"}:
            path = self.reachability(req["subject"], obj, req["operation"], req.get("scenario", "default"), req.get("kind", "access"), req.get("source"))
            detail["witness"] = path["witness"]
            detail["scope_complete"] = path["scope_complete"]
            actual = path["value"]
            return (negate(actual) if checker == "forbidden_operation" else actual), detail
        if checker == "required_function":
            return self.available(obj), detail
        if checker in {"protection", "authentication"}:
            control = req.get("control", "authentication" if checker == "authentication" else "protection")
            value = self.coverage(obj, control)
            if req.get("bypass_subject"):
                bypass = self.reachability(req["bypass_subject"], obj, req.get("operation", "read"), req.get("scenario", "bypass"))
                value = conjunction([value, negate(bypass["value"])])
                detail["witness"] = bypass["witness"]
            return value, detail
        if checker == "logging":
            candidates = self.facts.candidates("logger", [obj])
            logging = exists([conjunction([self.facts.boolean("logger", [obj, logger]), self.available(logger)])
                              for (logger,) in candidates], self.facts.complete("logger", [obj]))
            # Requirement is EventPossible -> ExistsWorkingLogger, not unconditional presence.
            return disjunction([negate(self.facts.boolean("event_possible", [obj])), logging]), detail
        if checker == "redundancy":
            pairs = []
            common = []
            replicas = req.get("replicas", [])
            for first, second in combinations(replicas, 2):
                shared = self._mandatory_dependencies(first) & self._mandatory_dependencies(second)
                if shared:
                    independent = FALSE
                    common.append({"replicas": [first, second], "dependencies": sorted(shared)})
                else:
                    independent = self.facts.boolean("independent", sorted([first, second]))
                pairs.append(conjunction([self.available(first), self.available(second), independent]))
            detail["common_dependencies"] = common
            return exists(pairs, req.get("replicas_complete", False)), detail
        if checker == "recovery":
            candidates = self.facts.candidates("backup", [obj])
            copies = []
            for (copy,) in candidates:
                keys = self.facts.candidates("key_required", [copy])
                key_results = [disjunction([negate(self.facts.boolean("key_required", [copy, key])),
                                           conjunction([self.facts.boolean("key_accessible", [key]), self.facts.boolean("present", [key])])])
                               for (key,) in keys]
                keys_ready = forall(key_results, self.facts.complete("key_required", [copy]))
                copies.append(conjunction([self.facts.boolean("backup", [obj, copy]), self.available(copy),
                                           self.facts.boolean("readable", [copy]), keys_ready]))
            return exists(copies, self.facts.complete("backup", [obj])), detail
        if checker == "configuration":
            predicate = req.get("predicate", "integrity")
            return _equality(self.facts.get(predicate, req.get("args", [obj])), req.get("expected", "TRUE")), detail
        if checker == "incompatible_roles":
            roles = req.get("roles", [])
            if len(roles) < 2:
                raise ValueError("incompatible_roles needs at least two explicitly defined roles")
            return negate(conjunction(self.facts.boolean("has_role", [req["subject"], role]) for role in roles)), detail
        if checker == "authorized_change":
            return disjunction([negate(self.facts.boolean("changed", [obj])), self.facts.boolean("approved", [obj])]), detail
        if checker == "crypto":
            parts = [self.facts.boolean("present", [obj]), self.facts.boolean("crypto_protected", [obj])]
            for field in ("algorithm", "function", "bits"):
                if field in req:
                    parts.append(_equality(self.facts.get("crypto_" + field, [obj]), req[field]))
            for endpoint in req.get("endpoints", []):
                parts.append(self.available(endpoint))
            return conjunction(parts), detail
        if checker == "quantum":
            # Deliberately small educational threat model. No ACL or active ability is produced.
            attacker, horizon = req["subject"], req.get("horizon", "unspecified")
            algorithm = self.facts.get("crypto_algorithm", [obj])
            function = self.facts.get("crypto_function", [obj])
            bits = self.facts.get("crypto_bits", [obj])
            if algorithm in {"RSA", "ECDH", "DH"} and function in {"key_exchange", "encryption"} and bits != UNKNOWN:
                try:
                    susceptible = TRUE if int(bits) > 0 else UNKNOWN
                except (ValueError, TypeError):
                    susceptible = UNKNOWN
            elif algorithm == "AES" and function in {"key_exchange", "encryption"} and bits != UNKNOWN:
                try:
                    susceptible = FALSE if int(bits) >= 256 else UNKNOWN
                except (ValueError, TypeError):
                    susceptible = UNKNOWN
            else:
                susceptible = UNKNOWN
            exposure = conjunction([susceptible, self.facts.boolean("material_available", [attacker, obj]),
                                    self.facts.boolean("observes", [attacker, obj]),
                                    self.facts.boolean("quantum_capable", [attacker, horizon]),
                                    self.facts.boolean("horizon_valid", [obj, horizon])])
            detail["derived"] = {"predicate": "passive_quantum_exposure", "value": exposure,
                                 "algorithm": algorithm, "function": function, "bits": bits,
                                 "horizon": horizon, "active_permissions_created": False,
                                 "normative_approval": "NOT_CHECKED",
                                 "scope": "educational passive exposure oracle; no prediction of hardware capability"}
            return negate(exposure), detail
        if checker == "evidence":
            return self.facts.boolean("evidence", [obj, req.get("document", "required")]), detail
        raise ValueError("unsupported checker: " + checker)


def analyze(model):
    started = perf_counter()
    errors = validate_model(model)
    if errors:
        model = model if isinstance(model, dict) else {}
        result = {"id": "model_consistency", "rule_id": "MODEL", "checker": "consistency", "status": "MODEL_ERROR",
                  "name": "Согласованность модели", "state": model.get("state"), "profile": model.get("profile"),
                  "object": None, "operation": None, "reason": "Contradictory or ill-typed model; no safety claim is possible",
                  "evidence": errors, "unknowns": [], "witness": None, "repair_options": []}
        return {"state": model.get("state"), "profile": model.get("profile"), "results": [result],
                "summary": {"MODEL_ERROR": 1}, "model_errors": errors, "timing": {"analysis_seconds": perf_counter() - started}}
    inference_start = perf_counter()
    engine = Engine(model)
    inference_seconds = perf_counter() - inference_start
    results = []
    for req in model.get("requirements", []):
        engine.facts.reset_trace()
        engine.derivations = []
        checker = req.get("checker")
        item = {"id": req["id"], "rule_id": req.get("rule_id", req["id"]),
                "catalog_rule_ids": req.get("catalog_rule_ids", []), "catalog_scope": req.get("catalog_scope", "fragment"),
                "name": req.get("name", req["id"]), "checker": checker, "state": model.get("state"),
                "profile": model.get("profile"), "object": req.get("object"), "operation": req.get("operation"),
                "subject": req.get("subject"), "applicability": req.get("applicable", "TRUE"),
                "cause_components": [], "witness": None, "repair_options": req.get("repair_options", [])}
        applicability = truth(req.get("applicable", "TRUE"))
        if applicability == FALSE:
            status, reason, value, detail = "NOT_APPLICABLE", "Explicit profile excludes this requirement", UNKNOWN, {}
        elif checker not in CHECKERS:
            status, reason, value, detail = "NOT_CHECKED", "No executable checker for this requirement", UNKNOWN, {}
        else:
            try:
                value, detail = engine.check(req)
                if applicability == UNKNOWN:
                    status, reason = "UNKNOWN", "Requirement applicability is unknown"
                elif checker == "evidence" and value == UNKNOWN:
                    status, reason = "REQUIRES_EVIDENCE", "Required documentary evidence has not been provided"
                else:
                    status = {TRUE: "PASS", FALSE: "FAIL", UNKNOWN: "UNKNOWN"}[value]
                    reason = {"PASS": "Requirement established in the explicit finite scope",
                              "FAIL": "Sufficient facts prove violation of the requirement",
                              "UNKNOWN": "Available facts or domain completeness do not decide the requirement"}[status]
            except (KeyError, ValueError, TypeError) as exc:
                status, reason, value, detail = "MODEL_ERROR", "Invalid checker specification: " + str(exc), UNKNOWN, {}
        evidence = list(engine.facts.used.values())
        causes = set()
        for entry in evidence:
            if entry.get("predicate") in {"present", "enabled", "healthy"} and entry.get("value") == "FALSE":
                causes.update(entry.get("args", []))
        item.update(status=status, reason=reason, value=value, evidence=evidence,
                    unknowns=list(engine.facts.missing.values()), derivation=engine.derivations,
                    cause_components=sorted(causes) if status in {"FAIL", "UNKNOWN"} else [],
                    requirement_provenance=req.get("provenance", []), **detail)
        if status == "FAIL" and not item["repair_options"]:
            item["repair_options"] = [
                {field: action.get(field) for field in ("id", "object", "effects", "preconditions", "cost", "provenance")}
                for action in model.get("action_catalog", []) if req["id"] in action.get("targets", [])]
        results.append(item)
        if status == "MODEL_ERROR":
            errors.append({"code": "INVALID_CHECKER_SPECIFICATION", "id": req["id"], "reason": reason})
    return {"state": model.get("state"), "profile": model.get("profile"), "results": results,
            "summary": dict(Counter(item["status"] for item in results)), "model_errors": errors,
            "availability": engine.availability, "inference_iterations": engine.iterations,
            "timing": {"inference_seconds": inference_seconds, "analysis_seconds": perf_counter() - started},
            "assumptions": model.get("assumptions", [])}


def reachability(model, subject, target, operation, scenario="default", kind="access", source=None):
    errors = validate_model(model)
    if errors:
        raise ValueError("MODEL_ERROR: " + str(errors))
    engine = Engine(model)
    engine.facts.reset_trace()
    result = engine.reachability(subject, target, operation, scenario, kind, source)
    result["evidence"] = list(engine.facts.used.values())
    return result


def structural_reachability(model, source, target):
    """Raw topology is explicitly separate from actual ability to operate."""
    adjacency = defaultdict(set)
    graph = model.get("raw_graph", model.get("source_graph", {}))
    facts = FactBase(model)
    for edge in graph.get("edges", []):
        a, b = (edge["source"], edge["target"]) if isinstance(edge, dict) else edge
        if facts.boolean("present", [a]) != FALSE and facts.boolean("present", [b]) != FALSE:
            adjacency[a].add(b)
    return witness_path(adjacency, source, target)
