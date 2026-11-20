"""Finite physical/syntactic/semantic channels, separate from access rights.

This module deliberately has no dependency on model.py or engine.py. A channel
can be inspected by renderers without constructing an inference engine. Nodes
and actual ACL are never inferred from a layer value or a drawing convention.
"""
from collections import defaultdict
from copy import deepcopy
from .logic import TRUE, FALSE, UNKNOWN, conjunction, truth

LAYERS = ("physical", "syntactic", "semantic")


def layer_value(value):
    """Normalize explicit three-valued data; reject numeric Boolean lookalikes."""
    if value is True:
        return TRUE
    if value is False:
        return FALSE
    if value is None:
        return UNKNOWN
    if isinstance(value, str) and value in {"TRUE", "FALSE", "UNKNOWN"}:
        return truth(value)
    raise ValueError("FLS layer must be true, false, TRUE, FALSE, UNKNOWN, or omitted")


def normalize_layers(layers):
    if not isinstance(layers, dict) or set(layers) - set(LAYERS):
        raise ValueError("FLS layers must be an object containing only physical, syntactic and semantic")
    return {name: layer_value(layers.get(name)).value for name in LAYERS}


def validate_fls(model):
    """Validate canonical channels and direction-exact transition references."""
    errors = []
    channels = model.get("fls_channels", [])
    if not isinstance(channels, list):
        return [{"code": "INVALID_FLS_CHANNELS", "reason": "fls_channels must be a list"}]
    index = {}
    nodes = model.get("nodes", {})
    for offset, channel in enumerate(channels):
        path = f"fls_channels/{offset}"
        if not isinstance(channel, dict):
            errors.append({"code": "INVALID_FLS_CHANNEL", "path": path, "reason": "expected object"})
            continue
        key = channel.get("id")
        if not isinstance(key, str) or not key or key in index:
            errors.append({"code": "INVALID_FLS_CHANNEL_ID", "path": path})
        else:
            index[key] = channel
        for field in ("source", "target"):
            node = channel.get(field)
            if not isinstance(node, str) or node not in nodes:
                errors.append({"code": "UNKNOWN_FLS_ENDPOINT", "path": path + "/" + field, "object": node})
        try:
            normalize_layers(channel.get("layers", {}))
        except (ValueError, TypeError) as exc:
            errors.append({"code": "INVALID_FLS_LAYERS", "path": path + "/layers", "reason": str(exc)})
        route = channel.get("protection_via", [])
        if not isinstance(route, list) or any(not isinstance(node, str) or not node for node in route):
            errors.append({"code": "INVALID_FLS_PROTECTION_ROUTE", "path": path, "reason": "protection_via must be an ordered list of exact node keys"})
            continue
        if len(route) != len(set(route)) or any(node in (channel.get("source"), channel.get("target")) for node in route):
            errors.append({"code": "INVALID_FLS_PROTECTION_ROUTE", "path": path, "reason": "intermediate protection nodes must be distinct from each other and from endpoints"})
        for node in route:
            if node not in nodes:
                errors.append({"code": "UNKNOWN_FLS_PROTECTION_NODE", "path": path, "object": node})
            elif not set(nodes[node].get("types", ["unknown"])) & {"component", "function", "channel", "unknown"}:
                errors.append({"code": "INVALID_FLS_PROTECTION_TYPE", "path": path, "object": node,
                               "reason": "protective route requires component, function, channel or unknown type"})
    for transition in model.get("transitions", []):
        if "channel" not in transition:
            continue
        ref = transition["channel"]
        if not isinstance(ref, str) or ref not in index:
            errors.append({"code": "UNKNOWN_TRANSITION_CHANNEL", "transition": transition.get("id"), "channel": ref})
        else:
            channel = index[ref]
            if (transition.get("source"), transition.get("target")) != (channel.get("source"), channel.get("target")):
                errors.append({"code": "FLS_DIRECTION_MISMATCH", "transition": transition.get("id"), "channel": ref,
                               "reason": "access/flow endpoints must match this directed channel exactly"})
    return errors


class _ChannelFacts:
    """Restricted snapshot fact reader with the same open-world semantics.

    Only presence and physical transport state are read. Keeping this tiny
    adapter independent avoids a model ↔ FLS import cycle in schema validation.
    """
    def __init__(self, model, fact_index=None):
        self.model = model
        self.index = fact_index if fact_index is not None else defaultdict(list)
        if fact_index is None:
            for entry in model.get("facts", []):
                self.index[(entry["predicate"], tuple(entry["args"]))].append(entry)
        self.reset_trace()

    def reset_trace(self):
        self.evidence = {}
        self.unknowns = {}

    def get(self, predicate, node):
        args = (node,)
        entries = self.index.get((predicate, args), [])
        if entries:
            for index, entry in enumerate(entries):
                self.evidence[(predicate, args, index)] = entry
            values = {("TRUE" if e["value"] is True else "FALSE" if e["value"] is False else str(e["value"].value if hasattr(e["value"], "value") else e["value"])) for e in entries}
            value = next(iter(values)) if len(values) == 1 else UNKNOWN
            if value == UNKNOWN:
                self.unknowns[(predicate, args)] = {"predicate": predicate, "args": list(args), "reason": "physical route fact is UNKNOWN or conflicting"}
            return value
        if predicate != "failure_mode":
            for entry in self.model.get("completeness", []):
                prefix = tuple(entry.get("args_prefix", []))
                if entry.get("predicate") == predicate and entry.get("complete") is True and args[:len(prefix)] == prefix:
                    self.evidence[("complete", predicate, prefix)] = {"completeness": entry}
                    return FALSE
        self.unknowns[(predicate, args)] = {"predicate": predicate, "args": list(args), "reason": "physical route fact absent; no complete relation scope"}
        return UNKNOWN

    def boolean(self, predicate, node):
        return layer_value(self.get(predicate, node))

    def transport(self, node):
        mode = self.get("failure_mode", node)
        health = self.boolean("healthy", node)
        if mode == "fail_open":
            works = TRUE
        elif mode == "fail_closed":
            works = FALSE
        elif mode == "normal":
            works = health
        else:
            works = TRUE if health == TRUE else UNKNOWN
        return conjunction([self.boolean("present", node), self.boolean("transport_enabled", node), works])


class FLSEvaluator:
    """Reusable indices for one immutable snapshot; channel traces stay isolated."""
    def __init__(self, model, *, fact_index=None):
        self.model = model
        self.facts = _ChannelFacts(model, fact_index=fact_index)
        self.channels = {}
        for channel in model.get("fls_channels", []):
            if not isinstance(channel, dict) or not isinstance(channel.get("id"), str):
                raise ValueError("FLS channels require string identifiers")
            if channel["id"] in self.channels:
                raise ValueError("Duplicate FLS channel id " + channel["id"])
            self.channels[channel["id"]] = channel

    def evaluate(self, channel_or_id):
        if isinstance(channel_or_id, str):
            if channel_or_id not in self.channels:
                raise ValueError("Unknown FLS channel id " + channel_or_id)
            channel = self.channels[channel_or_id]
        elif isinstance(channel_or_id, dict):
            channel = channel_or_id
        else:
            raise ValueError("Expected FLS channel object or id")
        layers = normalize_layers(channel.get("layers", {}))
        facts = self.facts
        facts.reset_trace()
        if channel.get("source") not in self.model.get("nodes", {}) or channel.get("target") not in self.model.get("nodes", {}):
            raise ValueError("FLS channel endpoints must reference existing nodes")
        protection = channel.get("protection_via", [])
        physical_conditions = [facts.boolean("present", channel["source"]), facts.boolean("present", channel["target"])]
        transport = []
        for node in protection:
            value = facts.transport(node)
            physical_conditions.append(value)
            transport.append({"node": node, "value": value, "predicate": "transport", "args": [node]})
        effective = dict(layers)
        effective["physical"] = conjunction([layers["physical"], *physical_conditions]).value
        unknowns = list(facts.unknowns.values())
        layer_evidence = []
        for name in LAYERS:
            layer_evidence.append({"predicate": "fls_layer", "args": [channel["id"], name], "value": layers[name],
                                   "provenance": deepcopy(channel.get("provenance", [])), "source_field": "layers." + name})
            if layers[name] == UNKNOWN:
                unknowns.append({"predicate": "fls_layer", "args": [channel["id"], name], "reason": "FLS layer omitted or explicitly UNKNOWN"})
        return {"id": channel["id"], "source": channel["source"], "target": channel["target"],
                "layers": layers, "effective_layers": effective, "value": conjunction(effective.values()).value,
                "protection_via": list(protection), "route": [channel["source"], *protection, channel["target"]],
                "transport_conditions": transport, "evidence": layer_evidence + list(facts.evidence.values()),
                "unknowns": unknowns, "provenance": deepcopy(channel.get("provenance", [])),
                "semantics": "physical AND syntactic AND semantic; channel existence alone grants no operation"}


def evaluate_channel(model, channel_or_id):
    """Evaluate one valid directed channel without granting any operation.

    ``layers`` are declarations, ``effective_layers`` include physical route
    availability. Protective ``enabled`` is intentionally not a transport gate.
    Call validate_model/validate_fls before evaluating untrusted native models.
    For a batch, evaluate_channels shares the snapshot's indices automatically.
    """
    return FLSEvaluator(model).evaluate(channel_or_id)


def evaluate_channels(model):
    evaluator = FLSEvaluator(model)
    return [evaluator.evaluate(key) for key in sorted(evaluator.channels)]
