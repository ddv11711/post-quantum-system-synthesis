"""Behavioral tests of finite mandatory access, separate from actual rights."""
from copy import deepcopy
from itertools import product

import pytest

from analyzer.engine import analyze, reachability
from analyzer.logic import TRUE, FALSE, UNKNOWN
from analyzer.mandatory import dominates
from analyzer.model import empty_model, fact, validate_model
from analyzer.transitions import apply_actions


LEVELS = ["public", "internal", "secret"]


def label(level="public", categories=()):
    return {"level": level, "categories": list(categories)}


def model(operation="read", subject_label=None, object_label=None, acl="TRUE"):
    m = empty_model("independent-model", "finite-mandatory")
    m["security_policy"] = {"enabled": True, "confidentiality_levels": list(LEVELS),
                            "integrity_enabled": False, "categories": ["HR", "ENG"]}
    m["nodes"] = {
        "operator": {"types": ["subject"], "security_label": subject_label or label()},
        "record": {"types": ["data"], "security_label": object_label or label()},
        "copy": {"types": ["data"], "security_label": label()},
    }
    m["facts"] = [fact("present", [key]) for key in m["nodes"]]
    m["facts"].append(fact("acl", ["operator", "record", operation], acl))
    m["mutable"] = [{"predicate": "acl", "args": ["operator", "record", operation]}]
    m["transitions"] = [{"id": "actual-operation", "subject": "operator", "source": "operator", "target": "record",
                          "operation": operation, "conditions": [{"predicate": "acl", "args": ["operator", "record", operation]}]}]
    m["completeness"] = [{"predicate": "transitions", "args_prefix": ["operator", operation, "default", "access"], "complete": True}]
    m["requirements"] = [{"id": "mac", "checker": "mandatory_access", "subject": "operator", "object": "record", "operation": operation}]
    return m


def finding(m):
    result = analyze(m)
    assert not result["model_errors"], result["model_errors"]
    return result["results"][0]


def add_flow(m, source="record", target="copy", *, scenario="copy"):
    m["transitions"].append({"id": "actual-copy", "subject": "operator", "source": source, "target": target,
                             "operation": "write", "kind": "flow", "scenario": scenario})
    m["completeness"].append({"predicate": "transitions", "args_prefix": ["operator", "write", scenario, "flow"], "complete": True})
    m["requirements"] = [{"id": "copy-label", "checker": "label_flow", "subject": "operator", "source": source,
                           "object": target, "operation": "write", "kind": "flow", "scenario": scenario}]


def exception(m):
    return {"id": "authorized-release", "subject": "operator", "source": "record", "target": "copy", "operation": "write", "scenario": "copy",
            "from_label": deepcopy(m["nodes"]["record"]["security_label"]), "to_label": deepcopy(m["nodes"]["copy"]["security_label"]),
            "authorized": "TRUE", "provenance": [{"kind": "declared", "file": "test policy"}]}


def test_dominance_against_independent_finite_lattice_oracle():
    # Independent bit-mask oracle: all ordered levels and all compartment sets.
    compartments = [[], ["HR"], ["ENG"], ["HR", "ENG"]]
    for a, b, ac, bc in product(range(3), range(3), range(4), range(4)):
        expected = a >= b and (ac | bc) == ac
        actual = dominates(label(LEVELS[a], compartments[ac]), label(LEVELS[b], compartments[bc]), LEVELS)
        assert (actual == TRUE) == expected
        assert actual != UNKNOWN


@pytest.mark.parametrize("operation", ["read", "write"])
def test_all_blp_level_and_compartment_combinations(operation):
    compartments = [[], ["HR"], ["ENG"], ["HR", "ENG"]]
    for a, b, ac, bc in product(range(3), range(3), range(4), range(4)):
        m = model(operation, label(LEVELS[a], compartments[ac]), label(LEVELS[b], compartments[bc]))
        allowed = (a >= b and (ac | bc) == ac) if operation == "read" else (b >= a and (bc | ac) == bc)
        result = finding(m)
        assert result["status"] == ("PASS" if allowed else "FAIL")
        assert result["mandatory"]["actual"] == TRUE
        assert result["witness"]["nodes"] == ["operator", "record"]


def test_strict_biba_is_explicit_optional_and_dual_to_confidentiality():
    for operation, a, b in product(("read", "write"), range(3), range(3)):
        m = model(operation)
        m["security_policy"].update(integrity_enabled=True, integrity_levels=["untrusted", "reviewed", "trusted"])
        m["nodes"]["operator"]["integrity_label"] = label(m["security_policy"]["integrity_levels"][a])
        m["nodes"]["record"]["integrity_label"] = label(m["security_policy"]["integrity_levels"][b])
        allowed = b >= a if operation == "read" else a >= b
        assert finding(m)["status"] == ("PASS" if allowed else "FAIL")
        m["security_policy"]["integrity_enabled"] = False
        assert finding(m)["status"] == "PASS"


def test_mandatory_policy_does_not_mask_actual_forbidden_path():
    m = model("read", label("public"), label("secret"))
    result = finding(m)
    assert result["status"] == "FAIL"
    assert result["mandatory"]["allowed"] == FALSE
    assert result["mandatory"]["actual"] == TRUE
    assert reachability(m, "operator", "record", "read")["value"] == TRUE
    repaired = apply_actions(m, [{"id": "revoke-actual-read", "effects": [{"predicate": "acl", "args": ["operator", "record", "read"], "value": "FALSE"}]}])
    assert finding(repaired)["status"] == "PASS"
    assert finding(repaired)["mandatory"]["allowed"] == FALSE
    assert repaired["security_policy"] == m["security_policy"]
    assert repaired["nodes"] == m["nodes"]


def test_unknown_labels_and_unknown_acl_are_not_treated_as_permission():
    m = model("read", label("public"), label("secret"), acl="UNKNOWN")
    assert finding(m)["status"] == "UNKNOWN"
    m = model()
    del m["nodes"]["operator"]["security_label"]
    result = finding(m)
    assert result["status"] == "UNKNOWN"
    assert any(e["predicate"] == "security_label" for e in result["unknowns"])
    m = model()
    m["nodes"]["operator"]["security_label"] = {"level": "public"}
    assert finding(m)["status"] == "UNKNOWN"
    m["nodes"]["operator"]["security_label"]["categories"] = []
    assert finding(m)["status"] == "PASS"


def test_known_violation_does_not_require_unknown_secondary_compartments():
    m = model("read", label("public"), label("secret"))
    del m["nodes"]["operator"]["security_label"]["categories"]
    assert finding(m)["status"] == "FAIL"
    # A proved absence of actual access discharges this prohibition even with missing labels.
    m["facts"][-1]["value"] = "FALSE"
    del m["nodes"]["record"]["security_label"]
    assert finding(m)["status"] == "PASS"


def test_clearance_is_ceiling_not_current_session_label():
    m = model("read", label("public"), label("secret"))
    m["nodes"]["operator"]["clearance"] = label("secret")
    assert finding(m)["status"] == "FAIL"  # high clearance never raises current label
    m["nodes"]["operator"]["security_label"] = label("secret")
    m["nodes"]["operator"]["clearance"] = label("internal")
    m["requirements"] = [{"id": "ceiling", "checker": "clearance", "subject": "operator"}]
    assert finding(m)["status"] == "FAIL"
    assert finding(m)["witness"] is None
    del m["nodes"]["operator"]["clearance"]
    assert finding(m)["status"] == "UNKNOWN"


def test_copy_preserves_classification_and_compartments():
    m = model(object_label=label("secret", ["HR"]))
    add_flow(m)
    assert finding(m)["status"] == "FAIL"
    assert finding(m)["witness"]["nodes"] == ["record", "copy"]
    m["nodes"]["copy"]["security_label"] = label("secret", ["HR", "ENG"])
    assert finding(m)["status"] == "PASS"
    m["nodes"]["copy"]["security_label"] = label("secret", ["ENG"])
    assert finding(m)["status"] == "FAIL"


def test_exact_declassification_does_not_create_access_or_bypass_integrity():
    m = model(object_label=label("secret", ["HR"]))
    add_flow(m)
    m["security_policy"]["declassifications"] = [exception(m)]
    result = finding(m)
    assert result["status"] == "PASS"
    assert result["mandatory"]["declassification"]["matching_authorizations"] == ["authorized-release"]
    m["security_policy"]["declassifications"][0]["scenario"] = "different"
    assert finding(m)["status"] == "FAIL"
    m["security_policy"]["declassifications"][0]["scenario"] = "copy"
    m["security_policy"].update(integrity_enabled=True, integrity_levels=["untrusted", "trusted"])
    m["nodes"]["record"]["integrity_label"] = label("untrusted")
    m["nodes"]["copy"]["integrity_label"] = label("trusted")
    assert finding(m)["status"] == "FAIL"
    # The authorization is normative only: removing actual flow removes the path.
    m["transitions"] = [m["transitions"][0]]
    assert reachability(m, "operator", "copy", "write", "copy", "flow", "record")["value"] == FALSE


def test_partial_or_wrong_declassification_cannot_grant_release():
    m = model(object_label=label("secret", ["HR"]))
    add_flow(m)
    auth = exception(m)
    m["security_policy"]["declassifications"] = [auth]
    auth["authorized"] = "UNKNOWN"
    assert finding(m)["status"] == "UNKNOWN"
    auth["authorized"] = "FALSE"
    assert finding(m)["status"] == "FAIL"
    auth["authorized"] = "TRUE"
    auth["to_label"] = label("internal")
    assert finding(m)["status"] == "FAIL"


def test_policy_disabled_is_not_applicable_and_unsupported_operation_unknown():
    m = model()
    m["security_policy"]["enabled"] = False
    assert finding(m)["status"] == "NOT_APPLICABLE"
    m = model("administer")
    assert finding(m)["status"] == "UNKNOWN"
    m = model()
    del m["security_policy"]["enabled"]
    assert finding(m)["status"] == "UNKNOWN"


@pytest.mark.parametrize("patch", [
    lambda m: m["security_policy"].update(enabled=1),
    lambda m: m["security_policy"].update(confidentiality_levels=["public", "public"]),
    lambda m: m["security_policy"].update(confidentiality_levels=[]),
    lambda m: m["security_policy"].update(confidentiality_levels=[0, 1]),
    lambda m: m["security_policy"].update(integrity_enabled="TRUE"),
    lambda m: m["nodes"]["record"].update(security_label=True),
    lambda m: m["nodes"]["record"].update(security_label={"level": "unknown-name", "categories": []}),
    lambda m: m["nodes"]["record"].update(security_label={"level": "public", "categories": ["HR", "HR"]}),
    lambda m: m["nodes"]["record"].update(security_label={"level": "public", "categories": ["unlisted"]}),
    lambda m: m["security_policy"].update(declassifications=[True]),
])
def test_malformed_labels_orders_and_exceptions_are_diagnostic(patch):
    m = model()
    patch(m)
    result = analyze(m)
    assert result["summary"] == {"MODEL_ERROR": 1}
    assert result["model_errors"]


def test_missing_order_is_unknown_not_an_invented_numeric_rank():
    m = model()
    del m["security_policy"]["confidentiality_levels"]
    assert finding(m)["status"] == "UNKNOWN"


def test_labels_clearance_and_security_policy_cannot_be_changed_by_repair_effects():
    m = model("read", label("public"), label("secret"))
    m["nodes"]["operator"]["clearance"] = label("public")
    before = deepcopy(m)
    for predicate in ("security_label", "clearance", "security_policy", "mandatory_allowed"):
        args = ["record"]
        m["mutable"].append({"predicate": predicate, "args": args})
        with pytest.raises(ValueError):
            apply_actions(m, [{"id": "fake-label-repair", "effects": [{"predicate": predicate, "args": args, "value": "TRUE"}]}])
    assert m["nodes"] == before["nodes"]
    assert m["security_policy"] == before["security_policy"]
    assert finding(m)["status"] == "FAIL"


def test_partial_dependency_list_retains_known_failure_but_not_false_success():
    m = model()
    m["nodes"]["service"] = {"types": ["component"]}
    m["facts"].extend(fact(predicate, ["service"]) for predicate in ("present", "enabled", "healthy"))
    m["dependencies"]["service"] = {"all": []}
    m["incomplete_dependencies"] = ["service"]
    m["requirements"] = [{"id": "service", "checker": "required_function", "object": "service"}]
    assert finding(m)["status"] == "UNKNOWN"
    next(f for f in m["facts"] if f["predicate"] == "healthy" and f["args"] == ["service"])["value"] = "FALSE"
    assert finding(m)["status"] == "FAIL"


def test_structural_only_readiness_is_explicit_unknown():
    m = empty_model("raw", "strict")
    m["requirements"] = [{"id": "semantics", "checker": "semantic_readiness", "missing": ["typed transitions", "policy"]}]
    result = finding(m)
    assert result["status"] == "UNKNOWN"
    assert len(result["unknowns"]) == 2


def test_unknown_policy_applicability_remains_unknown_without_an_actual_path():
    m = model(acl="FALSE")
    del m["security_policy"]["enabled"]
    assert finding(m)["status"] == "UNKNOWN"


def test_conflicting_exact_declassification_decisions_are_model_error():
    m = model(object_label=label("secret"))
    add_flow(m)
    yes, no = exception(m), exception(m)
    no.update(id="contradictory-release", authorized="FALSE")
    m["security_policy"]["declassifications"] = [yes, no]
    assert any(e["code"] == "CONFLICTING_DECLASSIFICATION" for e in validate_model(m))
