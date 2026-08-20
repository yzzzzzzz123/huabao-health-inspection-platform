"""Central Schema and cross-Stage semantic validation for Dolphin outputs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "skills" / "health-inspection" / "contracts" / "schemas"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import sha256_json  # noqa: E402
from shared.models import METRIC_COVERAGE, STAGE_BY_KEY  # noqa: E402
from policy_store import policy_runtime_gate_projection  # noqa: E402


class ValidationError(ValueError):
    """A candidate cannot be promoted."""


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def _resolve_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValidationError(f"unsupported external Schema reference: {reference}")
    value: Any = root
    for item in reference[2:].split("/"):
        key = item.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or key not in value:
            raise ValidationError(f"invalid Schema reference: {reference}")
        value = value[key]
    if not isinstance(value, dict):
        raise ValidationError(f"Schema reference is not an object: {reference}")
    return value


def validate(
    value: Any,
    schema: dict[str, Any],
    *,
    location: str = "$",
    root_schema: dict[str, Any] | None = None,
) -> None:
    root = root_schema or schema
    if "$ref" in schema:
        validate(
            value,
            _resolve_ref(root, str(schema["$ref"])),
            location=location,
            root_schema=root,
        )
        return
    expected = schema.get("type")
    if expected is not None:
        choices = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(value, str(item)) for item in choices):
            raise ValidationError(
                f"{location}: expected {choices}, got {type(value).__name__}"
            )
    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{location}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{location}: value {value!r} is outside enum")
    if isinstance(value, dict):
        missing = [key for key in schema.get("required", []) if key not in value]
        if missing:
            raise ValidationError(f"{location}: missing required keys {missing}")
        if len(value) < int(schema.get("minProperties", 0)):
            raise ValidationError(f"{location}: too few properties")
        if "maxProperties" in schema and len(value) > int(schema["maxProperties"]):
            raise ValidationError(f"{location}: too many properties")
        properties = schema.get("properties", {})
        patterns = schema.get("patternProperties", {})
        for key, child in value.items():
            matched = [
                item
                for pattern, item in patterns.items()
                if re.search(str(pattern), str(key)) is not None
            ]
            if (
                schema.get("additionalProperties") is False
                and key not in properties
                and not matched
            ):
                raise ValidationError(f"{location}: unexpected key {key!r}")
            if key in properties:
                validate(
                    child,
                    properties[key],
                    location=f"{location}.{key}",
                    root_schema=root,
                )
            for child_schema in matched:
                validate(
                    child,
                    child_schema,
                    location=f"{location}.{key}",
                    root_schema=root,
                )
            additional = schema.get("additionalProperties")
            if key not in properties and not matched and isinstance(additional, dict):
                validate(
                    child,
                    additional,
                    location=f"{location}.{key}",
                    root_schema=root,
                )
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            raise ValidationError(f"{location}: too few items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise ValidationError(f"{location}: too many items")
        if schema.get("uniqueItems") and len({repr(item) for item in value}) != len(value):
            raise ValidationError(f"{location}: duplicate items")
        child_schema = schema.get("items")
        if isinstance(child_schema, dict):
            for index, child in enumerate(value):
                validate(
                    child,
                    child_schema,
                    location=f"{location}[{index}]",
                    root_schema=root,
                )
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise ValidationError(f"{location}: string is too short")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise ValidationError(f"{location}: string is too long")
        if "pattern" in schema and re.search(str(schema["pattern"]), value) is None:
            raise ValidationError(
                f"{location}: does not match pattern {schema['pattern']}"
            )
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValidationError(f"{location}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValidationError(f"{location}: above maximum")


def load_schema(name: str) -> dict[str, Any]:
    path = SCHEMA_ROOT / name
    if path.parent != SCHEMA_ROOT or not path.is_file():
        raise ValidationError(f"unknown Schema: {name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError(f"Schema must be an object: {name}")
    return value


def validate_document(value: dict[str, Any], schema_name: str) -> None:
    schema = load_schema(schema_name)
    validate(value, schema, root_schema=schema)


def collect_evidence_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "evidence_refs" and isinstance(child, list):
                refs.update(str(item) for item in child)
            else:
                refs.update(collect_evidence_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(collect_evidence_refs(child))
    return refs


def _unique(values: Iterable[str], *, label: str) -> list[str]:
    result = [str(item) for item in values]
    if any(not item for item in result):
        raise ValidationError(f"{label} contains an empty ID")
    if len(result) != len(set(result)):
        raise ValidationError(f"{label} contains duplicate IDs")
    return result


def _passed_check(intelligence: dict[str, Any], name: str) -> bool:
    return any(
        item.get("name") == name and item.get("status") == "passed"
        for item in intelligence.get("self_test", {}).get("checks", [])
        if isinstance(item, dict)
    )


def validate_stage0(
    *,
    run_id: str,
    business_date: str,
    policy: dict[str, Any],
    source: dict[str, Any],
    facts: dict[str, Any],
    evidence_catalog: dict[str, Any],
    receipt: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    validate_document(facts, "facts.schema.json")
    validate_document(receipt, "data-operation.schema.json")
    if facts["run_id"] != run_id or facts["business_date"] != business_date:
        raise ValidationError("Stage 0 facts identity mismatch")
    if receipt["run_id"] != run_id or receipt["business_date"] != business_date:
        raise ValidationError("Stage 0 receipt identity mismatch")
    if receipt["status"] != "completed" or receipt["self_test"]["status"] != "passed":
        raise ValidationError("Stage 0 self-test did not pass")
    if receipt.get("command_plan") != [
        "data_layer",
        "calculate",
        "detect",
        "validate",
    ]:
        raise ValidationError("Stage 0 command plan differs from the allowlist")
    if receipt["self_test"]["unresolved_issues"]:
        raise ValidationError("Stage 0 has unresolved issues")
    metrics = facts.get("metrics", [])
    metric_ids = [str(item.get("id")) for item in metrics]
    source_ids = [str(item.get("id")) for item in source.get("metrics", [])]
    if (
        len(metrics) != METRIC_COVERAGE["total"]
        or metric_ids != source_ids
        or len(set(metric_ids)) != METRIC_COVERAGE["total"]
    ):
        raise ValidationError("Stage 0 must preserve the complete catalog order")
    dimensions = {
        key: sum(item.get("dimension") == key for item in metrics)
        for key in METRIC_COVERAGE["dimension"]
    }
    if dimensions != METRIC_COVERAGE["dimension"]:
        raise ValidationError("Stage 0 dimension coverage differs from contract")
    catalog_ids = [
        str(item.get("evidence_id"))
        for item in evidence_catalog.get("evidence", [])
    ]
    if len(catalog_ids) != len(set(catalog_ids)):
        raise ValidationError("evidence catalog contains duplicate IDs")
    if set(facts.get("evidence_ids", [])) != set(catalog_ids):
        raise ValidationError("facts evidence index differs from catalog")
    gate = policy_runtime_gate_projection(policy)
    if facts.get("health_policy", {}).get("sha256") != policy["sha256"]:
        raise ValidationError("facts are not bound to the frozen policy")
    coverage = facts["health"]["assessment"]
    expected = gate["evaluation"]
    for key in (
        "evaluated",
        "partially_evaluated",
        "monitor_only",
        "rule_covered",
        "active_rules",
    ):
        actual_key = {
            "evaluated": "evaluated_count",
            "partially_evaluated": "partially_evaluated_count",
            "monitor_only": "monitor_only_count",
            "rule_covered": "rule_covered_count",
            "active_rules": "active_rule_count",
        }[key]
        if coverage[actual_key] != expected[key]:
            raise ValidationError(f"Stage 0 policy coverage mismatch: {key}")
    if manifest.get("integrity") != "passed":
        raise ValidationError("Stage 0 manifest is not marked passed")
    hashes = manifest.get("artifacts")
    expected_hashes = {
        "data_layer_source": sha256_json(source),
        "data_layer_health_policy": sha256_json(policy),
        "data_layer_facts": sha256_json(facts),
        "data_layer_evidence_catalog": sha256_json(evidence_catalog),
    }
    if hashes != expected_hashes:
        raise ValidationError("Stage 0 manifest hashes differ from business documents")


def validate_stage_envelope(
    *,
    stage: str,
    business: dict[str, Any],
    intelligence: dict[str, Any],
    facts: dict[str, Any],
    evidence_catalog: dict[str, Any],
    upstream: Mapping[str, dict[str, Any]],
    packet: dict[str, Any],
) -> None:
    if stage not in STAGE_BY_KEY:
        raise ValidationError(f"unsupported Stage: {stage}")
    spec = STAGE_BY_KEY[stage]
    validate_document(business, str(spec["schema"]))
    validate_document(intelligence, "intelligence.schema.json")
    self_test = intelligence.get("self_test", {})
    if (
        self_test.get("status") != "passed"
        or self_test.get("unresolved_issues")
        or any(
            item.get("status") != "passed"
            for item in self_test.get("checks", [])
            if isinstance(item, dict)
        )
    ):
        raise ValidationError(f"{stage} Agent self-test did not pass")
    if (
        business.get("run_id") != facts.get("run_id")
        or business.get("business_date") != facts.get("business_date")
        or business.get("stage") != stage
        or intelligence.get("stage") != stage
        or intelligence.get("agent") != spec["agent"]
    ):
        raise ValidationError(f"{stage} identity differs from deterministic facts")
    evidence_ids = {
        str(item["evidence_id"]) for item in evidence_catalog.get("evidence", [])
    }
    unknown = collect_evidence_refs(
        {"business": business, "intelligence": intelligence}
    ) - evidence_ids
    if unknown:
        raise ValidationError(f"{stage} references unknown evidence: {sorted(unknown)}")

    if stage == "inspector":
        expected = _unique(
            (item["anomaly_id"] for item in facts["anomalies"]),
            label="deterministic anomalies",
        )
        components = {
            item["dimension"]: item for item in facts["health"]["components"]
        }
        dimensions = _unique(
            (item["dimension"] for item in business["dimension_summary"]),
            label="dimension summary",
        )
        if set(dimensions) != set(components):
            raise ValidationError("Inspector must preserve all three dimensions")
        for item in business["dimension_summary"]:
            expected_component = components[item["dimension"]]
            if (
                item["score"] != expected_component["score"]
                or item["status"] != expected_component["assessment_status"]
            ):
                raise ValidationError("Inspector changed deterministic health state")
        ranked = _unique(
            (item["anomaly_id"] for item in business["ranked_anomalies"]),
            label="ranked anomalies",
        )
        if set(ranked) != set(expected):
            raise ValidationError("Inspector must rank every deterministic anomaly")
        case_ids = _unique(
            (item["case_id"] for item in business["cases"]),
            label="Inspector cases",
        )
        del case_ids
        partition: list[str] = []
        for case in business["cases"]:
            partition.extend(
                _unique(case["anomaly_ids"], label=f"{case['case_id']} anomalies")
            )
        if len(partition) != len(set(partition)) or set(partition) != set(expected):
            raise ValidationError(
                "Inspector cases must strictly partition every anomaly exactly once"
            )
        if not _passed_check(intelligence, "case_anomaly_partition_contract"):
            raise ValidationError("Inspector partition self-test is missing")

    elif stage == "diagnostician":
        inspection = upstream["inspector"]
        cases = {item["case_id"]: item for item in inspection["cases"]}
        diagnoses = business["diagnoses"]
        _unique((item["diagnosis_id"] for item in diagnoses), label="diagnoses")
        covered = _unique(
            (item["case_id"] for item in diagnoses),
            label="diagnosis case coverage",
        )
        if set(covered) != set(cases):
            raise ValidationError("Diagnoses must cover exactly the Inspector cases")
        for diagnosis in diagnoses:
            expected = set(cases[diagnosis["case_id"]]["anomaly_ids"])
            actual = set(
                _unique(
                    diagnosis["anomaly_ids"],
                    label=f"{diagnosis['diagnosis_id']} anomalies",
                )
            )
            if actual != expected or diagnosis["anomaly_id"] not in expected:
                raise ValidationError("Diagnosis breaks the Inspector anomaly chain")

    elif stage == "advisor":
        diagnoses = {
            item["diagnosis_id"]: item
            for item in upstream["diagnostician"]["diagnoses"]
        }
        actions = business["actions"]
        _unique((item["action_id"] for item in actions), label="actions")
        if {item["diagnosis_id"] for item in actions} != set(diagnoses):
            raise ValidationError("Advisor must cover every diagnosis")
        metric_ids = {item["id"] for item in facts["metrics"]}
        anomaly_metric = {
            item["anomaly_id"]: item["metric_id"] for item in facts["anomalies"]
        }
        for action in actions:
            diagnosis = diagnoses[action["diagnosis_id"]]
            anomaly_ids = set(
                _unique(action["anomaly_ids"], label=f"{action['action_id']} anomalies")
            )
            if not anomaly_ids.issubset(set(diagnosis["anomaly_ids"])):
                raise ValidationError("Advisor anomaly IDs do not close to diagnosis")
            target_ids = set(
                _unique(
                    action["target_metric_ids"],
                    label=f"{action['action_id']} target metrics",
                )
            )
            if target_ids - metric_ids or not {
                anomaly_metric[item] for item in anomaly_ids
            }.issubset(target_ids):
                raise ValidationError("Advisor target metrics are not closed")
            manual_fields = {
                "adjustment_content",
                "expected_improvement",
                "observation_metrics",
            }
            if action["action_type"] == "review_only":
                if manual_fields & set(action):
                    raise ValidationError("review_only contains adjustment fields")
            else:
                if manual_fields - set(action):
                    raise ValidationError("manual_adjustment is incomplete")
                directions = {
                    item["metric_id"] for item in action["expected_improvement"]
                }
                if directions != target_ids:
                    raise ValidationError(
                        "manual expected directions must cover target metrics"
                    )
                for window in ("next_day", "day_7"):
                    observed = set(action["observation_metrics"][window])
                    if not observed or not observed.issubset(target_ids):
                        raise ValidationError(
                            "observation metrics must use target HI IDs"
                        )

    elif stage == "auditor":
        actions = {
            item["action_id"]: item for item in upstream["advisor"]["actions"]
        }
        reviews = business["logic_reviews"]
        _unique((item["review_id"] for item in reviews), label="logic reviews")
        covered = _unique(
            (item["action_id"] for item in reviews),
            label="Auditor action coverage",
        )
        if set(covered) != set(actions):
            raise ValidationError("Auditor must review exactly all actions")
        for review in reviews:
            action = actions[review["action_id"]]
            if (
                review["diagnosis_id"] != action["diagnosis_id"]
                or review["anomaly_ids"] != action["anomaly_ids"]
                or review["target_metric_ids"] != action["target_metric_ids"]
            ):
                raise ValidationError("Auditor logic review breaks the ID chain")
        due = packet.get("facts_projection", {}).get("due_effect_reviews", [])
        expected = {item["review_key"]: item for item in due}
        actual = {
            item["review_key"]: item for item in business.get("effect_reviews", [])
        }
        if len(expected) != len(due) or set(actual) != set(expected):
            raise ValidationError("Auditor effect review coverage differs from packet")
        for key, projection in expected.items():
            for field, expected_value in projection.items():
                if actual[key].get(field) != expected_value:
                    raise ValidationError(
                        f"{key}: Auditor changed deterministic field {field}"
                    )
            if "因果" not in actual[key]["attribution_limit"]:
                raise ValidationError(f"{key}: causal attribution limit is missing")

    elif stage == "reporter":
        action_plan = upstream["advisor"]
        audit = upstream["auditor"]
        inspection = upstream["inspector"]
        health = facts["health"]
        expected_assessment = {
            "band": health["band"],
            "rated_band": health["rated_band"],
            "provisional": health["provisional"],
            "scoring_status": health["scoring"]["status"],
            "scoring_source": health["scoring"]["source"],
            "scoring_confirmed": health["scoring"]["confirmed"],
            **health["assessment"],
        }
        if (
            business["health_score"] != health["score"]
            or business["health_assessment"] != expected_assessment
            or business["data_provenance"] != facts["data_provenance"]
        ):
            raise ValidationError("Reporter changed deterministic facts")
        fixed_delivery = {
            "channel": "dingtalk_custom_robot",
            "mode": "automatic_after_finalize",
            "send": True,
        }
        if business["delivery_request"] != fixed_delivery:
            raise ValidationError("Reporter delivery request is not fixed")
        if not _passed_check(intelligence, "delivery_request_contract"):
            raise ValidationError("Reporter delivery request self-test is missing")
        anomaly_ids = {
            item["anomaly_id"] for item in inspection["ranked_anomalies"]
        }
        if {item["anomaly_id"] for item in business["key_anomalies"]} != anomaly_ids:
            raise ValidationError("Reporter must preserve all verified anomalies")
        actions = {item["action_id"]: item for item in action_plan["actions"]}
        logic = {item["action_id"]: item for item in audit["logic_reviews"]}
        supported = {
            key
            for key, value in logic.items()
            if value["verdict"] in {"supported", "supported_with_caveats"}
        }
        recommended = {
            item["action_id"] for item in business["recommended_actions"]
        }
        unsupported = {
            item["action_id"] for item in business["unsupported_actions"]
        }
        if recommended != supported or unsupported != set(actions) - supported:
            raise ValidationError("Reporter recommendation split differs from audit")
        for item in business["recommended_actions"]:
            action = actions[item["action_id"]]
            expected_status = (
                "not_applicable"
                if action["action_type"] == "review_only"
                else "manual_execution"
            )
            for field in (
                "title",
                "action_type",
                "owner",
                "priority",
                "target_metric_ids",
                "acceptance_criteria",
            ):
                if item[field] != action[field]:
                    raise ValidationError(
                        f"Reporter changed trusted action field {field}"
                    )
            if item["audit_verdict"] != logic[item["action_id"]]["verdict"]:
                raise ValidationError("Reporter changed audit verdict")
            if item["implementation_status"] != expected_status:
                raise ValidationError("Reporter implementation status is invalid")
            if action["action_type"] == "manual_adjustment":
                if item.get("adjustment_content") != action["adjustment_content"]:
                    raise ValidationError("Reporter changed adjustment content")
            elif "adjustment_content" in item:
                raise ValidationError("Reporter added adjustment to review_only")
        if business["effect_reviews"] != audit["effect_reviews"]:
            raise ValidationError("Reporter must preserve effect reviews exactly")
        binding = intelligence.get("controlled_bindings", {}).get(
            "effect_reviews"
        )
        expected_binding = {
            "source_stage": "auditor",
            "source_field": "effect_reviews",
            "item_count": len(audit["effect_reviews"]),
            "sha256": sha256_json(audit["effect_reviews"]),
        }
        if binding != expected_binding:
            raise ValidationError(
                "Reporter effect review controlled binding is invalid"
            )


def validate_envelope(
    *,
    stage: str,
    envelope: dict[str, Any],
    facts: dict[str, Any],
    evidence_catalog: dict[str, Any],
    upstream: Mapping[str, dict[str, Any]],
    packet: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(envelope) != {"business", "intelligence"}:
        raise ValidationError("Agent envelope must contain business and intelligence")
    business = envelope["business"]
    intelligence = envelope["intelligence"]
    if not isinstance(business, dict) or not isinstance(intelligence, dict):
        raise ValidationError("Agent envelope members must be objects")
    validate_stage_envelope(
        stage=stage,
        business=business,
        intelligence=intelligence,
        facts=facts,
        evidence_catalog=evidence_catalog,
        upstream=upstream,
        packet=packet,
    )
    return business, intelligence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True)
    args = parser.parse_args()
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise SystemExit("document must be a JSON object")
    validate_document(value, args.schema)
    print(json.dumps({"valid": True, "sha256": sha256_json(value)}))


if __name__ == "__main__":
    main()
