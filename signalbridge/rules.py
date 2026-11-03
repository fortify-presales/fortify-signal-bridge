"""YAML signal rules. Classifiers stay in fcli; this module only makes emit decisions."""

import glob
import os

import yaml

FIELD_MAP = {
    "finding.severity": "severity",
    "finding.suppressed": "suppressed",
    "finding.domain": "finding_domain",
    "finding.ai_application_type": "ai_application_type",
    "finding.source_status": "source_status",
    "finding.auditor_status": "auditor_status",
    "finding.category": "category",
    "finding.exploited": "exploited",
    "finding.malware": "malware",
    "finding.fortify_aviator": "fortify_aviator",
}

ALLOWED_RULE_KEYS = {"id", "version", "description", "enabled", "platforms", "when", "emit"}
ALLOWED_EMIT = {"type", "confidence", "severity_from", "title"}


class RuleError(Exception):
    pass


def _fail(path, message):
    raise RuleError(f"{path}: {message}")


def _check_rule_directory(directory, path, platforms):
    """Product folders match classifiers/<platform>/. shared/ is for rules that span products."""
    parent = os.path.dirname(os.path.abspath(path))
    root = os.path.abspath(directory)
    if os.path.dirname(parent) != root:
        return
    folder = os.path.basename(parent)
    if folder == "shared":
        if len(set(platforms)) < 2:
            _fail(path, "rules in shared/ must list more than one platform")
        return
    if set(platforms) != {folder}:
        _fail(path, f"rules in {folder}/ must set platforms to [{folder}]")


def load_rules(directory):
    # Top-level files keep a flat custom directory working. One subdirectory level
    # matches classifiers/<platform>/, plus shared/ for rules that span products.
    paths = sorted(set(
        glob.glob(os.path.join(directory, "*.yaml"))
        + glob.glob(os.path.join(directory, "*.yml"))
        + glob.glob(os.path.join(directory, "*", "*.yaml"))
        + glob.glob(os.path.join(directory, "*", "*.yml"))
    ))
    if not paths:
        raise RuleError(f"No signal rules in {directory}")
    rules = []
    seen = set()
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle)
        if not isinstance(doc, dict):
            _fail(path, "rule must be a mapping")
        unknown = set(doc) - ALLOWED_RULE_KEYS
        if unknown:
            _fail(path, f"unknown keys {sorted(unknown)}")
        rule_id = doc.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            _fail(path, "id is required")
        if rule_id in seen:
            _fail(path, f"duplicate rule id {rule_id}")
        seen.add(rule_id)
        version = doc.get("version")
        if not isinstance(version, str) or not version:
            _fail(path, "version must be a string")
        platforms = doc.get("platforms")
        if not isinstance(platforms, list) or not platforms or any(p not in ("fod", "ssc") for p in platforms):
            _fail(path, "platforms must list fod and/or ssc")
        _check_rule_directory(directory, path, platforms)
        when = doc.get("when") or {}
        conditions = when.get("all") if isinstance(when, dict) else None
        if not isinstance(conditions, list) or not conditions:
            _fail(path, "when.all must be a non-empty list")
        parsed = []
        for condition in conditions:
            parsed.append(_parse_condition(path, condition))
        emit = doc.get("emit") or {}
        if not isinstance(emit, dict):
            _fail(path, "emit must be a mapping")
        extra = set(emit) - ALLOWED_EMIT
        if extra:
            _fail(path, f"unknown emit keys {sorted(extra)}")
        for key in ("type", "confidence", "title"):
            if not isinstance(emit.get(key), str) or not emit[key]:
                _fail(path, f"emit.{key} is required")
        if emit.get("severity_from") not in (None, "finding.severity"):
            _fail(path, "emit.severity_from must be finding.severity")
        rules.append({
            "id": rule_id,
            "version": version,
            "description": doc.get("description") or "",
            "enabled": bool(doc.get("enabled", True)),
            "platforms": list(platforms),
            "conditions": parsed,
            "emit": emit,
            "path": path,
        })
    return rules


def _parse_condition(path, condition):
    if not isinstance(condition, dict):
        _fail(path, "condition must be a mapping")
    if "classification" in condition:
        if set(condition) - {"classification", "equals"}:
            _fail(path, "classification conditions only allow equals")
        if condition.get("equals") not in (True, False):
            _fail(path, "classification equals must be true or false")
        if not isinstance(condition.get("classification"), str):
            _fail(path, "classification id must be a string")
        return {"kind": "classification", "id": condition["classification"], "equals": condition["equals"]}
    if "field" in condition:
        allowed = {"field", "equals", "in"}
        if set(condition) - allowed:
            _fail(path, f"unknown condition keys {sorted(set(condition) - allowed)}")
        field = condition.get("field")
        if field not in FIELD_MAP:
            _fail(path, f"unknown field {field}")
        if "equals" in condition and "in" in condition:
            _fail(path, "use equals or in, not both")
        if "equals" in condition:
            return {"kind": "equals", "field": field, "equals": condition["equals"]}
        if "in" in condition:
            if not isinstance(condition["in"], list) or not condition["in"]:
                _fail(path, "in must be a non-empty list")
            return {"kind": "in", "field": field, "in": list(condition["in"])}
        _fail(path, "field condition needs equals or in")
    _fail(path, "condition needs classification or field")
    return None


def rules_for_platform(rules, platform):
    return [rule for rule in rules if rule["enabled"] and platform in rule["platforms"]]


def referenced_classifiers(rules, platform):
    ids = []
    for rule in rules_for_platform(rules, platform):
        for condition in rule["conditions"]:
            if condition["kind"] == "classification" and condition["id"] not in ids:
                ids.append(condition["id"])
    return ids


def matches(rule, finding):
    return all(_match_condition(condition, finding) for condition in rule["conditions"])


def _match_condition(condition, finding):
    if condition["kind"] == "classification":
        present = condition["id"] in (finding.get("classifications") or [])
        return present if condition["equals"] else not present
    value = finding.get(FIELD_MAP[condition["field"]])
    # A missing or null value is unknown. It does not satisfy true, false, or membership.
    if value is None:
        return False
    if condition["kind"] == "equals":
        return value == condition["equals"]
    return value in condition["in"]
