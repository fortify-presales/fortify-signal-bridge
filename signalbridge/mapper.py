"""Map a collector finding and a matched rule into a fortify.signal document."""

from signalbridge import PROCESSOR_VERSION, SIGNAL_SCHEMA_VERSION
from signalbridge.event_id import event_id

SEVERITY_NAMES = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Info": "info",
    "Best_Practice": "best_practice",
}


def signal_severity(raw):
    if raw is None:
        return None
    if raw in SEVERITY_NAMES:
        return SEVERITY_NAMES[raw]
    return str(raw).lower()


def build_signal(document, finding, rule, observed_at, detail_level):
    platform = document.get("source_platform")
    instance_id = document.get("source_instance_id")
    revision = finding.get("source_revision")
    identity = event_id(
        platform,
        instance_id,
        finding.get("release_id"),
        finding.get("source_finding_id"),
        finding.get("last_modified_date"),
        revision,
        rule["id"],
        rule["version"],
        SIGNAL_SCHEMA_VERSION,
    )
    catalog = {item.get("id"): item for item in (document.get("classification") or {}).get("classifiers") or []}
    evidence = []
    matched_ids = set(finding.get("classifications") or [])
    for condition in rule["conditions"]:
        if condition["kind"] != "classification":
            continue
        meta = catalog.get(condition["id"]) or {}
        version = meta.get("version")
        evidence.append({
            "id": condition["id"],
            "version": None if version is None else str(version),
            "matched": condition["id"] in matched_ids,
        })
    producer = document.get("producer") or {}
    finding_out = {
        "domain": finding.get("finding_domain"),
        "category": finding.get("category"),
        "cwe": None,
        "source_status": finding.get("source_status"),
        "auditor_status": finding.get("auditor_status"),
        "suppressed": finding.get("suppressed"),
        "last_modified": finding.get("last_modified_date"),
    }
    if detail_level in ("standard", "full"):
        finding_out.update({
            "file_path": finding.get("file_path"),
            "line": finding.get("line"),
            "component_name": finding.get("component_name"),
            "component_version": finding.get("component_version"),
            "component_purl": finding.get("component_purl"),
            "advisory_ids": list(finding.get("advisory_ids") or []),
            "summary": finding.get("summary"),
        })
    if detail_level == "full":
        finding_out.update({
            "explanation": finding.get("explanation"),
            "recommendation": finding.get("recommendation"),
            "traces": list(finding.get("traces") or []),
        })
    return {
        "schema_name": "fortify.signal",
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "event_id": identity,
        "event_type": "fortify.signal.observed",
        "observed_at": observed_at,
        "source": {
            "platform": platform,
            "instance_id": instance_id,
            "application_id": finding.get("application_id"),
            "release_id": finding.get("release_id"),
            "finding_id": finding.get("source_finding_id"),
            "deep_link": finding.get("source_url"),
        },
        "application": {
            "name": finding.get("application_name"),
            "release": finding.get("release_name"),
        },
        "signal": {
            "type": rule["emit"]["type"],
            "severity": signal_severity(finding.get("severity")),
            "confidence": rule["emit"]["confidence"],
            "title": rule["emit"]["title"],
        },
        "finding": finding_out,
        "evidence": {"classifications": evidence},
        "provenance": {
            "collection_id": document.get("collection_id"),
            "collector_version": producer.get("collector_version"),
            "processor_version": PROCESSOR_VERSION,
            "signal_rule_id": rule["id"],
            "signal_rule_version": rule["version"],
            "signal_schema_version": SIGNAL_SCHEMA_VERSION,
        },
    }
