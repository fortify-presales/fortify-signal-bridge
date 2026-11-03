"""Map an fcli SSC issue record into a fortify.collector finding.

The SSC fcli action applies the same field table. Tests use this function so the
mapping does not depend on a live SSC. SSC engine type SCA is static analysis and
becomes finding domain SAST. Finding domain SCA is reserved for open source.
"""

AI_TYPES = {"Non AI", "LLM Application", "AI Agent"}
ENGINE_DOMAIN = {
    "SCA": ("SAST", "Static"),
    "WEBINSPECT": ("DAST", "Dynamic"),
    "DEBRICKED": ("SCA", "OpenSource"),
}


def ai_application_type(version):
    attributes = (version or {}).get("attrValuesByName") or {}
    value = attributes.get("AI Application Type")
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else None
    if value in AI_TYPES:
        return value
    return None


def _domain(issue):
    engine = issue.get("engineType")
    if engine in ENGINE_DOMAIN:
        return ENGINE_DOMAIN[engine]
    return "UNKNOWN", engine


def map_issue(issue, version, classifications=None):
    domain, scan_type = _domain(issue)
    application = (version or {}).get("application") or {}
    primary_tag = issue.get("primaryTag")
    auditor = primary_tag if primary_tag else issue.get("issueStatus")
    line = issue.get("lineNumber")
    if line == 0:
        line = None
    last_modified = issue.get("lastModifiedDate") or issue.get("foundDate")
    details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
    return {
        "source_finding_id": str(issue.get("id")),
        "instance_id": issue.get("issueInstanceId"),
        "source_url": issue.get("_href"),
        "application_id": application.get("id"),
        "application_name": application.get("name"),
        "ai_application_type": ai_application_type(version),
        "release_id": (version or {}).get("id") or issue.get("projectVersionId"),
        "release_name": (version or {}).get("name"),
        "classifications": list(classifications or []),
        "scan_id": issue.get("lastScanId"),
        "rule_id": issue.get("primaryRuleGuid"),
        "finding_domain": domain,
        "source_scan_type": scan_type,
        "analyzer_name": issue.get("analyzer"),
        "fortify_aviator": None,
        "aviator_remediation_guidance_available": None,
        "impact": issue.get("impact"),
        "probability": issue.get("likelihood"),
        "confidence": issue.get("confidence"),
        "category": issue.get("issueName"),
        "severity": issue.get("friority"),
        "source_status": issue.get("scanStatus"),
        "developer_status": None,
        "auditor_status": auditor,
        "suppressed": issue.get("suppressed"),
        "exploited": None,
        "malware": None,
        "introduced_date": issue.get("foundDate"),
        "closed_date": issue.get("removedDate"),
        "last_modified_date": last_modified,
        "source_revision": issue.get("revision"),
        "sca_provider": None,
        "component_name": None,
        "component_version": None,
        "component_purl": None,
        "advisory_ids": [],
        "summary": details.get("summary"),
        "explanation": details.get("explanation"),
        "recommendation": details.get("recommendation"),
        "file_path": issue.get("fullFileName"),
        "line": line,
        "traces": [],
    }
