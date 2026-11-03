from datetime import datetime, timezone
from pathlib import Path

from signalbridge.checkpoint import derive_window_days, load_checkpoint, write_checkpoint
from signalbridge.ssc_mapping import map_issue


def test_checkpoint_window_and_missing_file(tmp_path):
    assert load_checkpoint(str(tmp_path / "missing.json")) is None
    last = datetime(2026, 11, 1, tzinfo=timezone.utc)
    now = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
    assert derive_window_days(last, now=now, overlap_minutes=60) == 2
    path = tmp_path / "checkpoint.json"
    write_checkpoint(str(path), "customer-fod-prod", "col-1", "2026-11-02T15:30:00Z", "2026-11-02T15:29:00Z")
    loaded = load_checkpoint(str(path))
    assert loaded["last_collection_id"] == "col-1"
    assert not path.with_suffix(".json.tmp").exists()
    assert "resolved" not in Path(str(path)).read_text()


def test_ssc_issue_mapping_uses_friority_and_sast_domain():
    issue = {
        "id": 2499,
        "issueInstanceId": "ABC",
        "issueName": "Cross-Site Scripting: Persistent",
        "friority": "Critical",
        "severity": 4.0,
        "engineType": "SCA",
        "fullFileName": "src/Api.java",
        "lineNumber": 85,
        "primaryRuleGuid": "RULE",
        "suppressed": False,
        "hidden": False,
        "removed": False,
        "scanStatus": "REINTRODUCED",
        "foundDate": "2022-11-11T17:48:24-05:00",
        "removedDate": None,
        "revision": 3,
        "primaryTag": "Exploitable",
        "issueStatus": "Reviewed",
        "lastScanId": 40001,
        "analyzer": "Data Flow",
        "impact": 5.0,
        "likelihood": 4.0,
        "confidence": 5.0,
        "hasCorrelatedIssues": False,
        "_href": "https://ssc.example/api/v1/issues/2499",
    }
    version = {
        "id": 20001,
        "name": "main",
        "application": {"id": 10, "name": "Payments"},
        "attrValuesByName": {"AI Application Type": "LLM Application"},
    }
    finding = map_issue(issue, version, ["ssc-reintroduced"])
    assert finding["severity"] == "Critical"
    assert finding["finding_domain"] == "SAST"
    assert finding["source_scan_type"] == "Static"
    assert finding["release_id"] == 20001
    assert finding["source_finding_id"] == "2499"
    assert finding["auditor_status"] == "Exploitable"
    assert finding["source_revision"] == 3
    assert finding["ai_application_type"] == "LLM Application"
    assert finding["fortify_aviator"] is None
    assert finding["exploited"] is None
    assert finding["closed_date"] is None
    debricked = map_issue({"id": 1, "engineType": "DEBRICKED", "friority": "High", "revision": 1}, version)
    assert debricked["finding_domain"] == "SCA"
    assert debricked["source_scan_type"] == "OpenSource"
