import json
from pathlib import Path

import pytest

from signalbridge.engine import process_collection
from signalbridge.rules import load_rules, matches
from signalbridge.validate import validate_collector, validate_signal

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(str(ROOT / "rules"))
OBSERVED = "2026-11-02T15:30:00Z"


def _load(name):
    return json.loads((ROOT / "tests" / "fixtures" / name).read_text())


def _signals(document):
    _cleaned, signals, counts = process_collection(
        document, RULES, "summary", False, True, observed_at=OBSERVED,
        classifiers_dir=str(ROOT / "classifiers"),
    )
    return signals, counts


def test_sample_collection_emits_nothing():
    document = json.loads((ROOT / "examples" / "run" / "findings.json").read_text())
    validate_collector(document)
    signals, counts = _signals(document)
    assert signals == []
    assert counts["findings_valid"] == 1
    assert counts["signals_emitted"] == 0


def test_each_fod_rule_and_a_non_match():
    signals, _counts = _signals(_load("fod-rules.json"))
    kinds = sorted(item["signal"]["type"] for item in signals)
    assert kinds == [
        "agentic-or-llm-application-risk",
        "aviator-confirmed-dast",
        "aviator-confirmed-sast",
        "known-exploited-open-source",
        "open-source-malware",
    ]
    assert all(item["event_type"] == "fortify.signal.observed" for item in signals)
    for signal in signals:
        validate_signal(signal)


def test_rerun_keeps_event_ids():
    document = _load("fod-rules.json")
    first, _ = _signals(document)
    second, _ = _signals(document)
    assert [item["event_id"] for item in first] == [item["event_id"] for item in second]
    assert len(set(item["event_id"] for item in first)) == len(first)


def test_null_is_not_false():
    rule = {
        "id": "null-check",
        "version": "1",
        "enabled": True,
        "platforms": ["fod"],
        "conditions": [{"kind": "equals", "field": "finding.exploited", "equals": False}],
        "emit": {"type": "x", "confidence": "low", "title": "x"},
    }
    assert matches(rule, {"exploited": False, "classifications": []}) is True
    assert matches(rule, {"exploited": None, "classifications": []}) is False
    assert matches(rule, {"classifications": []}) is False
    assert matches(rule, {"exploited": True, "classifications": []}) is False


def test_paired_rules_use_the_classifier_id_and_directory():
    for rule in RULES:
        folder = Path(rule["path"]).parent.name
        classifications = [item["id"] for item in rule["conditions"] if item["kind"] == "classification"]
        if folder == "shared":
            assert len(rule["platforms"]) > 1
            assert classifications == []
            continue
        assert rule["platforms"] == [folder]
        assert classifications == [rule["id"]]
        assert Path(rule["path"]).name == rule["id"] + ".yaml"
        assert (ROOT / "classifiers" / folder / Path(rule["path"]).name).is_file()


def test_ssc_rules_do_not_fire_on_fod():
    signals, _ = _signals(_load("fod-rules.json"))
    assert not any(item["signal"]["type"].startswith("ssc-") for item in signals)


def test_ssc_fixture_schema_and_rules():
    document = _load("ssc-findings.json")
    validate_collector(document)
    signals, _counts = _signals(document)
    kinds = sorted(item["signal"]["type"] for item in signals)
    assert "ssc-reintroduced-critical" in kinds
    assert "ssc-open-source-high" in kinds
    assert "ssc-correlated-high" in kinds
    assert "agentic-or-llm-application-risk" in kinds
    assert not any(item["signal"]["type"].startswith("aviator-") for item in signals)
    reintroduced = next(item for item in signals if item["signal"]["type"] == "ssc-reintroduced-critical")
    assert reintroduced["provenance"]["signal_rule_version"] == "1"
    assert reintroduced["evidence"]["classifications"][0]["id"] == "ssc-reintroduced"
    assert reintroduced["evidence"]["classifications"][0]["matched"] is True
    for signal in signals:
        validate_signal(signal)


def test_unknown_rule_field_is_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "id: bad\nversion: '1'\nplatforms: [fod]\nwhen:\n  all:\n"
        "    - field: finding.not_a_field\n      equals: true\n"
        "emit:\n  type: t\n  confidence: low\n  title: t\n",
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        load_rules(str(tmp_path))
