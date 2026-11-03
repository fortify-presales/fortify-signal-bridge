import json
from pathlib import Path

from signalbridge.engine import process_collection
from signalbridge.mapper import signal_severity
from signalbridge.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(str(ROOT / "rules"))


def test_severity_names():
    assert signal_severity("Critical") == "critical"
    assert signal_severity("Best_Practice") == "best_practice"
    assert signal_severity(None) is None


def test_detail_levels_add_fields_without_dropping_identity():
    document = json.loads((ROOT / "tests" / "fixtures" / "fod-rules.json").read_text())
    summary, _counts = _one(document, "summary")
    standard, _ = _one(document, "standard")
    full, _ = _one(document, "full")
    assert summary["event_id"] == standard["event_id"] == full["event_id"]
    assert "file_path" not in summary["finding"]
    assert "summary" not in summary["finding"]
    assert standard["finding"]["file_path"]
    assert "explanation" not in standard["finding"]
    assert full["finding"]["explanation"]
    assert full["finding"]["traces"]
    assert summary["source"]["deep_link"]
    assert summary["provenance"]["processor_version"] == "0.1.0"


def _one(document, level):
    _cleaned, signals, counts = process_collection(
        document, RULES, level, False, True, observed_at="2026-11-02T15:30:00Z",
        classifiers_dir=str(ROOT / "classifiers"),
    )
    return signals[0], counts
