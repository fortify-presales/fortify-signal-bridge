import json
from pathlib import Path

from signalbridge.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_process_sample_writes_empty_ndjson(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_INSTANCE_ID", "fod-ams-prod")
    output = tmp_path / "signals.ndjson"
    code = main(["process", "--input", str(ROOT / "examples" / "run" / "findings.json"), "--output", str(output)])
    assert code == 0
    assert output.read_text(encoding="utf-8") == ""


def test_run_input_publishes_and_checkpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_INSTANCE_ID", "fod-ams-prod")
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("SINKS", "json")
    monkeypatch.setenv("CHECKPOINT_ENABLED", "true")
    monkeypatch.setenv("CHECKPOINT_PATH", str(tmp_path / "checkpoint.json"))
    monkeypatch.setenv("RUN_MODE", "incremental")
    code = main(["run", "--input", str(ROOT / "tests" / "fixtures" / "fod-rules.json"), "--sink", "json"])
    assert code == 0
    published = list((tmp_path / "out" / "signals" / "fod" / "complete").iterdir())
    assert len(published) == 1
    manifest = json.loads((published[0] / "manifest.json").read_text())
    assert manifest["status"] == "complete"
    assert manifest["counts"]["signals_emitted"] == manifest["counts"]["signals_delivered"]
    assert manifest["coverage"]["authoritative_for_lifecycle"] is False
    lines = (published[0] / "signals.ndjson").read_text().splitlines()
    assert len(lines) == manifest["counts"]["signals_emitted"]
    assert json.loads((tmp_path / "checkpoint.json").read_text())["source_instance_id"] == "fod-ams-prod"
    (tmp_path / "checkpoint.json").unlink()
    import shutil
    shutil.rmtree(tmp_path / "out" / "signals")
    code = main(["run", "--input", str(ROOT / "tests" / "fixtures" / "fod-rules.json"), "--sink", "json"])
    assert code == 0


def test_missing_instance_is_configuration_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_INSTANCE_ID", raising=False)
    code = main(["process", "--input", str(ROOT / "examples" / "run" / "findings.json"), "--output", str(tmp_path / "out.ndjson")])
    assert code == 2
