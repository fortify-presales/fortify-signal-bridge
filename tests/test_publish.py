import json
from pathlib import Path

from signalbridge.engine import process_collection
from signalbridge.publish import build_manifest, publish_run, stage_directory
from signalbridge.rules import load_rules
from signalbridge.sinks.json_sink import JsonSink
from signalbridge.sinks.stdout_sink import StdoutSink
from signalbridge.validate import validate_manifest

ROOT = Path(__file__).resolve().parents[1]


def _signals():
    document = json.loads((ROOT / "tests" / "fixtures" / "fod-rules.json").read_text())
    rules = load_rules(str(ROOT / "rules"))
    cleaned, signals, counts = process_collection(
        document, rules, "summary", False, True, observed_at="2026-11-02T15:30:00Z",
        classifiers_dir=str(ROOT / "classifiers"),
    )
    return cleaned, signals, counts, rules


def test_json_and_stdout_match_and_hide_secrets(tmp_path, capsys):
    _cleaned, signals, _counts, _rules = _signals()
    path = tmp_path / "signals.ndjson"
    sink = JsonSink(str(path))
    sink.open({})
    sink.send(signals)
    sink.flush()
    sink.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(signals)
    assert json.loads(lines[0])["event_id"] == signals[0]["event_id"]
    out = StdoutSink()
    out.open({})
    out.send(signals)
    out.flush()
    out.close()
    captured = capsys.readouterr().out.splitlines()
    assert captured == lines
    assert "super-secret-token" not in path.read_text(encoding="utf-8")
    assert "super-secret-token" not in "\n".join(captured)


def test_manifest_counts_and_atomic_publish(tmp_path):
    document, signals, counts, rules = _signals()
    counts["signals_delivered"] = len(signals)
    counts["signals_failed"] = 0
    staging = stage_directory(str(tmp_path), document["collection_id"], document["source_platform"])
    artifact = Path(staging) / "signals.ndjson"
    artifact.write_text("\n".join("{}".format("")) , encoding="utf-8")
    from signalbridge.publish import sha256_file, write_json
    artifact.write_text("".join(json.dumps(item) + "\n" for item in signals), encoding="utf-8")
    manifest = build_manifest(
        document, counts, [{"id": "json", "required": True, "status": "complete", "delivered": len(signals), "failed": 0}],
        "2026-11-02T15:25:00Z", "complete", "incremental", rules, sha256_file(str(artifact)), len(signals),
    )
    validate_manifest(manifest)
    assert manifest["counts"]["signals_emitted"] == len(signals)
    assert manifest["coverage"]["authoritative_for_lifecycle"] is False
    assert manifest["release"]["processor_version"] == "0.1.0"
    assert manifest["release"]["rule_bundle_sha256"]
    write_json(str(Path(staging) / "manifest.json"), manifest)
    destination = publish_run(str(tmp_path), document["collection_id"], str(artifact), manifest, True, "fod")
    assert destination.endswith("/fod/complete/" + document["collection_id"]) or destination.endswith("\\fod\\complete\\" + document["collection_id"])
    assert (Path(destination) / "manifest.json").is_file()
    assert not (tmp_path / "signals" / "fod" / ".staging" / document["collection_id"]).exists()


def test_same_collection_id_publishes_for_each_platform(tmp_path):
    document, signals, counts, rules = _signals()
    counts["signals_delivered"] = len(signals)
    counts["signals_failed"] = 0
    from signalbridge.publish import sha256_file, write_json
    destinations = []
    for platform in ("fod", "ssc"):
        staged = dict(document, source_platform=platform)
        staging = stage_directory(str(tmp_path), document["collection_id"], platform)
        artifact = Path(staging) / "signals.ndjson"
        artifact.write_text("{}\n", encoding="utf-8")
        manifest = build_manifest(
            staged, counts, [{"id": "json", "required": True, "status": "complete", "delivered": 1, "failed": 0}],
            "2026-11-02T15:25:00Z", "complete", "incremental", rules, sha256_file(str(artifact)), 1,
        )
        write_json(str(Path(staging) / "manifest.json"), manifest)
        destinations.append(publish_run(str(tmp_path), document["collection_id"], str(artifact), manifest, True, platform))
    assert Path(destinations[0]).is_dir() and Path(destinations[1]).is_dir()
    assert Path(destinations[0]) != Path(destinations[1])
