"""Stage a signal run and publish it with a rename."""

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

from signalbridge import PROCESSOR_VERSION
from signalbridge.validate import validate_manifest


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(document, counts, sinks, started_at, status, run_mode, rules, signals_sha, signal_count):
    coverage = document.get("coverage") or {}
    producer = document.get("producer") or {}
    from signalbridge.engine import classifier_bundle_sha256, rule_bundle_sha256
    return {
        "schema_name": "fortify.signalbridge.run",
        "schema_version": "1.0",
        "collection_id": document.get("collection_id"),
        "run_mode": run_mode,
        "source_platform": document.get("source_platform"),
        "source_instance_id": document.get("source_instance_id"),
        "started_at": started_at,
        "completed_at": utc_now(),
        "status": status,
        "coverage": {
            "retrieval_complete": bool(coverage.get("retrieval_complete")),
            "snapshot_consistent": bool(coverage.get("snapshot_consistent")),
            "authoritative_for_lifecycle": bool(coverage.get("authoritative_for_lifecycle")),
        },
        "counts": {
            "findings_collected": counts["findings_collected"],
            "findings_valid": counts["findings_valid"],
            "findings_rejected": counts["findings_rejected"],
            "signals_emitted": counts["signals_emitted"],
            "signals_delivered": counts["signals_delivered"],
            "signals_failed": counts["signals_failed"],
        },
        "documents": [{
            "name": "signals.ndjson",
            "record_count": signal_count,
            "sha256": signals_sha,
        }],
        "sinks": sinks,
        "release": {
            "processor_version": PROCESSOR_VERSION,
            "collector_version": producer.get("collector_version"),
            "fcli_version": producer.get("version"),
            "action_sha256": producer.get("collector_sha256"),
            "classifier_bundle_sha256": classifier_bundle_sha256(document),
            "rule_bundle_sha256": rule_bundle_sha256(rules),
            "signal_schema_version": "1.0",
            "collection_schema_version": str(document.get("schema_version")),
        },
    }


def signal_root(output_root, platform):
    """signals/<platform>/ so a FoD run and an SSC run do not share a directory."""
    if platform not in ("fod", "ssc"):
        raise OSError(f"source_platform must be fod or ssc, got {platform!r}")
    return os.path.join(output_root, "signals", platform)


def publish_run(output_root, collection_id, signals_path, manifest, success, platform):
    """Move the staged directory to complete/ or failed/. The manifest is already the last file."""
    root = signal_root(output_root, platform)
    staging = os.path.join(root, ".staging", collection_id)
    if not os.path.isdir(staging):
        raise OSError(f"Missing staging directory {staging}")
    validate_manifest(manifest)
    destination_root = os.path.join(root, "complete" if success else "failed")
    os.makedirs(destination_root, exist_ok=True)
    destination = os.path.join(destination_root, collection_id)
    if os.path.exists(destination):
        raise OSError(f"Signal run already published: {destination}")
    os.rename(staging, destination)
    return destination


def stage_directory(output_root, collection_id, platform):
    staging = os.path.join(signal_root(output_root, platform), ".staging", collection_id)
    if os.path.isdir(staging):
        shutil.rmtree(staging)
    os.makedirs(staging)
    return staging


def write_json(path, document):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
