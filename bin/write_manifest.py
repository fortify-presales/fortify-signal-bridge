#!/usr/bin/env python3
"""Write the run manifest that indexes every collection file produced by bin/collect.sh."""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe(run_dir, name):
    path = os.path.join(run_dir, name)
    entry = {"file": name, "bytes": os.path.getsize(path), "sha256": sha256_file(path),
             "collection_type": None, "schema_version": None, "record_count": None}
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        entry["collection_type"] = doc.get("collection_type")
        entry["schema_version"] = doc.get("schema_version")
        entry["record_count"] = (doc.get("coverage") or {}).get("fetched_count")
    except (ValueError, OSError):
        entry["collection_type"] = "invalid"
    return entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--status-file", required=True, help="TSV: collector, exit code, started, completed, files")
    parser.add_argument("--settings", required=True, help="JSON object of non-secret run settings")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--fcli-version")
    parser.add_argument("--collector-version")
    args = parser.parse_args()

    collectors = []
    with open(args.status_file, encoding="utf-8") as handle:
        for line in handle:
            name, code, started, completed, files = (line.rstrip("\n").split("\t") + [""] * 5)[:5]
            outputs = [describe(args.run_dir, f) for f in files.split(",")
                       if f and os.path.exists(os.path.join(args.run_dir, f))]
            collectors.append({
                "collector": name,
                "status": "succeeded" if code == "0" else "failed",
                "exit_code": int(code),
                "started_at": started,
                "completed_at": completed,
                "outputs": outputs,
            })

    manifest = {
        "schema_name": "fortify.collector.manifest",
        "schema_version": "1.0",
        "run_id": args.run_id,
        "source_platform": "fod",
        "started_at": args.started_at,
        "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "succeeded" if all(c["status"] == "succeeded" for c in collectors) else "failed",
        "fcli_version": args.fcli_version or None,
        "collector_version": args.collector_version or None,
        "settings": json.loads(args.settings),
        "collectors": collectors,
    }
    with open(os.path.join(args.run_dir, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
