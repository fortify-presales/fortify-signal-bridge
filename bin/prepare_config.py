#!/usr/bin/env python3
"""Validate classifier files and scope settings; emit NUL-separated KEY=VALUE pairs for bin/collect.sh."""
import glob
import hashlib
import json
import os
import re
import sys

import yaml

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SCAN_TYPES = {"Static": "Static", "Dynamic": "Dynamic", "Mobile": "Mobile", "OpenSource": "Open Source",
              "Network": "Network", "Monitoring": "Monitoring"}
ALLOWED_KEYS = {"id", "version", "title", "description", "scan_types", "issue_query", "application_query"}


def fail(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(2)


def check_query(name, value, source):
    if not isinstance(value, str) or not value.strip():
        fail(f"{source}: {name} must be a non-empty string")
    query = " ".join(value.split())
    # Queries are passed to fcli inside a double-quoted command token.
    if '"' in query or "\\" in query:
        fail(f"{source}: {name} must not contain double quotes or backslashes; use single-quoted SpEL strings")
    if len(query) > 4000:
        fail(f"{source}: {name} is too long")
    return query


def load_classifiers(dirs):
    found = {}
    for directory in dirs:
        for path in sorted(glob.glob(os.path.join(directory, "*.yaml")) + glob.glob(os.path.join(directory, "*.yml"))):
            with open(path, "rb") as handle:
                raw = handle.read()
            try:
                doc = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                fail(f"{path}: invalid YAML: {exc}")
            if not isinstance(doc, dict):
                fail(f"{path}: classifier must be a YAML mapping")
            unknown = set(doc) - ALLOWED_KEYS
            if unknown:
                fail(f"{path}: unknown keys {sorted(unknown)}")
            cid = doc.get("id")
            if not isinstance(cid, str) or not ID_RE.match(cid):
                fail(f"{path}: id must match {ID_RE.pattern}")
            version = doc.get("version")
            if not isinstance(version, int) or version < 1:
                fail(f"{path}: version must be a positive integer")
            scan_types = doc.get("scan_types") or []
            if not isinstance(scan_types, list) or any(s not in SCAN_TYPES for s in scan_types):
                fail(f"{path}: scan_types must be a list of {sorted(SCAN_TYPES)}")
            issue_query = check_query("issue_query", doc.get("issue_query"), path)
            app_query = doc.get("application_query")
            if app_query is not None:
                app_query = check_query("application_query", app_query, path)
            if scan_types:
                native = ",".join("'" + SCAN_TYPES[s] + "'" for s in scan_types)
                issue_query = "{" + native + "}.contains(scantype) && (" + issue_query + ")"
            if cid in found:
                print(f"Classifier {cid} from {path} overrides {found[cid]['path']}", file=sys.stderr)
            found[cid] = {
                "id": cid, "version": version, "title": doc.get("title") or cid, "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(), "issue_query": issue_query,
                "application_query": app_query,
            }
    return found


def attributes_query(spec):
    """Convert 'Name=V1|V2;Other=V3' into a SpEL query over FoD application records."""
    clauses = []
    for part in filter(None, (p.strip() for p in spec.split(";"))):
        if "=" not in part:
            fail(f"APPLICATION_ATTRIBUTES entry '{part}' must be Name=Value[|Value...]")
        name, values = (x.strip() for x in part.split("=", 1))
        items = [v.strip() for v in values.split("|") if v.strip()]
        if not name or not items or any(c in name + values for c in "'\"\\"):
            fail(f"APPLICATION_ATTRIBUTES entry '{part}' is invalid (no quotes or backslashes allowed)")
        literal = ",".join("'" + v + "'" for v in items)
        clauses.append(f"attributes.?[name == '{name}' && {{{literal}}}.contains(value)].size() > 0")
    return " && ".join(clauses)


def main():
    builtin_dir = os.path.join(os.environ.get("COLLECTOR_HOME", "/opt/collector"), "classifiers")
    custom_dir = os.environ.get("CLASSIFIERS_DIR", "")
    selection = os.environ.get("CLASSIFIERS", "all").strip()
    mode = os.environ.get("CLASSIFIER_MODE", "tag").strip()
    if mode not in ("tag", "filter"):
        fail("CLASSIFIER_MODE must be 'tag' or 'filter'")
    dirs = [builtin_dir] + ([custom_dir] if custom_dir else [])
    if custom_dir and not os.path.isdir(custom_dir):
        fail(f"CLASSIFIERS_DIR {custom_dir} is not a directory")

    available = load_classifiers(dirs)
    if selection in ("", "none"):
        enabled = []
    elif selection == "all":
        enabled = sorted(available)
    else:
        enabled = [s.strip() for s in selection.split(",") if s.strip()]
        missing = [s for s in enabled if s not in available]
        if missing:
            fail(f"Unknown classifiers {missing}; available: {sorted(available)}")
    if mode == "filter" and not enabled:
        fail("CLASSIFIER_MODE=filter requires at least one enabled classifier")

    out = {"COLLECTOR_CLASSIFIER_MODE": mode}
    summary = []
    for index, cid in enumerate(enabled):
        c = available[cid]
        prefix = f"COLLECTOR_CLASSIFIER_{index}_"
        out[prefix + "ID"] = c["id"]
        out[prefix + "VERSION"] = str(c["version"])
        out[prefix + "TITLE"] = c["title"]
        out[prefix + "SHA256"] = c["sha256"]
        out[prefix + "ISSUE_QUERY"] = c["issue_query"]
        if c["application_query"]:
            out[prefix + "APPLICATION_QUERY"] = c["application_query"]
        summary.append({"id": c["id"], "version": c["version"], "sha256": c["sha256"]})
    out["COLLECTOR_CLASSIFIERS_JSON"] = json.dumps(summary, separators=(",", ":"))

    app_parts = []
    if os.environ.get("APPLICATION_QUERY", "").strip():
        app_parts.append("(" + " ".join(os.environ["APPLICATION_QUERY"].split()) + ")")
    if os.environ.get("APPLICATION_ATTRIBUTES", "").strip():
        app_parts.append("(" + attributes_query(os.environ["APPLICATION_ATTRIBUTES"]) + ")")
    out["COLLECTOR_APPLICATION_QUERY"] = " && ".join(app_parts)
    out["COLLECTOR_RELEASE_QUERY"] = " ".join(os.environ.get("RELEASE_QUERY", "").split())

    for key, value in out.items():
        if "\0" in value or "\n" in value:
            fail(f"{key} contains invalid characters")
        sys.stdout.write(f"{key}={value}\0")
    print(f"Classifiers enabled ({mode}): {', '.join(enabled) or 'none'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
