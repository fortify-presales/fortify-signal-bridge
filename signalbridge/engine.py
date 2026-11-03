"""Turn a findings collection into fortify.signal events."""

import hashlib
import json
from datetime import datetime, timezone

from signalbridge.mapper import build_signal
from signalbridge.reader import accept_findings
from signalbridge.rules import matches, referenced_classifiers, rules_for_platform
from signalbridge.validate import SchemaFailure, validate_signal


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rule_bundle_sha256(rules):
    digest = hashlib.sha256()
    for rule in sorted(rules, key=lambda item: item["path"]):
        with open(rule["path"], "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()


def classifier_bundle_sha256(document):
    rows = (document.get("classification") or {}).get("classifiers") or []
    payload = json.dumps(rows, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def known_classifier_ids(classifiers_dir, platform):
    import glob
    import os
    # classifiers/<platform>/*.yaml — fod, ssc, and any later product directory.
    root = os.path.join(classifiers_dir, platform)
    ids = set()
    for path in glob.glob(os.path.join(root, "*.yaml")) + glob.glob(os.path.join(root, "*.yml")):
        name = os.path.splitext(os.path.basename(path))[0]
        ids.add(name)
        try:
            import yaml
            with open(path, encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
            if isinstance(doc, dict) and isinstance(doc.get("id"), str):
                ids.add(doc["id"])
        except Exception:
            continue
    return ids


def process_collection(document, rules, detail_level, fail_on_invalid_finding, fail_on_invalid_signal,
                       observed_at=None, classifiers_dir=None):
    cleaned, rejected = accept_findings(document, fail_on_invalid_finding)
    platform = cleaned.get("source_platform")
    active = rules_for_platform(rules, platform)
    if classifiers_dir:
        known = known_classifier_ids(classifiers_dir, platform)
        missing = [item for item in referenced_classifiers(rules, platform) if item not in known]
        if missing:
            raise SchemaFailure(f"Rules reference unknown classifiers {missing}")
    stamp = observed_at or utc_now()
    signals = []
    evaluated = 0
    for finding in cleaned.get("findings") or []:
        for rule in active:
            evaluated += 1
            if not matches(rule, finding):
                continue
            signal = build_signal(cleaned, finding, rule, stamp, detail_level)
            if fail_on_invalid_signal:
                validate_signal(signal)
            signals.append(signal)
    counts = {
        "findings_collected": len(document.get("findings") or []),
        "findings_valid": len(cleaned.get("findings") or []),
        "findings_rejected": rejected,
        "rules_evaluated": evaluated,
        "signals_emitted": len(signals),
        "signals_delivered": 0,
        "signals_failed": 0,
    }
    return cleaned, signals, counts
