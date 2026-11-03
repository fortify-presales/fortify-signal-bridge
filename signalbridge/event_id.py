"""Deterministic fortify.signal event identifiers."""

import hashlib
import json


def canonical_identity(platform, instance_id, release_id, source_finding_id,
                       last_modified_date, source_revision, rule_id, rule_version,
                       schema_version):
    """JSON array in the documented field order. None becomes JSON null."""
    payload = [
        platform,
        instance_id,
        release_id,
        source_finding_id,
        last_modified_date,
        source_revision,
        rule_id,
        rule_version,
        schema_version,
    ]
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def event_id(platform, instance_id, release_id, source_finding_id,
             last_modified_date, source_revision, rule_id, rule_version,
             schema_version):
    digest = hashlib.sha256(canonical_identity(
        platform, instance_id, release_id, source_finding_id, last_modified_date,
        source_revision, rule_id, rule_version, schema_version,
    )).hexdigest()
    return "sha256:" + digest
