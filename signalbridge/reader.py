"""Read a fortify.collector findings document."""

import json

from signalbridge.validate import SchemaFailure, finding_errors, validate_collector


def load_findings(path):
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("collection_type") != "findings":
        raise SchemaFailure("Input is not a findings collection")
    if document.get("source_platform") not in ("fod", "ssc"):
        raise SchemaFailure("source_platform must be fod or ssc")
    return document


def accept_findings(document, fail_on_invalid_finding):
    """Validate the collection. Optionally drop individual invalid findings."""
    if fail_on_invalid_finding:
        validate_collector(document)
        return document, 0
    rejected = finding_errors(document)
    if not rejected:
        return document, 0
    kept = [finding for index, finding in enumerate(document.get("findings") or []) if index not in rejected]
    cleaned = dict(document)
    cleaned["findings"] = kept
    validate_collector(cleaned)
    return cleaned, len(rejected)
