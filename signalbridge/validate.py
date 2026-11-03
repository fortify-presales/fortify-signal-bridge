"""JSON Schema checks for collector documents, signals, and run manifests."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from signalbridge.redact import redact

ROOT = Path(__file__).resolve().parent.parent
COLLECTOR_SCHEMA = ROOT / "schema"
SIGNAL_SCHEMA = COLLECTOR_SCHEMA / "signal" / "v1.0" / "fortify-signal.schema.json"
MANIFEST_SCHEMA = COLLECTOR_SCHEMA / "signal" / "v1.0" / "run-manifest.schema.json"


class SchemaFailure(Exception):
    def __init__(self, message):
        super().__init__(redact(message))


def collector_registry():
    resources = []
    for path in COLLECTOR_SCHEMA.glob("v*/*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _validator(schema, registry=None):
    kwargs = {"format_checker": FormatChecker()}
    if registry is not None:
        kwargs["registry"] = registry
    return Draft202012Validator(schema, **kwargs)


def schema_path_for(document):
    version = str(document.get("schema_version"))
    if document.get("schema_name") == "fortify.collector.manifest":
        name = "manifest"
    else:
        name = document.get("collection_type")
    return COLLECTOR_SCHEMA / ("v" + version) / (str(name) + ".schema.json")


def validate_collector(document):
    path = schema_path_for(document)
    if not path.is_file():
        raise SchemaFailure(f"No collector schema for {document.get('schema_name')} {document.get('schema_version')}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    errors = sorted(_validator(schema, collector_registry()).iter_errors(document), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.path)
        raise SchemaFailure(f"{location}: {first.message}")


def finding_errors(document):
    """Return indexes of findings that fail the collection schema, or raise if the envelope is invalid."""
    path = schema_path_for(document)
    schema = json.loads(path.read_text(encoding="utf-8"))
    validator = _validator(schema, collector_registry())
    errors = list(validator.iter_errors(document))
    bad = set()
    for error in errors:
        parts = list(error.absolute_path)
        if parts and parts[0] == "findings" and len(parts) >= 2 and isinstance(parts[1], int):
            bad.add(parts[1])
            continue
        location = "/".join(str(part) for part in parts)
        raise SchemaFailure(f"{location}: {error.message}")
    return bad


def validate_signal(signal):
    schema = json.loads(SIGNAL_SCHEMA.read_text(encoding="utf-8"))
    try:
        _validator(schema).validate(signal)
    except ValidationError as exc:
        location = "/".join(str(part) for part in exc.path)
        raise SchemaFailure(f"signal {location}: {exc.message}") from exc


def validate_manifest(manifest):
    schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
    try:
        _validator(schema).validate(manifest)
    except ValidationError as exc:
        location = "/".join(str(part) for part in exc.path)
        raise SchemaFailure(f"manifest {location}: {exc.message}") from exc
