#!/usr/bin/env python3
"""Validate collector output (a run directory or individual files) against schema/v1.x. Requires: pip install jsonschema"""
import json
import pathlib
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_ROOT = pathlib.Path(__file__).resolve().parent.parent / "schema"


def load_registry():
    resources = []
    for path in SCHEMA_ROOT.glob("v*/*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def schema_for(doc):
    if doc.get("schema_name") == "fortify.collector.manifest":
        name = "manifest"
    else:
        name = doc.get("collection_type")
    return SCHEMA_ROOT / ("v" + str(doc.get("schema_version"))) / (str(name) + ".schema.json")


def main(paths):
    registry = load_registry()
    files = []
    for p in map(pathlib.Path, paths):
        files.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    failed = 0
    for f in files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        schema_path = schema_for(doc)
        if not schema_path.exists():
            print(f"FAIL {f}: no schema {schema_path.relative_to(SCHEMA_ROOT)}")
            failed += 1
            continue
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        if errors:
            failed += 1
            print(f"FAIL {f}")
            for e in errors[:20]:
                print(f"  /{'/'.join(map(str, e.path))}: {e.message[:300]}")
        else:
            print(f"OK   {f} ({schema_path.relative_to(SCHEMA_ROOT)})")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: validate_output.py <run-dir|file> [...]")
        sys.exit(2)
    for s in SCHEMA_ROOT.glob("v*/*.schema.json"):
        Draft202012Validator.check_schema(json.loads(s.read_text(encoding="utf-8")))
    sys.exit(main(sys.argv[1:]))
