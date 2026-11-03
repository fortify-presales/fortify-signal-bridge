"""Optional watermark file. It never decides that a finding was resolved."""

import json
import os
from datetime import datetime, timedelta, timezone


def load_checkpoint(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def derive_window_days(last_window_end, now=None, overlap_minutes=60):
    """Whole UTC days from last_window_end minus overlap, capped at 30."""
    if isinstance(last_window_end, str):
        text = last_window_end.replace("Z", "+00:00")
        last_window_end = datetime.fromisoformat(text)
    if last_window_end.tzinfo is None:
        last_window_end = last_window_end.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    start = last_window_end - timedelta(minutes=int(overlap_minutes))
    days = (now.date() - start.astimezone(timezone.utc).date()).days
    if days < 0:
        days = 0
    if days > 30:
        days = 30
    return days


def write_checkpoint(path, source_instance_id, collection_id, completed_at, window_end):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    document = {
        "schema_version": "1.0",
        "source_instance_id": source_instance_id,
        "last_successful_run": completed_at,
        "last_collection_id": collection_id,
        "last_window_end": window_end,
    }
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return document
