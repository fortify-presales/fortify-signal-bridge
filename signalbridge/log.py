"""One JSON object per log line on stderr."""

import json
import logging
import sys
from datetime import datetime, timezone

from signalbridge.redact import redact


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class JsonLog:
    def __init__(self, stream=None):
        self.stream = stream or sys.stderr
        self.context = {}

    def bind(self, **fields):
        self.context.update(fields)

    def emit(self, level, stage, message, **fields):
        event = {"timestamp": _now(), "level": level, "stage": stage, "message": redact(message)}
        event.update(self.context)
        event.update(fields)
        clean = {}
        for key, value in event.items():
            if isinstance(value, str):
                clean[key] = redact(value)
            else:
                clean[key] = value
        self.stream.write(json.dumps(clean, separators=(",", ":"), default=str) + "\n")
        self.stream.flush()

    def info(self, stage, message, **fields):
        self.emit("info", stage, message, **fields)

    def error(self, stage, message, **fields):
        self.emit("error", stage, message, **fields)


def silence_library_logs():
    logging.getLogger("signalbridge").setLevel(logging.WARNING)
