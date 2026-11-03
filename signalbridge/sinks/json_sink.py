"""Write one fortify.signal JSON object per line."""

import json
import os

from signalbridge.sinks import Sink


class JsonSink(Sink):
    sink_id = "json"

    def __init__(self, path):
        self.path = path
        self._handle = None
        self._batch = []

    def open(self, run_context):
        super().open(run_context)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._handle = open(self.path, "w", encoding="utf-8")

    def send(self, batch):
        self._batch.extend(batch)

    def flush(self):
        for signal in self._batch:
            self._handle.write(json.dumps(signal, separators=(",", ":"), ensure_ascii=False) + "\n")
            self.delivered += 1
        self._batch = []
        self._handle.flush()

    def close(self):
        try:
            if self.status == "complete" and self._batch:
                self.flush()
        finally:
            if self._handle:
                self._handle.close()
                self._handle = None
