"""NDJSON on standard output for local runs and container pipelines."""

import json
import sys

from signalbridge.sinks import Sink


class StdoutSink(Sink):
    sink_id = "stdout"

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self._batch = []

    def send(self, batch):
        self._batch.extend(batch)

    def flush(self):
        for signal in self._batch:
            self.stream.write(json.dumps(signal, separators=(",", ":"), ensure_ascii=False) + "\n")
            self.delivered += 1
        self._batch = []
        self.stream.flush()

    def close(self):
        if self.status == "complete" and self._batch:
            self.flush()
