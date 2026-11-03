"""CrowdStrike HEC adapter. The signal object is wrapped only here."""

import json
import urllib.error
import urllib.request

from signalbridge.retryutil import delay_seconds, http_disposition
from signalbridge.sinks import Sink, SinkError


def hec_body(signals):
    return json.dumps([{"event": signal} for signal in signals], separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class CrowdStrikeHecSink(Sink):
    sink_id = "crowdstrike"

    def __init__(self, url, token, timeout=30, max_retries=4, batch_size=100,
                 transport=None, sleep=None, rng=None):
        self.url = url
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self.batch_size = batch_size
        self.transport = transport
        self.sleep = sleep
        self.rng = rng
        self._pending = []
        self.attempts = 0

    def send(self, batch):
        self._pending.extend(batch)
        while len(self._pending) >= self.batch_size:
            chunk = self._pending[:self.batch_size]
            self._pending = self._pending[self.batch_size:]
            self._deliver(chunk)

    def flush(self):
        if self._pending:
            chunk = self._pending
            self._pending = []
            self._deliver(chunk)

    def close(self):
        if self.status == "complete":
            self.flush()

    def _deliver(self, chunk):
        body = hec_body(chunk)
        attempt = 0
        while True:
            attempt += 1
            self.attempts = attempt
            try:
                status = self._post(body)
            except SinkError:
                raise
            except Exception as exc:
                status = None
                error = exc
            else:
                error = None
            if status is not None and http_disposition(status) == "ok":
                self.delivered += len(chunk)
                return
            disposition = "retry" if status is None else http_disposition(status)
            if disposition != "retry" or attempt >= self.max_retries:
                self.failed += len(chunk)
                self.status = "failed"
                category = "temporary" if disposition == "retry" else "permanent"
                self.error_category = category
                detail = f"HTTP {status}" if status is not None else type(error).__name__
                raise SinkError(f"CrowdStrike delivery failed ({detail})", category)
            if self.sleep:
                self.sleep(delay_seconds(attempt, self.rng))

    def _post(self, body):
        if self.transport:
            return self.transport(body)
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
