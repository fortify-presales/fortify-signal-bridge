import io
import json

from signalbridge.log import JsonLog
from signalbridge.redact import clear_secrets, redact, register_secret
from signalbridge.retryutil import delay_seconds, http_disposition
from signalbridge.sinks import SinkError
from signalbridge.sinks.crowdstrike import CrowdStrikeHecSink, hec_body


def setup_function():
    clear_secrets()


def _signal(index):
    return {"event_id": f"sha256:{index:064x}", "event_type": "fortify.signal.observed"}


def test_http_and_delay_classification():
    assert http_disposition(200) == "ok"
    assert http_disposition(429) == "retry"
    assert http_disposition(500) == "retry"
    assert http_disposition(408) == "retry"
    assert http_disposition(400) == "permanent"
    assert http_disposition(401) == "permanent"
    assert http_disposition(403) == "permanent"
    assert delay_seconds(1, lambda: 0) == 1
    assert delay_seconds(2, lambda: 0) == 2
    assert delay_seconds(6, lambda: 0) == 30


def test_batches_and_retries():
    calls = []

    def transport(body):
        calls.append(json.loads(body.decode()))
        if len(calls) == 1:
            return 429
        if len(calls) == 2:
            return 500
        return 200

    slept = []
    sink = CrowdStrikeHecSink(
        "https://hec.example/services/collector", "token-value-should-not-leak",
        batch_size=2, max_retries=4, transport=transport, sleep=slept.append, rng=lambda: 0,
    )
    signals = [_signal(i) for i in range(3)]
    sink.open({})
    sink.send(signals)
    sink.flush()
    sink.close()
    assert sink.delivered == 3
    assert sink.failed == 0
    assert len(calls) == 4  # first batch retried twice, then the remainder
    assert len(calls[0]) == 2
    assert calls[0][0]["event"]["event_id"] == signals[0]["event_id"]
    assert slept == [1, 2]


def test_permanent_failure_does_not_retry():
    calls = []

    def transport(_body):
        calls.append(1)
        return 400

    sink = CrowdStrikeHecSink("https://hec.example", "token-value-should-not-leak", transport=transport, sleep=lambda _delay: None)
    sink.open({})
    try:
        sink.send([_signal(1)])
        sink.flush()
        raised = False
    except SinkError as exc:
        raised = exc.category == "permanent"
    assert raised
    assert calls == [1]
    assert sink.failed == 1


def test_timeout_is_temporary():
    def transport(_body):
        raise TimeoutError("timed out")

    sink = CrowdStrikeHecSink(
        "https://hec.example", "token-value-should-not-leak", max_retries=2,
        transport=transport, sleep=lambda _delay: None, rng=lambda: 0,
    )
    sink.open({})
    try:
        sink.send([_signal(1)])
        sink.flush()
    except SinkError as exc:
        assert exc.category == "temporary"
    else:
        raise AssertionError("expected temporary failure")


def test_token_is_redacted_from_logs():
    token = "token-value-should-not-leak"
    register_secret(token)
    stream = io.StringIO()
    log = JsonLog(stream)
    log.error("deliver", f"failed with Authorization Bearer {token}", url="https://user:token-value-should-not-leak@hec.example")
    text = stream.getvalue()
    assert token not in text
    assert "***" in text
    assert redact(hec_body([_signal(1)]).decode())
