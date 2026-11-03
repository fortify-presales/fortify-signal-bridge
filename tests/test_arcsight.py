import socket
import threading

from signalbridge.redact import clear_secrets, redact, register_secret
from signalbridge.sinks import SinkError
from signalbridge.sinks.arcsight import (
    ArcSightCefSink,
    escape_extension,
    escape_header,
    format_cef,
    format_syslog,
)


def _signal():
    return {
        "schema_name": "fortify.signal",
        "schema_version": "1.0",
        "event_id": "sha256:" + "ab" * 32,
        "event_type": "fortify.signal.observed",
        "observed_at": "2026-11-02T15:30:00Z",
        "source": {
            "platform": "fod",
            "instance_id": "customer-fod-prod",
            "application_id": 101,
            "release_id": 202879,
            "finding_id": "abc",
            "deep_link": "https://example.invalid/finding",
        },
        "application": {"name": "App|Name", "release": "main"},
        "signal": {"type": "aviator-confirmed-sast", "severity": "critical", "confidence": "high", "title": "A=B\\C\nD"},
        "finding": {
            "domain": "SAST",
            "category": "XSS",
            "source_status": "Open",
            "auditor_status": "Remediation Required",
            "suppressed": False,
            "last_modified": "2026-11-02T15:20:00Z",
            "summary": "short",
            "explanation": "line1\nline2",
        },
        "evidence": {"classifications": []},
        "provenance": {
            "collection_id": "col",
            "collector_version": "1.0",
            "processor_version": "0.1.0",
            "signal_rule_id": "aviator-confirmed-critical",
            "signal_rule_version": "1",
            "signal_schema_version": "1.0",
        },
    }


def test_cef_escaping_and_severity():
    line = format_cef(_signal(), "full")
    assert line.startswith("CEF:0|OpenText|Fortify SignalBridge|0.1.0|aviator-confirmed-sast|")
    assert "|10|" in line
    assert "externalId=sha256:" in line
    assert "App\\|Name" not in line or "cs2=App\\|Name" in line
    assert escape_header("A|B") == "A\\|B"
    assert "=" not in escape_extension("A=B").replace("\\=", "")
    assert "\\n" in line
    assert "\n" not in line
    unknown = _signal()
    unknown["signal"]["severity"] = "weird"
    unknown_line = format_cef(unknown)
    assert "|0|" in unknown_line
    assert "cs4=weird" in unknown_line
    syslog = format_syslog(line, "rfc5424", "2026-11-02T15:30:00Z", 10, "connector.example")
    assert syslog.startswith("<")
    assert " CEF:0|" in syslog or syslog.endswith(line) or "fortify.signal - CEF:0|" in syslog


def test_reconnect_resends_the_same_event():
    calls = []

    def connector(payload):
        calls.append(payload)
        if len(calls) == 1:
            raise SinkError("reset", "temporary")

    sink = ArcSightCefSink("arcsight.example", 514, connector=connector, sleep=lambda _delay: None, rng=lambda: 0)
    sink.open({})
    sink.send([_signal()])
    sink.flush()
    sink.close()
    assert sink.delivered == 1
    assert calls[0] == calls[1]
    assert b"externalId=sha256:" in calls[0]


def test_tcp_server_receives_newline_framed_cef():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received = []

    def accept():
        conn, _addr = server.accept()
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        received.append(data)
        conn.close()
        server.close()

    thread = threading.Thread(target=accept)
    thread.start()
    sink = ArcSightCefSink("127.0.0.1", port, sleep=lambda _delay: None)
    sink.open({})
    sink.send([_signal()])
    sink.flush()
    sink.close()
    thread.join(2)
    assert received and received[0].endswith(b"\n")
    assert b"externalId=" in received[0]


def test_client_key_material_is_not_logged():
    clear_secrets()
    secret = "arcsight-client-key-material"
    register_secret(secret)
    assert secret not in redact(f"loaded key {secret} from disk")
