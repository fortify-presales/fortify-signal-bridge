"""CEF syslog for an ArcSight 8.x SmartConnector.

Syslog has no application acknowledgement. A batch is delivered when the bytes
have been written and flushed. The CEF REST SmartConnector is not implemented:
it polls a REST API, and this process is not a server.
"""

import socket
import ssl
from datetime import datetime, timezone

from signalbridge import PROCESSOR_VERSION
from signalbridge.retryutil import delay_seconds
from signalbridge.sinks import Sink, SinkError

CEF_SEVERITY = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}
# local0 facility is 16. Syslog severity is derived from the CEF integer.
SYSLOG_SEVERITY = {10: 2, 8: 4, 5: 5, 3: 6, 1: 6, 0: 6}
EXPLANATION_CAP = 1024


def escape_header(value):
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "\\r").replace("\n", "\\n")


def escape_extension(value):
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def cef_severity(signal):
    name = ((signal.get("signal") or {}).get("severity") or "").lower()
    if name in CEF_SEVERITY:
        return CEF_SEVERITY[name], None
    original = (signal.get("signal") or {}).get("severity")
    return 0, original


def format_cef(signal, detail_level="summary"):
    severity, unknown = cef_severity(signal)
    body = signal.get("signal") or {}
    source = signal.get("source") or {}
    finding = signal.get("finding") or {}
    application = signal.get("application") or {}
    provenance = signal.get("provenance") or {}
    header = "|".join([
        "CEF:0",
        escape_header("OpenText"),
        escape_header("Fortify SignalBridge"),
        escape_header(PROCESSOR_VERSION),
        escape_header(body.get("type")),
        escape_header(body.get("title")),
        str(severity),
    ])
    extensions = [
        ("externalId", signal.get("event_id")),
        ("rt", signal.get("observed_at")),
        ("cat", finding.get("category")),
        ("deviceProcessName", finding.get("domain")),
        ("request", source.get("deep_link")),
        ("dvchost", source.get("instance_id")),
        ("cs1Label", "ruleId"),
        ("cs1", provenance.get("signal_rule_id")),
        ("cs2Label", "application"),
        ("cs2", application.get("name")),
        ("cs3Label", "release"),
        ("cs3", application.get("release")),
        ("cn1Label", "releaseId"),
        ("cn1", source.get("release_id")),
        ("cn2Label", "applicationId"),
        ("cn2", source.get("application_id")),
    ]
    if finding.get("last_modified"):
        extensions.append(("end", finding.get("last_modified")))
    if unknown is not None:
        extensions.append(("cs4Label", "sourceSeverity"))
        extensions.append(("cs4", unknown))
    if detail_level in ("standard", "full") and finding.get("summary"):
        extensions.append(("msg", finding.get("summary")))
    if detail_level == "full" and finding.get("explanation"):
        extensions.append(("cs5Label", "explanation"))
        extensions.append(("cs5", str(finding.get("explanation"))[:EXPLANATION_CAP]))
    body_ext = " ".join(f"{key}={escape_extension(value)}" for key, value in extensions if value is not None)
    line = header + ("|" + body_ext if body_ext else "|")
    if "\n" in line or "\r" in line:
        raise SinkError("CEF line contains a raw newline", "permanent")
    return line


def syslog_priority(cef_value):
    return 16 * 8 + SYSLOG_SEVERITY.get(cef_value, 6)


def format_syslog(cef_line, syslog_format, observed_at, severity, hostname="fortify-signalbridge"):
    when = datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    pri = syslog_priority(severity)
    host = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in hostname)[:255] or "fortify-signalbridge"
    if syslog_format == "bsd":
        stamp = f"{when.strftime('%b')} {when.day:2d} {when.strftime('%H:%M:%S')}"
        return f"<{pri}>{stamp} {host} {cef_line}"
    if syslog_format == "rfc5424":
        stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"<{pri}>1 {stamp} {host} FortifySignalBridge - fortify.signal - {cef_line}"
    raise SinkError(f"Unknown syslog format {syslog_format}", "permanent")


class ArcSightCefSink(Sink):
    sink_id = "arcsight"

    def __init__(self, host, port, protocol="tcp", syslog_format="rfc5424", timeout=30,
                 max_retries=4, batch_size=100, tls=False, ca_file=None, client_cert=None,
                 client_key=None, detail_level="summary", sleep=None, rng=None, connector=None):
        self.host = host
        self.port = int(port)
        self.protocol = protocol
        self.syslog_format = syslog_format
        self.timeout = timeout
        self.max_retries = max_retries
        self.batch_size = batch_size
        self.tls = tls
        self.ca_file = ca_file
        self.client_cert = client_cert
        self.client_key = client_key
        self.detail_level = detail_level
        self.sleep = sleep
        self.rng = rng
        self.connector = connector
        self._pending = []

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

    def _lines(self, chunk):
        lines = []
        for signal in chunk:
            try:
                cef_line = format_cef(signal, self.detail_level)
                severity, _unknown = cef_severity(signal)
                observed = signal.get("observed_at") or "1970-01-01T00:00:00Z"
                lines.append(format_syslog(cef_line, self.syslog_format, observed, severity, self.host))
            except SinkError:
                raise
            except Exception as exc:
                raise SinkError(f"CEF encoding failed: {exc}", "permanent") from exc
        return lines

    def _deliver(self, chunk):
        lines = self._lines(chunk)
        payload = "".join(line + "\n" for line in lines).encode("utf-8")
        attempt = 0
        while True:
            attempt += 1
            try:
                self._write(payload)
                self.delivered += len(chunk)
                return
            except SinkError as exc:
                if exc.category != "temporary" or attempt >= self.max_retries:
                    self.failed += len(chunk)
                    self.status = "failed"
                    self.error_category = exc.category
                    raise
                if self.sleep:
                    self.sleep(delay_seconds(attempt, self.rng))

    def _write(self, payload):
        if self.connector:
            self.connector(payload)
            return
        if self.protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.sendto(payload, (self.host, self.port))
            except OSError as exc:
                raise SinkError(f"ArcSight UDP send failed: {exc.__class__.__name__}", "temporary") from exc
            finally:
                sock.close()
            return
        if self.protocol != "tcp":
            raise SinkError(f"Unknown ArcSight protocol {self.protocol}", "permanent")
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            sock = raw
            if self.tls:
                context = ssl.create_default_context(cafile=self.ca_file) if self.ca_file else ssl.create_default_context()
                if self.client_cert:
                    context.load_cert_chain(self.client_cert, self.client_key)
                sock = context.wrap_socket(raw, server_hostname=self.host)
            sock.connect((self.host, self.port))
            sock.sendall(payload)
            if hasattr(sock, "flush"):
                sock.flush()
        except OSError as exc:
            raise SinkError(f"ArcSight connection failed: {exc.__class__.__name__}", "temporary") from exc
        except ssl.SSLError as exc:
            raise SinkError(f"ArcSight TLS failed: {exc.__class__.__name__}", "temporary") from exc
        finally:
            try:
                sock.close()
            except Exception:
                raw.close()
