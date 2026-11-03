"""Keep secret values out of logs and error text."""

import logging
import threading

_secrets = []
_lock = threading.Lock()


def register_secret(value):
    if not value or len(value) < 4:
        return
    with _lock:
        if value not in _secrets:
            _secrets.append(value)


def clear_secrets():
    with _lock:
        _secrets.clear()


def redact(text):
    if text is None:
        return text
    out = str(text)
    with _lock:
        values = list(_secrets)
    for secret in values:
        if secret and secret in out:
            out = out.replace(secret, "***")
    return out


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))


def configure_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(message)s"))
    root = logging.getLogger("signalbridge")
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    root.propagate = False
    return root
