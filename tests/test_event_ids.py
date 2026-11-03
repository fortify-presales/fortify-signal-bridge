import hashlib
import json

from signalbridge.event_id import canonical_identity, event_id


def test_documented_vector():
    digest = hashlib.sha256(canonical_identity(
        "fod", "customer-fod-prod", 202879, "dcc9e589-example",
        "2026-11-02T15:20:00Z", None, "aviator-confirmed-critical", "1", "1.0",
    )).hexdigest()
    assert event_id(
        "fod", "customer-fod-prod", 202879, "dcc9e589-example",
        "2026-11-02T15:20:00Z", None, "aviator-confirmed-critical", "1", "1.0",
    ) == "sha256:" + digest


def test_repeat_is_stable_and_ignores_runtime_fields():
    first = event_id("fod", "inst", 10, "abc", "2026-11-01T00:00:00Z", None, "rule", "1", "1.0")
    second = event_id("fod", "inst", 10, "abc", "2026-11-01T00:00:00Z", None, "rule", "1", "1.0")
    assert first == second
    assert first.startswith("sha256:")


def test_null_timestamp_differs_from_empty_string():
    null_id = event_id("fod", "inst", 10, "abc", None, None, "rule", "1", "1.0")
    empty_id = event_id("fod", "inst", 10, "abc", "", None, "rule", "1", "1.0")
    assert null_id != empty_id
    raw = canonical_identity("fod", "inst", 10, "abc", None, None, "rule", "1", "1.0")
    assert b"null" in raw
    assert json.loads(raw.decode())[4] is None


def test_revision_and_platform_change_the_id():
    fod = event_id("fod", "inst", 10, "abc", "2026-11-01T00:00:00Z", None, "rule", "1", "1.0")
    ssc = event_id("ssc", "inst", 10, "abc", "2026-11-01T00:00:00Z", None, "rule", "1", "1.0")
    revised = event_id("ssc", "inst", 10, "abc", "2026-11-01T00:00:00Z", 4, "rule", "1", "1.0")
    assert len({fod, ssc, revised}) == 3
