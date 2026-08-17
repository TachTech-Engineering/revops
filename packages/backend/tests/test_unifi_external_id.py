"""
UniFi alert identity.

`external_id` is what uq_normalized_alerts_org_connector_external deduplicates
on, so how UniFi builds it decides two things: whether a re-delivered syslog
buffer duplicates alerts, and whether two genuinely different events collapse
into one. The connector previously got this wrong in both directions at once --
a uuid on the syslog path (never deduped) and hostname+timestamp on another
path (over-deduped, silently dropping distinct events once the unique index
existed).

The over-dedup direction is the dangerous one: a duplicate alert is noise, a
dropped alert is a missed detection. These tests pin both.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.connectors.data_sources.unifi_syslog import (
    UniFiSyslogConnector,
    content_external_id,
)

TS = datetime(2026, 8, 17, 12, 0, 0)


def _msg(message: str, *, ts: datetime = TS, source_ip: str = "10.0.0.1", host: str = "udm"):
    return SimpleNamespace(
        message=message,
        raw=message,
        timestamp=ts,
        source_ip=source_ip,
        hostname=host,
        app_name="kernel",
        process_id="123",
    )


def _connector() -> UniFiSyslogConnector:
    import uuid as _uuid

    return UniFiSyslogConnector(_uuid.uuid4(), {}, {})


# --- the helper ------------------------------------------------------------


def test_same_content_yields_same_id():
    """Re-delivery of a buffered message must dedupe, not duplicate."""
    assert content_external_id("p", "a", TS, "msg") == content_external_id("p", "a", TS, "msg")


def test_different_content_yields_different_id():
    """Distinct events must survive: a collision here is a lost alert."""
    assert content_external_id("p", "a", TS, "msg") != content_external_id("p", "a", TS, "other")


def test_different_timestamp_yields_different_id():
    later = TS + timedelta(seconds=1)
    assert content_external_id("p", "a", TS, "msg") != content_external_id("p", "a", later, "msg")


def test_id_is_independent_of_local_timezone():
    """datetime.timestamp() reads a naive datetime as LOCAL time, so an id built
    from it would change with the container's TZ. isoformat() must be used."""
    import os
    import time

    before = content_external_id("p", TS)
    old_tz = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "Asia/Tokyo"
        time.tzset()
        assert content_external_id("p", TS) == before
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()


def test_id_fits_the_column():
    """external_id is VARCHAR(500); the clamp would silently truncate."""
    assert len(content_external_id("unifi-syslog", "x" * 10_000)) < 100


def test_none_and_missing_parts_do_not_crash():
    assert content_external_id("p", None, "", 0)


# --- the syslog normalization path ----------------------------------------


def test_syslog_replay_produces_the_same_id():
    """The bug this fixes: the buffer re-delivers, and the uuid scheme made
    every delivery a new alert."""
    c = _connector()
    first = c._normalize_syslog_message(_msg("CEF:0|Ubiquiti|UDM|1|100|Port scan|8|src=1.2.3.4"))
    second = c._normalize_syslog_message(_msg("CEF:0|Ubiquiti|UDM|1|100|Port scan|8|src=1.2.3.4"))
    assert first.external_id == second.external_id


def test_two_distinct_messages_in_the_same_second_stay_distinct():
    """Same host, same timestamp, different content -- must NOT collapse."""
    c = _connector()
    a = c._normalize_syslog_message(_msg("CEF:0|Ubiquiti|UDM|1|100|Port scan|8|src=1.2.3.4"))
    b = c._normalize_syslog_message(_msg("CEF:0|Ubiquiti|UDM|1|101|Admin login|5|src=9.9.9.9"))
    assert a.external_id != b.external_id


def test_same_message_from_different_devices_stays_distinct():
    c = _connector()
    a = c._normalize_syslog_message(_msg("link down", source_ip="10.0.0.1", host="sw-1"))
    b = c._normalize_syslog_message(_msg("link down", source_ip="10.0.0.2", host="sw-2"))
    assert a.external_id != b.external_id


def test_syslog_id_is_not_random():
    """Guards against a regression to uuid: two normalizations of one message
    must agree."""
    c = _connector()
    ids = {
        c._normalize_syslog_message(_msg("same line")).external_id for _ in range(5)
    }
    assert len(ids) == 1


def test_syslog_id_is_prefixed_and_bounded():
    c = _connector()
    alert = c._normalize_syslog_message(_msg("anything"))
    assert alert.external_id.startswith("unifi-syslog-")
    assert len(alert.external_id) <= 500
