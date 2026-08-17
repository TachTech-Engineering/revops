"""
DB-free regression tests for the 2026-08-13 reliability backlog.

Covers the pure logic behind items 10-14 and 17: syslog timestamp parsing
(every fractional-second width), correlation rule evaluation order, feed retry
backoff, the connector-sync in-flight guard, case-number sequencing, and the
Redis listener reconnect schedule. Nothing here touches a database or a socket.
"""

import asyncio
import uuid
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.services.case_service import (
    _sequence_lock_key,
    format_case_number,
    next_case_sequence,
)
from app.services.correlation_service import CorrelationService
from app.services.feed_service import (
    MAX_CONSECUTIVE_SYNC_FAILURES,
    SYNC_RETRY_MAX_MINUTES,
    compute_retry_delay_minutes,
)
from app.services.notification_service import NotificationService
from app.services.syslog_receiver import SyslogReceiverService, parse_syslog_timestamp

# --------------------------------------------------------------------------
# Item 10: UniFi syslog timestamps
# --------------------------------------------------------------------------

# Every fractional-second width UniFi/RFC 5424 devices emit. The old
# fromisoformat(ts[:26]) was width dependent and returned a tz-AWARE datetime
# for the 3-digit case, which is the standard UniFi CEF format.
_ISO_WIDTHS = [
    ("2024-01-15T12:34:56Z", 0),
    ("2024-01-15T12:34:56.1Z", 100000),
    ("2024-01-15T12:34:56.12Z", 120000),
    ("2024-01-15T12:34:56.123Z", 123000),
    ("2024-01-15T12:34:56.123456Z", 123456),
    ("2024-01-15T12:34:56.123456789Z", 123456),  # sub-microsecond truncated
]


@pytest.mark.parametrize(("ts_str", "expected_microsecond"), _ISO_WIDTHS)
def test_iso_timestamps_parse_naive_utc_at_every_fraction_width(ts_str, expected_microsecond):
    parsed = parse_syslog_timestamp(ts_str)

    assert parsed.tzinfo is None, f"{ts_str} produced a tz-aware datetime"
    assert (parsed.year, parsed.month, parsed.day) == (2024, 1, 15)
    assert (parsed.hour, parsed.minute, parsed.second) == (12, 34, 56)
    assert parsed.microsecond == expected_microsecond


@pytest.mark.parametrize(("ts_str", "_expected"), _ISO_WIDTHS)
def test_parsed_timestamps_compare_against_naive_datetimes(ts_str, _expected):
    """The exact comparison unifi_syslog.fetch_alerts does against `since`.

    It used to raise TypeError *after* get_buffered_messages had already
    drained the buffer, so the messages were lost for good.
    """
    since = datetime(2024, 1, 1, 0, 0, 0)
    assert parse_syslog_timestamp(ts_str) > since


def test_explicit_offset_is_converted_to_utc_not_just_stripped():
    parsed = parse_syslog_timestamp("2024-01-15T12:34:56.123+02:00")
    assert parsed.tzinfo is None
    assert parsed.hour == 10 and parsed.minute == 34


def test_rfc3164_timestamp_assumes_current_year():
    parsed = parse_syslog_timestamp("Jan  5 12:34:56")
    assert parsed.tzinfo is None
    assert (parsed.month, parsed.day, parsed.hour) == (1, 5, 12)


@pytest.mark.parametrize("ts_str", ["", "   ", None, "not-a-timestamp", "2024-13-45T99:99:99Z"])
def test_missing_or_unparseable_timestamp_falls_back_to_naive_now(ts_str):
    parsed = parse_syslog_timestamp(ts_str)
    assert parsed.tzinfo is None


def test_unifi_cef_message_is_buffered_with_a_naive_timestamp():
    receiver = SyslogReceiverService()
    raw = (
        "Jan  5 12:34:56 2024-01-15T12:34:56.123Z DK Dream Machine Pro "
        "CEF:0|Ubiquiti|UniFi OS|4.0|1001|Threat Detected|"
    )
    parsed = receiver._parse_message(raw, "192.0.2.10", 514)

    assert parsed is not None
    assert parsed.timestamp.tzinfo is None
    assert parsed.timestamp < datetime(2024, 1, 15, 12, 34, 57)


# --------------------------------------------------------------------------
# Item 11: correlation rules must all be evaluated
# --------------------------------------------------------------------------


class _FakeScalars:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class _FakeResult:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        return _FakeScalars(self._items)


class _FakeDB:
    """Minimal AsyncSession stand-in that always returns the seeded rules."""

    def __init__(self, rules):
        self._rules = rules

    async def execute(self, *_args, **_kwargs):
        return _FakeResult(self._rules)

    def add(self, _obj):
        pass

    async def flush(self):
        pass


def _make_service_with_rules(rules, *, evaluated, created):
    service = CorrelationService(_FakeDB(rules))

    async def fake_create_from_alert(alert, rule, organization_id):
        created.append(rule.name)
        return SimpleNamespace(id=uuid.uuid4(), rule=rule.name)

    async def fake_get_or_create_window(alert, rule, organization_id):
        evaluated.append(rule.name)
        return SimpleNamespace(alert_count=1, window_key="k"), True

    async def fake_check_threshold(window, alert, rule):
        return False

    service._create_incident_from_alert = fake_create_from_alert
    service._get_or_create_window = fake_get_or_create_window
    service._check_window_threshold = fake_check_threshold
    return service


def _alert():
    return SimpleNamespace(
        id=uuid.uuid4(),
        severity="critical",
        title="Suspicious login",
        rule_name="failed_login",
        source_type="panther",
        raw_data={},
    )


async def test_single_alert_rule_no_longer_starves_threshold_rules():
    """The seeded min_alerts:1 rule used to `return` and skip every other rule."""
    rules = [
        SimpleNamespace(
            id=uuid.uuid4(),
            name="Auto-Incident: Critical/High Severity Alerts",
            conditions={"severity_filter": ["critical", "high"], "min_alerts": 1},
        ),
        SimpleNamespace(
            id=uuid.uuid4(),
            name="5 failed logins in 10 minutes",
            conditions={"min_alerts": 5, "time_window_minutes": 10},
        ),
    ]
    evaluated: list[str] = []
    created: list[str] = []
    service = _make_service_with_rules(rules, evaluated=evaluated, created=created)

    incidents = await service.evaluate_alert_against_rules(_alert(), uuid.uuid4())

    # The single-alert rule still fires...
    assert created == ["Auto-Incident: Critical/High Severity Alerts"]
    # ...and the threshold rule still got this alert added to its window.
    assert evaluated == ["5 failed logins in 10 minutes"]
    assert len(incidents) == 1


async def test_process_alert_with_windows_returns_first_incident():
    rules = [
        SimpleNamespace(
            id=uuid.uuid4(),
            name="critical",
            conditions={"severity_filter": ["critical"], "min_alerts": 1},
        )
    ]
    service = _make_service_with_rules(rules, evaluated=[], created=[])

    incident = await service.process_alert_with_windows(_alert(), uuid.uuid4())
    assert incident is not None and incident.rule == "critical"


async def test_non_matching_rules_are_skipped_entirely():
    rules = [
        SimpleNamespace(
            id=uuid.uuid4(),
            name="low only",
            conditions={"severity_filter": ["low"], "min_alerts": 3},
        )
    ]
    evaluated: list[str] = []
    created: list[str] = []
    service = _make_service_with_rules(rules, evaluated=evaluated, created=created)

    assert await service.evaluate_alert_against_rules(_alert(), uuid.uuid4()) == []
    assert evaluated == [] and created == []


# --------------------------------------------------------------------------
# Item 12: feed sync retry backoff
# --------------------------------------------------------------------------


def test_feed_retry_backoff_is_exponential_and_capped():
    schedule = [compute_retry_delay_minutes(n) for n in range(1, 9)]
    assert schedule == [5, 10, 20, 40, 80, 160, 240, 240]
    assert max(schedule) == SYNC_RETRY_MAX_MINUTES


def test_feed_retry_backoff_never_returns_zero_or_decreases():
    delays = [compute_retry_delay_minutes(n) for n in range(0, 12)]
    assert all(d > 0 for d in delays)
    assert delays == sorted(delays)


def test_a_feed_stays_retryable_until_the_failure_threshold():
    # Every attempt before the threshold must still schedule a next attempt.
    for attempt in range(1, MAX_CONSECUTIVE_SYNC_FAILURES):
        assert compute_retry_delay_minutes(attempt) > 0


# --------------------------------------------------------------------------
# Item 13: connector sync in-flight guard and task references
# --------------------------------------------------------------------------


class _FakeConnectorDB:
    def __init__(self, connectors):
        self._connectors = connectors

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def execute(self, *_args, **_kwargs):
        return _FakeResult(self._connectors)


async def test_long_running_sync_is_not_spawned_twice(monkeypatch):
    from app.jobs import connector_sync as cs

    connector = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name="unifi",
        sync_interval_minutes=1,
        last_sync_at=None,  # never synced -> always due
    )
    monkeypatch.setattr(cs, "AsyncSessionLocal", lambda: _FakeConnectorDB([connector]))

    started = asyncio.Event()
    release = asyncio.Event()
    calls: list[uuid.UUID] = []

    async def fake_sync_connector_alerts(connector_id, organization_id):
        calls.append(connector_id)
        started.set()
        await release.wait()

    monkeypatch.setattr("app.api.v1.connectors.sync_connector_alerts", fake_sync_connector_alerts)

    scheduler = cs.ConnectorSyncScheduler()

    await scheduler._check_and_sync_connectors()
    await started.wait()

    # The sync is still running and last_sync_at is still None: the old code
    # spawned a fresh duplicate on every tick.
    await scheduler._check_and_sync_connectors()
    assert len(calls) == 1

    # The task is strongly referenced, so the GC cannot cancel it mid-sync.
    assert len(scheduler._tasks) == 1

    release.set()
    await asyncio.gather(*list(scheduler._tasks))
    await asyncio.sleep(0)

    assert scheduler._in_flight == set()
    assert scheduler._tasks == set()

    # Once the sync finished, the connector is eligible again.
    await scheduler._check_and_sync_connectors()
    await asyncio.gather(*list(scheduler._tasks))
    assert len(calls) == 2


async def test_in_flight_guard_is_released_when_a_sync_raises(monkeypatch):
    from app.jobs import connector_sync as cs

    scheduler = cs.ConnectorSyncScheduler()
    connector_id = uuid.uuid4()
    scheduler._in_flight.add(connector_id)

    async def boom(connector_id, organization_id):
        raise RuntimeError("connector exploded")

    monkeypatch.setattr("app.api.v1.connectors.sync_connector_alerts", boom)

    await scheduler._sync_connector(connector_id, uuid.uuid4())
    assert connector_id not in scheduler._in_flight


# --------------------------------------------------------------------------
# Item 14: per-organization case numbering
# --------------------------------------------------------------------------


def test_case_number_format_keeps_climbing_past_four_digits():
    assert format_case_number(2026, 1) == "CASE-2026-0001"
    assert format_case_number(2026, 9999) == "CASE-2026-9999"
    assert format_case_number(2026, 10000) == "CASE-2026-10000"


def test_next_sequence_compares_numerically_not_lexicographically():
    """CASE-2026-10000 sorts *below* CASE-2026-9999 as a string.

    The old ORDER BY case_number DESC therefore pinned the counter at 9999
    forever, and every create past that point hit a duplicate key.
    """
    numbers = ["CASE-2026-9998", "CASE-2026-9999", "CASE-2026-10000"]
    assert next_case_sequence(numbers, 2026) == 10001


def test_next_sequence_starts_at_one_for_an_empty_organization():
    assert next_case_sequence([], 2026) == 1


def test_next_sequence_ignores_other_years_and_malformed_numbers():
    numbers = ["CASE-2025-5000", "CASE-2026-0007", "CASE-2026-legacy", "", "CASE-2026-"]
    assert next_case_sequence(numbers, 2026) == 8


def test_next_sequence_is_order_independent():
    numbers = ["CASE-2026-0300", "CASE-2026-0012", "CASE-2026-0299"]
    assert next_case_sequence(numbers, 2026) == 301
    assert next_case_sequence(list(reversed(numbers)), 2026) == 301


def test_sequence_lock_key_is_stable_per_org_and_fits_int4():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()

    key_a = _sequence_lock_key(org_a, 2026)
    assert key_a == _sequence_lock_key(org_a, 2026)
    assert key_a != _sequence_lock_key(org_a, 2027)
    assert key_a != _sequence_lock_key(org_b, 2026)
    assert -(2**31) <= key_a < 2**31


# --------------------------------------------------------------------------
# Item 17: Redis listener reconnect backoff
# --------------------------------------------------------------------------


def test_redis_reconnect_backoff_is_exponential_and_capped():
    schedule = [NotificationService.reconnect_delay(n) for n in range(1, 8)]
    assert schedule == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert max(schedule) == NotificationService.RECONNECT_MAX_DELAY


def test_redis_reconnect_backoff_is_never_zero():
    assert all(NotificationService.reconnect_delay(n) > 0 for n in range(0, 10))


async def test_listener_reconnects_after_a_redis_error_instead_of_exiting(monkeypatch):
    """One hiccup used to end the loop for the process lifetime."""
    service = NotificationService()
    service._started = True
    service._pubsub = object()  # non-None so _listen_loop tries to consume

    failures = []
    reconnects = []
    started_flags = []

    async def flaky_consume():
        failures.append(1)
        started_flags.append(service._started)
        if len(failures) <= 2:
            raise ConnectionError("redis went away")
        service._started = False  # third pass: let the loop end cleanly

    async def fake_reconnect():
        reconnects.append(1)

    monkeypatch.setattr(NotificationService, "reconnect_delay", staticmethod(lambda _n: 0.0))
    service._consume_messages = flaky_consume
    service._reconnect = fake_reconnect

    await asyncio.wait_for(service._listen_loop(), timeout=5)

    # Two errors did not end the loop: it consumed again both times.
    assert len(failures) == 3
    assert len(reconnects) >= 2
    # _started is only cleared by disconnect(), never by a connection error --
    # the old loop set it False and left registered subscribers with no
    # listener at all.
    assert started_flags == [True, True, True]
