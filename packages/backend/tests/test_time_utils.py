"""
utcnow helper — cheap, DB-free guard for the naive-UTC column convention.

Every DateTime column in the models is TIMESTAMP WITHOUT TIME ZONE, so utcnow()
must return a NAIVE datetime (tzinfo is None) that still tracks real UTC.
"""

from datetime import UTC, datetime

from app.core.time_utils import utcnow


def test_utcnow_is_naive():
    now = utcnow()
    assert isinstance(now, datetime)
    assert now.tzinfo is None


def test_utcnow_tracks_real_utc():
    real_utc_naive = datetime.now(UTC).replace(tzinfo=None)
    delta_seconds = abs((real_utc_naive - utcnow()).total_seconds())
    # Generous bound: proves it is UTC "now", not a fixed/local value.
    assert delta_seconds < 5
