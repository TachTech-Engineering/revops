"""Time helpers for the app's naive-UTC datetime convention."""

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime.

    Drop-in replacement for the deprecated ``datetime.utcnow()``. The value is
    deliberately naive (tzinfo stripped): every ``DateTime`` column in the models
    is ``TIMESTAMP WITHOUT TIME ZONE``, and mixing tz-aware values in breaks
    comparisons — see commit 6a7be58. Use this everywhere instead of
    ``datetime.utcnow()`` or ``datetime.now(timezone.utc)``.
    """
    return datetime.now(UTC).replace(tzinfo=None)
