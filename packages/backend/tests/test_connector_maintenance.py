"""
Housekeeping on the connector sync loop.

Claimed Falco ingest events are retained for a debugging window and then
reaped. `purge_processed()` existed but nothing called it, so the staging table
only ever grew. It now runs on the existing sync loop, throttled and guarded by
an advisory lock because every replica runs that loop.
"""

import inspect
from datetime import timedelta

import pytest

from app.core.time_utils import utcnow
from app.db.run_migrations import SCHEMA_ADVISORY_LOCK_ID
from app.jobs.connector_sync import MAINTENANCE_LOCK_ID, ConnectorSyncScheduler
from app.jobs.cve_feed_sync import CVE_SYNC_LOCK_ID
from app.services import escalation_service as escalation_module
from app.services.escalation_service import ESCALATION_SWEEP_LOCK_ID


def test_advisory_lock_ids_are_distinct():
    """Two sweeps sharing a lock id would silently block each other."""
    ids = [
        MAINTENANCE_LOCK_ID,
        ESCALATION_SWEEP_LOCK_ID,
        SCHEMA_ADVISORY_LOCK_ID,
        CVE_SYNC_LOCK_ID,
    ]
    assert len(set(ids)) == len(ids)


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _StubSession:
    """Records executed SQL; reports whether the advisory lock was acquired."""

    def __init__(self, lock_acquired=True):
        self.lock_acquired = lock_acquired
        self.statements: list[str] = []
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt, params=None):
        self.statements.append(str(stmt))
        return _Result(self.lock_acquired)

    async def commit(self):
        self.committed = True


def _wire(monkeypatch, session, purged=0):
    calls = {"purge": 0, "purge_generic": 0}

    async def fake_purge(db, older_than_hours=24):
        calls["purge"] += 1
        return purged

    async def fake_purge_generic(db, older_than_hours=24):
        calls["purge_generic"] += 1
        return purged

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", lambda: session)
    monkeypatch.setattr("app.services.falco_event_buffer.purge_processed", fake_purge)
    monkeypatch.setattr("app.services.ingest_buffer.purge_processed", fake_purge_generic)
    return calls


@pytest.mark.asyncio
async def test_maintenance_runs_on_first_tick(monkeypatch):
    """A pod that restarts frequently must still perform housekeeping."""
    session = _StubSession()
    calls = _wire(monkeypatch, session, purged=3)
    scheduler = ConnectorSyncScheduler()
    assert scheduler._last_maintenance is None

    await scheduler._run_maintenance_if_due()

    assert calls["purge"] == 1
    assert session.committed


@pytest.mark.asyncio
async def test_maintenance_is_throttled(monkeypatch):
    """It rides a 60s loop but must not sweep every minute."""
    session = _StubSession()
    calls = _wire(monkeypatch, session)
    scheduler = ConnectorSyncScheduler()

    await scheduler._run_maintenance_if_due()
    await scheduler._run_maintenance_if_due()
    assert calls["purge"] == 1, "second tick within the interval must be skipped"

    # Age the marker past the interval.
    scheduler._last_maintenance = utcnow() - timedelta(seconds=scheduler._maintenance_interval + 1)
    await scheduler._run_maintenance_if_due()
    assert calls["purge"] == 2


@pytest.mark.asyncio
async def test_replica_without_the_lock_skips(monkeypatch):
    """Three replicas run this loop; only the lock holder should sweep."""
    session = _StubSession(lock_acquired=False)
    calls = _wire(monkeypatch, session)
    scheduler = ConnectorSyncScheduler()

    await scheduler._run_maintenance_if_due()

    assert calls["purge"] == 0
    assert not session.committed
    assert any("pg_try_advisory_xact_lock" in s for s in session.statements)


@pytest.mark.asyncio
async def test_lock_is_not_leaked_when_purge_raises(monkeypatch):
    """A leaked lock would block the sweep on every later tick.

    With a transaction-scoped lock there is nothing to release by hand: the
    failed transaction ends and Postgres drops the lock. What must hold is that
    the sweep does not commit a partial result.
    """
    session = _StubSession()

    async def boom(db, older_than_hours=24):
        raise RuntimeError("purge failed")

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", lambda: session)
    monkeypatch.setattr("app.services.falco_event_buffer.purge_processed", boom)

    scheduler = ConnectorSyncScheduler()
    with pytest.raises(RuntimeError):
        await scheduler._run_maintenance_if_due()

    assert not session.committed


@pytest.mark.asyncio
async def test_maintenance_failure_does_not_stop_the_sync_loop(monkeypatch):
    """Housekeeping is best-effort; it must not take connector sync down."""
    scheduler = ConnectorSyncScheduler()
    scheduler._check_interval = 0
    ticks = {"sync": 0}

    async def fake_sync():
        ticks["sync"] += 1
        if ticks["sync"] >= 2:
            scheduler._running = False

    async def failing_maintenance():
        raise RuntimeError("housekeeping exploded")

    monkeypatch.setattr(scheduler, "_check_and_sync_connectors", fake_sync)
    monkeypatch.setattr(scheduler, "_run_maintenance_if_due", failing_maintenance)

    await scheduler.start()

    assert ticks["sync"] >= 2, "sync kept running despite maintenance raising"


# ---------------------------------------------------------------------------
# Advisory locks must be transaction-scoped.
#
# The first version of this sweep used session-scoped pg_try_advisory_lock and
# committed before unlocking. A session-scoped lock belongs to a *connection*;
# after a commit SQLAlchemy can hand the unlock a different pooled connection,
# so the unlock succeeds against a connection that never held the lock and the
# real holder sits idle in the pool holding it forever -- silently disabling
# the sweep. Observed in production: held 108s by an idle connection.
# ---------------------------------------------------------------------------



def _sweep_source() -> str:
    from app.jobs import connector_sync

    return inspect.getsource(connector_sync.ConnectorSyncScheduler._run_maintenance_if_due)


def test_maintenance_uses_transaction_scoped_lock():
    src = _sweep_source()
    assert "pg_try_advisory_xact_lock" in src
    assert "pg_try_advisory_lock(" not in src, "session-scoped lock leaks across the pool"


def test_maintenance_does_not_unlock_manually():
    """An explicit unlock is the tell that the lock is session-scoped."""
    assert "pg_advisory_unlock" not in _sweep_source()


def test_escalation_sweep_uses_transaction_scoped_lock():
    src = inspect.getsource(escalation_module.EscalationScheduler._process_due_escalations)
    assert "pg_try_advisory_xact_lock" in src
    assert "pg_advisory_unlock" not in src
