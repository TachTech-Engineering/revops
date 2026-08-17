"""
Feed sync NULL-org fix (pre-existing production breakage).

feed_service.sync_feed must attribute every imported IOC and the FeedSyncLog row
to the feed's organization_id (both columns are NOT NULL), and must SKIP — not
crash — a legacy feed whose organization_id is NULL. No real network is used:
httpx is stubbed to return a canned CSV.
"""

import uuid

import pytest
from sqlalchemy import select

from app.core.time_utils import utcnow
from app.db.models import IOC, FeedStatus, FeedSyncLog, FeedType, ThreatFeed
from app.services.feed_service import feed_service


class _FakeResponse:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return {}


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient used as an async context manager."""

    def __init__(self, text: str):
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, timeout=None):
        return _FakeResponse(self._text)


@pytest.mark.asyncio
async def test_sync_feed_attributes_org_to_iocs_and_log(db_session, monkeypatch):
    from app.db.models import Organization

    org = Organization(name="Sync Org", slug=f"sync-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()

    feed = ThreatFeed(
        name="Custom CSV feed",
        url="https://example.invalid/iocs.csv",
        feed_type=FeedType.CUSTOM_CSV,
        organization_id=org.id,
        next_sync_at=utcnow(),
        created_by="seed",
    )
    db_session.add(feed)
    await db_session.flush()

    # CSV: header row is skipped by parse_generic_csv, leaving two IP IOCs.
    csv_body = "ip_address\n198.51.100.10\n203.0.113.55\n"
    monkeypatch.setattr(
        "app.services.feed_service.httpx.AsyncClient",
        lambda *a, **k: _FakeAsyncClient(csv_body),
    )

    result = await feed_service.sync_feed(db_session, feed.id, organization_id=org.id)

    assert result["status"] == "success"
    assert result["iocs_added"] == 2

    iocs = (await db_session.execute(select(IOC).where(IOC.feed_id == feed.id))).scalars().all()
    assert len(iocs) == 2
    # The fix: imported IOCs carry the feed's org, never NULL.
    assert all(ioc.organization_id == org.id for ioc in iocs)

    logs = (
        (await db_session.execute(select(FeedSyncLog).where(FeedSyncLog.feed_id == feed.id)))
        .scalars()
        .all()
    )
    assert len(logs) == 1
    assert logs[0].organization_id == org.id
    assert logs[0].status == "success"

    await db_session.refresh(feed)
    assert feed.status == FeedStatus.ACTIVE


@pytest.mark.asyncio
async def test_sync_feed_skips_legacy_null_org_feed(db_session, monkeypatch):
    # A legacy row predating org enforcement. The NOT NULL constraints make it
    # impossible to persist here, so we serve it via get_feed to exercise the
    # guard branch exactly as production would hit it.
    legacy_feed = ThreatFeed(
        id=uuid.uuid4(),
        name="Legacy feed",
        url="https://example.invalid/legacy.csv",
        feed_type=FeedType.CUSTOM_CSV,
        organization_id=None,
        created_by="legacy",
    )

    async def _fake_get_feed(db, feed_id, organization_id=None):
        return legacy_feed

    monkeypatch.setattr(feed_service, "get_feed", _fake_get_feed)

    # Must not raise despite the NULL org.
    result = await feed_service.sync_feed(db_session, legacy_feed.id)

    assert result["status"] == "skipped"
    assert "organization_id" in result["error"]
    assert result["iocs_added"] == 0

    # No sync log is written for a skipped legacy feed.
    logs = (
        (await db_session.execute(select(FeedSyncLog).where(FeedSyncLog.feed_id == legacy_feed.id)))
        .scalars()
        .all()
    )
    assert logs == []
