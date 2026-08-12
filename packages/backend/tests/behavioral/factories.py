"""Small async data factories for behavioral tests (not a factory framework)."""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import FeedType, RuleHealth, SuppressionRule, ThreatFeed


async def seed_feed(
    db: AsyncSession,
    organization_id: uuid.UUID,
    name: str = "Test Feed",
    feed_type: FeedType = FeedType.CUSTOM_CSV,
) -> ThreatFeed:
    feed = ThreatFeed(
        name=name,
        url="https://example.invalid/feed.csv",
        feed_type=feed_type,
        organization_id=organization_id,
        next_sync_at=utcnow(),
        created_by="seed",
    )
    db.add(feed)
    await db.flush()
    return feed


async def seed_rule_health(
    db: AsyncSession,
    organization_id: uuid.UUID,
    rule_id: str = "Rule.Test",
) -> RuleHealth:
    rh = RuleHealth(
        organization_id=organization_id,
        rule_id=rule_id,
        rule_name="Test Rule",
        last_checked_at=utcnow(),
    )
    db.add(rh)
    await db.flush()
    return rh


async def seed_suppression(
    db: AsyncSession,
    organization_id: uuid.UUID,
    name: str = "Test Suppression",
) -> SuppressionRule:
    rule = SuppressionRule(
        organization_id=organization_id,
        name=name,
        created_by="seed",
    )
    db.add(rule)
    await db.flush()
    return rule
