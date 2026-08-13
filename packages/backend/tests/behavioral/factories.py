"""Small async data factories for behavioral tests (not a factory framework)."""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import (
    IOC,
    AlertCluster,
    AlertClusterStatus,
    Case,
    CasePriority,
    FeedType,
    HuntQuery,
    HuntResult,
    HuntResultStatus,
    IOCSeverity,
    IOCType,
    Notification,
    NotificationType,
    RuleHealth,
    SuppressionRule,
    ThreatFeed,
    ThreatHunt,
)


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


async def seed_ioc(
    db: AsyncSession,
    organization_id: uuid.UUID,
    value: str = "10.10.10.10",
    ioc_type: IOCType = IOCType.IP_ADDRESS,
    severity: IOCSeverity = IOCSeverity.MEDIUM,
) -> IOC:
    ioc = IOC(
        organization_id=organization_id,
        ioc_type=ioc_type,
        value=value,
        severity=severity,
        source="seed",
        created_by="seed",
    )
    db.add(ioc)
    await db.flush()
    return ioc


async def seed_case(
    db: AsyncSession,
    organization_id: uuid.UUID,
    title: str = "Seeded Case",
    case_number: str | None = None,
) -> Case:
    case = Case(
        organization_id=organization_id,
        case_number=case_number or f"CASE-{uuid.uuid4().hex[:8]}",
        title=title,
        priority=CasePriority.MEDIUM,
        created_by="seed",
    )
    db.add(case)
    await db.flush()
    return case


async def seed_alert_cluster(
    db: AsyncSession,
    organization_id: uuid.UUID,
    name: str = "Seeded Cluster",
) -> AlertCluster:
    now = utcnow()
    cluster = AlertCluster(
        organization_id=organization_id,
        name=name,
        summary="Seeded summary",
        severity="medium",
        status=AlertClusterStatus.OPEN,
        cluster_type="rule_based",
        alert_count=3,
        first_alert_at=now,
        last_alert_at=now,
        common_entities={},
    )
    db.add(cluster)
    await db.flush()
    return cluster


async def seed_notification(
    db: AsyncSession,
    organization_id: uuid.UUID,
    user_email: str,
    title: str = "Seeded Notification",
) -> Notification:
    notification = Notification(
        organization_id=organization_id,
        user_email=user_email,
        notification_type=NotificationType.MENTION,
        title=title,
        message="Seeded message",
    )
    db.add(notification)
    await db.flush()
    return notification


async def seed_hunt(
    db: AsyncSession,
    organization_id: uuid.UUID,
    title: str = "Seeded Hunt",
) -> ThreatHunt:
    hunt = ThreatHunt(
        organization_id=organization_id,
        title=title,
        hypothesis="If X then Y is observable in Z.",
        created_by="seed",
    )
    db.add(hunt)
    await db.flush()
    return hunt


async def seed_hunt_query(
    db: AsyncSession,
    hunt_id: uuid.UUID,
    name: str = "Seeded Query",
    sql_query: str = "SELECT * FROM security_events ORDER BY timestamp DESC",
) -> HuntQuery:
    query = HuntQuery(
        hunt_id=hunt_id,
        name=name,
        sql_query=sql_query,
    )
    db.add(query)
    await db.flush()
    return query


async def seed_hunt_result(
    db: AsyncSession,
    organization_id: uuid.UUID,
    hunt_id: uuid.UUID,
    query_id: uuid.UUID | None = None,
    simulated: bool = True,
) -> HuntResult:
    """Seed a COMPLETED hunt result marked as simulated (guards honesty labeling)."""
    findings = [
        {
            "severity": "medium",
            "description": "[SIMULATED] Placeholder finding - no query was executed",
            "source": "threat_hunt_simulation",
            "simulated": simulated,
        }
    ]
    result = HuntResult(
        organization_id=organization_id,
        hunt_id=hunt_id,
        query_id=query_id,
        status=HuntResultStatus.COMPLETED,
        results_count=len(findings),
        findings=findings,
        raw_results={"simulated": simulated, "query": "SELECT ..."},
        executed_by="seed",
        executed_at=utcnow(),
    )
    db.add(result)
    await db.flush()
    return result
