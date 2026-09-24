"""Attaches freshly ingested alerts to a shared cluster.

The matching rules live in :mod:`app.services.alert_grouping`; this module is
the database half -- finding the cluster a fingerprint currently routes to,
creating one when there is none, and settling the race when two connectors sync
the same event at the same time.

Grouping runs inside the caller's transaction, immediately after the alerts are
inserted, so an alert is never visible without its cluster.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from uuid import UUID

from sqlalchemy import desc, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import (
    AlertCluster,
    AlertClusterKey,
    AlertClusterMember,
    AlertClusterStatus,
    NormalizedAlert,
)
from app.services.alert_grouping import candidate_keys

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Cap on how many distinct values of one entity kind are kept on the cluster
# summary. A cluster that has swept 400 hosts is described well enough by the
# first handful, and common_entities is rendered verbatim in the UI.
_MAX_SUMMARY_VALUES = 12


def _severity_rank(severity: str | None) -> int:
    return _SEVERITY_RANK.get((severity or "").lower(), 0)


def _window() -> timedelta:
    return timedelta(hours=settings.alert_grouping_window_hours)


def _headline(alert: NormalizedAlert, keys: list[tuple[str, str, str]]) -> tuple[str, str]:
    """Name the cluster after the alert that opened it and its top entity."""
    title = (alert.title or alert.rule_name or "Alert").strip()
    kind, value, _ = keys[0]
    name = f"{title} — {kind}: {value}" if value else title
    return name[:500], title


async def _release_lapsed_keys(
    db: AsyncSession,
    organization_id: UUID,
    fingerprints: list[str],
    event_time,
) -> None:
    """Retire fingerprints whose grouping window closed before this event.

    Releasing lazily, against the incoming alert's own event time rather than
    wall-clock now, is what keeps a 30-day backfill honest: replaying history
    must reproduce the clusters that live ingestion would have built, not fold
    a month of separate incidents into one because they all arrived in the same
    minute. It also means no sweeper job has to exist.
    """
    await db.execute(
        update(AlertClusterKey)
        .where(
            AlertClusterKey.organization_id == organization_id,
            AlertClusterKey.fingerprint.in_(fingerprints),
            AlertClusterKey.expires_at.is_not(None),
            AlertClusterKey.expires_at < event_time,
        )
        .values(expires_at=None)
    )


async def _find_cluster(
    db: AsyncSession,
    organization_id: UUID,
    fingerprints: list[str],
    event_time,
) -> AlertCluster | None:
    """Return the open cluster this alert belongs to, if one is still collecting."""
    result = await db.execute(
        select(AlertCluster)
        .join(AlertClusterKey, AlertClusterKey.cluster_id == AlertCluster.id)
        .where(
            AlertClusterKey.organization_id == organization_id,
            AlertClusterKey.fingerprint.in_(fingerprints),
            AlertClusterKey.expires_at.is_not(None),
        )
        .order_by(desc(AlertCluster.last_alert_at))
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _add_key(
    db: AsyncSession,
    cluster: AlertCluster,
    organization_id: UUID,
    key: tuple[str, str, str],
    expires_at,
) -> bool:
    """Claim one fingerprint for this cluster. False if another cluster holds it."""
    kind, value, digest = key
    try:
        async with db.begin_nested():
            db.add(
                AlertClusterKey(
                    organization_id=organization_id,
                    cluster_id=cluster.id,
                    fingerprint=digest,
                    entity_kind=kind,
                    entity_value=value[:255],
                    expires_at=expires_at,
                )
            )
            await db.flush()
        return True
    except IntegrityError:
        # Held by a different active cluster. The alert is already a member of
        # this one, and merging the two is a judgement call that belongs to an
        # analyst via /alert-clusters/{id}/merge, not to the sync path.
        return False


def _summarize(cluster: AlertCluster, alert: NormalizedAlert, keys) -> None:
    entities: dict[str, list[str]] = {}
    existing = cluster.common_entities if isinstance(cluster.common_entities, dict) else {}

    for field, value in existing.items():
        if isinstance(value, list):
            entities[field] = [str(v) for v in value]
        elif value is not None:
            entities[field] = [str(value)]

    for kind, value, _ in keys:
        if not value:
            continue
        bucket = entities.setdefault(kind, [])
        if value not in bucket and len(bucket) < _MAX_SUMMARY_VALUES:
            bucket.append(value)

    sources = entities.setdefault("sources", [])
    if alert.source_type and alert.source_type not in sources:
        sources.append(alert.source_type)

    # Reassigned rather than mutated: common_entities is a plain JSON column,
    # so in-place edits are invisible to the unit of work and never persist.
    cluster.common_entities = entities

    source_list = ", ".join(sources) or "one source"
    cluster.summary = (
        f"{cluster.alert_count} alert(s) reported by {source_list} "
        f"between {cluster.first_alert_at:%Y-%m-%d %H:%M} and "
        f"{cluster.last_alert_at:%Y-%m-%d %H:%M} UTC, grouped because they "
        f"describe the same activity on the same entities."
    )


async def group_alerts(
    db: AsyncSession,
    alerts: list[NormalizedAlert],
    organization_id: UUID,
) -> dict[str, int]:
    """Attach each alert to a cluster, creating clusters as needed.

    Every alert ends up in a cluster, including one that is the only report of
    its event -- otherwise the second source to report it would have nothing to
    join, which is the entire point. A cluster of one is simply an alert that
    only one product saw.

    Returns counts for the sync log. Never raises: a grouping failure must not
    cost the caller the alerts it just ingested.
    """
    stats = {"clusters_created": 0, "alerts_grouped": 0}
    if not alerts or not settings.alert_grouping_enabled:
        return stats

    # Oldest first. The window only behaves like a window if time moves
    # forward as the batch is walked: a full_sync replaying a month of history
    # in one pass has to reproduce the clusters live ingestion would have
    # built, so a recurrence in week 1 and another in week 4 stay two
    # investigations. Walking a batch in arrival order would instead let the
    # newest alert open a cluster that every older one then joins.
    for alert in sorted(alerts, key=lambda a: a.created_at_source):
        try:
            stats_delta = await _group_one(db, alert, organization_id)
        except Exception:
            logger.exception("Failed to group alert %s; leaving it ungrouped", alert.id)
            continue
        stats["clusters_created"] += stats_delta[0]
        stats["alerts_grouped"] += stats_delta[1]

    return stats


async def _group_one(
    db: AsyncSession,
    alert: NormalizedAlert,
    organization_id: UUID,
) -> tuple[int, int]:
    keys = candidate_keys(alert)
    fingerprints = [digest for _, _, digest in keys]
    event_time = alert.created_at_source

    await _release_lapsed_keys(db, organization_id, fingerprints, event_time)

    cluster = await _find_cluster(db, organization_id, fingerprints, event_time)
    created = 0

    if cluster is None:
        name, _ = _headline(alert, keys)
        cluster = AlertCluster(
            organization_id=organization_id,
            name=name,
            summary="",
            severity=(alert.severity or "medium").lower(),
            status=AlertClusterStatus.OPEN,
            primary_rule_id=alert.rule_id,
            cluster_type="auto_correlated",
            alert_count=0,
            first_alert_at=event_time,
            last_alert_at=event_time,
            common_entities={},
        )
        try:
            async with db.begin_nested():
                db.add(cluster)
                await db.flush()
        except IntegrityError:
            logger.exception("Could not create cluster for alert %s", alert.id)
            return (0, 0)

        # Claim the headline fingerprint under the partial unique index. Losing
        # this race means a concurrent connector sync created the cluster for
        # this same event a moment ago -- which is exactly the cross-source
        # duplicate we are here to catch -- so fall in behind it.
        if not await _add_key(db, cluster, organization_id, keys[0], event_time + _window()):
            await db.delete(cluster)
            await db.flush()
            cluster = await _find_cluster(db, organization_id, fingerprints, event_time)
            if cluster is None:
                return (0, 0)
        else:
            created = 1

    try:
        async with db.begin_nested():
            db.add(
                AlertClusterMember(
                    organization_id=organization_id,
                    cluster_id=cluster.id,
                    alert_id=str(alert.id),
                    similarity_score=1.0,
                )
            )
            await db.flush()
    except IntegrityError:
        # Already a member; a re-sync of the same alert must not double-count.
        return (created, 0)

    # The collapsed alert list shows the cluster's most severe report, ties
    # going to the most recent -- an analyst scanning the list should see the
    # worst thing any product said about this event, not whichever product
    # happened to sync first.
    promotes = cluster.representative_alert_id is None or _severity_rank(
        alert.severity
    ) > _severity_rank(cluster.severity)
    if not promotes and _severity_rank(alert.severity) == _severity_rank(cluster.severity):
        promotes = event_time >= cluster.last_alert_at

    cluster.alert_count += 1
    if event_time < cluster.first_alert_at:
        cluster.first_alert_at = event_time
    if event_time > cluster.last_alert_at:
        cluster.last_alert_at = event_time
    if _severity_rank(alert.severity) > _severity_rank(cluster.severity):
        cluster.severity = (alert.severity or "").lower()
    if cluster.primary_rule_id is None:
        cluster.primary_rule_id = alert.rule_id
    if promotes:
        cluster.representative_alert_id = alert.id

    expires_at = cluster.last_alert_at + _window()
    for key in keys:
        await _add_key(db, cluster, organization_id, key, expires_at)

    # Slide the window on every fingerprint the cluster already owns, so a
    # cluster stays open as long as any of its entities keeps producing alerts.
    await db.execute(
        update(AlertClusterKey)
        .where(
            AlertClusterKey.cluster_id == cluster.id,
            AlertClusterKey.expires_at.is_not(None),
            AlertClusterKey.expires_at < expires_at,
        )
        .values(expires_at=expires_at)
    )

    _summarize(cluster, alert, keys)
    await db.flush()

    return (created, 1)
