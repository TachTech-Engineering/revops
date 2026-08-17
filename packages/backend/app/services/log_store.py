"""
Raw log storage and search.

Covers the sources RevOps ingests directly and is the system of record for --
UniFi syslog and the Falco webhook. Panther retains its own logs in Snowflake
(see the IOC search path), so those are deliberately not duplicated here.

Three properties matter more than features:

* **It must not be able to take the application down.** Logs share a volume
  with the operational database, and log volume is orders of magnitude larger
  than alert volume. Ingestion is therefore capped: past ``MAX_STORED_BYTES``
  the store refuses writes and says so, rather than filling the disk.
* **Retention is a partition drop, not a DELETE.** The table is append-only and
  partitioned by day, so expiring data is instant and leaves no bloat.
* **Every read is organization-scoped in SQL, from the caller's authenticated
  session.** Logs are the most sensitive data in the product; the org filter is
  never taken from request input, and every value is a bind parameter.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.time_utils import utcnow

logger = logging.getLogger(__name__)

# Days of partitions to keep ahead of "now" so ingestion never lands on a
# missing partition between maintenance runs. Mirrored in the migration.
PARTITION_PRECREATE_DAYS = 7

# Hard ceiling on the whole table, including indexes. The operational database
# lives on the same 10Gi volume, so this exists to make "logs filled the disk"
# impossible rather than merely unlikely. Raise it together with the PVC.
MAX_STORED_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB

# Bound on a single search response, whatever the caller asks for.
MAX_SEARCH_LIMIT = 1000


@dataclass
class LogEvent:
    """One log line on its way into the store."""

    organization_id: UUID
    connector_id: UUID
    source_type: str
    event_time: datetime
    message: str
    host: str | None = None
    source_ip: str | None = None
    severity: str | None = None
    attributes: dict[str, Any] | None = None


def retention_days() -> int:
    return max(1, int(getattr(settings, "log_retention_days", 14)))


async def stored_bytes(db: AsyncSession) -> int:
    """Total size of the log table including partitions and indexes.

    Summed over the partition tree, not taken from the parent: a partitioned
    parent holds no rows, so ``pg_total_relation_size('raw_log_events')`` is
    always 0 and would silently disable the ceiling below.
    """
    result = await db.execute(
        text(
            """
            SELECT COALESCE(sum(pg_total_relation_size(relid)), 0)
            FROM pg_partition_tree('raw_log_events')
            """
        )
    )
    return int(result.scalar() or 0)


async def organization_for_connector(db: AsyncSession, connector_id: UUID) -> UUID | None:
    """Look up a connector's organization.

    Data-source connectors are constructed with an id and config but no
    organization, and log rows must carry one -- a log the search can never
    scope to a tenant is a log nobody can read.
    """
    result = await db.execute(
        text("SELECT organization_id FROM connectors WHERE id = :cid"), {"cid": connector_id}
    )
    return result.scalar()


def _partitionable(event: LogEvent) -> tuple[datetime, dict[str, Any] | None]:
    """Pin an event to a time a partition actually exists for.

    Syslog timestamps come from the sending device's clock, and skewed or
    unset clocks are routine -- a device reporting 1970 or 2035 would land
    outside every partition and the line would be dropped. Such an event is
    filed at receipt time instead, with the value the device claimed preserved
    in ``attributes`` so the skew stays visible rather than being laundered.
    """
    now = utcnow()
    floor = now - timedelta(days=retention_days())
    ceiling = now + timedelta(days=PARTITION_PRECREATE_DAYS)

    if floor <= event.event_time <= ceiling:
        return event.event_time, event.attributes

    attributes = dict(event.attributes or {})
    attributes["reported_event_time"] = event.event_time.isoformat()
    attributes["event_time_source"] = "receipt (device clock out of range)"
    return now, attributes


async def store_events(db: AsyncSession, events: list[LogEvent]) -> int:
    """Persist log lines. Returns the number stored.

    Refuses the batch when the table is at its ceiling: dropping logs is
    recoverable, filling the shared volume is not. Never raises on a storage
    problem -- log retention must not be able to fail an ingest request that
    has already been accepted.
    """
    if not events:
        return 0

    prepared = [(e, *_partitionable(e)) for e in events]

    try:
        if await stored_bytes(db) >= MAX_STORED_BYTES:
            logger.warning(
                "Raw log store is at its %d byte ceiling; dropping %d event(s). "
                "Lower LOG_RETENTION_DAYS or grow the volume.",
                MAX_STORED_BYTES,
                len(events),
            )
            return 0

        # SAVEPOINT, so a failed insert rolls back only these rows. Callers
        # store logs inside the transaction that also writes the alert and
        # commit afterwards; without this, one log line for an unpartitioned
        # day aborts that transaction and the caller's commit fails too --
        # losing the alert to protect a log line.
        async with db.begin_nested():
            await db.execute(
                text(
                    """
                INSERT INTO raw_log_events (
                    id, event_time, organization_id, connector_id, source_type,
                    received_at, host, source_ip, severity, message, attributes
                ) VALUES (
                    gen_random_uuid(), :event_time, :organization_id, :connector_id,
                    :source_type, :received_at, :host, :source_ip, :severity,
                    :message, CAST(:attributes AS jsonb)
                )
                """
                ),
                [
                    {
                        "event_time": event_time,
                        "organization_id": e.organization_id,
                        "connector_id": e.connector_id,
                        "source_type": e.source_type[:50],
                        "received_at": utcnow(),
                        # Clamped to the column widths: an over-long hostname
                        # from a misbehaving device must not reject the batch.
                        "host": (e.host or None) and e.host[:255],
                        "source_ip": (e.source_ip or None) and e.source_ip[:45],
                        "severity": (e.severity or None) and e.severity[:20],
                        "message": e.message,
                        "attributes": json.dumps(attributes or {}, default=str),
                    }
                    for e, event_time, attributes in prepared
                ],
            )
        return len(events)
    except Exception:
        # A missing partition or a full disk must not fail the caller's
        # request: the alert derived from these lines is the important part.
        logger.exception("Failed to store %d raw log event(s)", len(events))
        return 0


async def search_logs(
    db: AsyncSession,
    organization_id: UUID,
    start: datetime,
    end: datetime,
    query: str | None = None,
    source_type: str | None = None,
    host: str | None = None,
    connector_id: UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Search one organization's logs. Returns (rows, total_matching).

    ``organization_id`` comes from the caller's session, never from request
    input, and is applied in SQL rather than filtered afterwards. Free text goes
    through ``websearch_to_tsquery``, which accepts user phrasing and cannot
    produce a syntax error the way ``to_tsquery`` can.
    """
    limit = max(1, min(int(limit), MAX_SEARCH_LIMIT))
    offset = max(0, int(offset))

    where = [
        "organization_id = :org_id",
        "event_time >= :start",
        "event_time < :end",
    ]
    params: dict[str, Any] = {"org_id": organization_id, "start": start, "end": end}

    if query:
        where.append("search_vector @@ websearch_to_tsquery('english', :q)")
        params["q"] = query
    if source_type:
        where.append("source_type = :source_type")
        params["source_type"] = source_type
    if host:
        where.append("host = :host")
        params["host"] = host
    if connector_id:
        where.append("connector_id = :connector_id")
        params["connector_id"] = connector_id

    clause = " AND ".join(where)

    total = (
        await db.execute(text(f"SELECT count(*) FROM raw_log_events WHERE {clause}"), params)
    ).scalar() or 0

    rows = (
        (
            await db.execute(
                text(
                    f"""
                SELECT id, event_time, received_at, source_type, connector_id,
                       host, source_ip, severity, message, attributes
                FROM raw_log_events
                WHERE {clause}
                ORDER BY event_time DESC
                LIMIT :limit OFFSET :offset
                """
                ),
                {**params, "limit": limit, "offset": offset},
            )
        )
        .mappings()
        .all()
    )

    return [dict(r) for r in rows], int(total)


async def ensure_partitions(db: AsyncSession, days_ahead: int = PARTITION_PRECREATE_DAYS) -> int:
    """Create the day partitions ingestion will need. Returns how many were made."""
    created = 0
    today = utcnow().date()
    for offset in range(days_ahead + 1):
        day = today + timedelta(days=offset)
        name = f"raw_log_events_{day.strftime('%Y%m%d')}"
        result = await db.execute(
            text("SELECT to_regclass(:name) IS NOT NULL"), {"name": f"public.{name}"}
        )
        if result.scalar():
            continue
        # Identifiers cannot be bound, so they are built from a formatted date
        # rather than any caller-supplied value.
        await db.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF raw_log_events "
                f"FOR VALUES FROM ('{day}') TO ('{day + timedelta(days=1)}')"
            )
        )
        created += 1
    return created


async def drop_expired_partitions(db: AsyncSession, keep_days: int | None = None) -> list[str]:
    """Drop partitions older than the retention window. Returns their names."""
    keep = keep_days if keep_days is not None else retention_days()
    cutoff = utcnow().date() - timedelta(days=keep)

    names = (
        (
            await db.execute(
                text(
                    """
                SELECT c.relname
                FROM pg_class c
                JOIN pg_inherits i ON i.inhrelid = c.oid
                JOIN pg_class p ON p.oid = i.inhparent
                WHERE p.relname = 'raw_log_events'
                ORDER BY c.relname
                """
                )
            )
        )
        .scalars()
        .all()
    )

    dropped = []
    for name in names:
        suffix = name.rsplit("_", 1)[-1]
        try:
            day = datetime.strptime(suffix, "%Y%m%d").date()
        except ValueError:
            continue
        if day < cutoff:
            await db.execute(text(f"DROP TABLE IF EXISTS {name}"))
            dropped.append(name)
    return dropped
