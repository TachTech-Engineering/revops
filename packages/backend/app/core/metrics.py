"""
Operational metrics, in Prometheus text format.

Nothing watched this platform. Every fault found during the 2026-08 hardening
was found by a person going and looking, and the two most expensive ones were
invisible precisely because they were silent:

* Syslog messages buffered on a replica that never drained them -- the sync
  reported success having found nothing, for a day.
* The staging buffer livelocked, re-processing the same 8,000 rows for two
  days while 23,526 newer messages were never touched and the queue grew from
  13,533 to 38,321.

Both would have been a single obvious line on a graph. The metrics here are
chosen from what actually broke, not from what is easy to export.

Every value is a gauge derived from database state and computed on scrape.
They are deliberately aggregate: no organization ids, no connector names, no
message content. ``/metrics`` is unauthenticated because Google Managed
Prometheus scrapes the pod directly, so it must never carry tenant data. It is
also not reachable from outside the cluster -- the ingress routes ``/api/*`` to
this service and everything else to the frontend.
"""

import logging
import time

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Scrapes are frequent and some of these queries touch whole tables, so results
# are reused briefly. Well under a typical 30s scrape interval, so a graph
# still moves at the resolution the scrape provides.
_CACHE_SECONDS = 10
_cache: dict[str, object] = {"at": 0.0, "body": ""}


def _line(name: str, value: float, labels: dict[str, str] | None = None) -> str:
    if not labels:
        return f"{name} {value}"
    rendered = ",".join(
        # Escape per the Prometheus exposition format: backslash, quote, newline.
        '{}="{}"'.format(
            k,
            str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n"),
        )
        for k, v in sorted(labels.items())
    )
    return f"{name}{{{rendered}}} {value}"


async def _scalar(db: AsyncSession, sql: str, default: float = 0.0) -> float:
    try:
        result = (await db.execute(text(sql))).scalar()
        return float(result) if result is not None else default
    except Exception:
        # A metric that cannot be computed must not fail the scrape: a blind
        # exporter is bad, an exporter that 500s takes the whole endpoint down.
        logger.exception("metric query failed: %s", sql.strip().split("\n")[0][:80])
        return default


async def render(db: AsyncSession) -> str:
    """Build the exposition payload."""
    now = time.monotonic()
    if now - float(_cache["at"]) < _CACHE_SECONDS and _cache["body"]:
        return str(_cache["body"])

    out: list[str] = []

    def emit(name: str, help_text: str, kind: str, samples: list[tuple[float, dict | None]]):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        for value, labels in samples:
            out.append(_line(name, value, labels))

    # --- Ingest staging buffers -------------------------------------------
    # THE metric. Depth alone would not have caught the livelock (it grew
    # slowly), but depth plus oldest-age would have screamed on day one.
    buffers = []
    ages = []
    for buffer_name, table in (
        ("syslog", "syslog_ingest_events"),
        ("falco", "falco_ingest_events"),
    ):
        pending = await _scalar(
            db,
            f"SELECT count(*) FROM {table} WHERE processed_at IS NULL",  # noqa: S608
        )
        oldest = await _scalar(
            db,
            f"""SELECT COALESCE(EXTRACT(EPOCH FROM (now() AT TIME ZONE 'UTC'
                 - min(received_at))), 0)
                FROM {table} WHERE processed_at IS NULL""",  # noqa: S608
        )
        buffers.append((pending, {"buffer": buffer_name}))
        ages.append((oldest, {"buffer": buffer_name}))

    emit(
        "revops_ingest_pending",
        "Staged ingest rows not yet processed.",
        "gauge",
        buffers,
    )
    emit(
        "revops_ingest_oldest_pending_seconds",
        "Age of the oldest unprocessed staged row. Rises without bound if a drain stalls.",
        "gauge",
        ages,
    )

    # --- Raw log store -----------------------------------------------------
    # The size cap silently read 0 for its first days because it measured the
    # partitioned parent. Exporting it means the next such mistake is visible.
    from app.services import log_store

    stored = await _scalar(
        db,
        """SELECT COALESCE(sum(pg_total_relation_size(relid)), 0)
           FROM pg_partition_tree('raw_log_events')""",
    )
    partitions = await _scalar(
        db,
        """SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent
           WHERE p.relname = 'raw_log_events'""",
    )
    emit(
        "revops_log_store_bytes", "Raw log store size including indexes.", "gauge", [(stored, None)]
    )
    emit(
        "revops_log_store_max_bytes",
        "Ceiling past which raw log ingestion is refused.",
        "gauge",
        [(float(log_store.MAX_STORED_BYTES), None)],
    )
    emit(
        "revops_log_partitions",
        "Day partitions on raw_log_events. Zero ahead of today means ingestion is about to fail.",
        "gauge",
        [(partitions, None)],
    )

    # --- Connector freshness ----------------------------------------------
    # A connector that stops syncing is invisible today: the loop keeps
    # running and reports success. Labelled by type, never by name.
    try:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT connector_type,
                           COALESCE(EXTRACT(EPOCH FROM (now() AT TIME ZONE 'UTC'
                             - max(last_sync_at))), -1) AS age
                    FROM connectors
                    WHERE category = 'DATA_SOURCE' AND status = 'CONNECTED'
                    GROUP BY connector_type
                    """
                )
            )
        ).all()
    except Exception:
        logger.exception("connector freshness query failed")
        rows = []
    emit(
        "revops_connector_seconds_since_sync",
        "Seconds since a connector type last completed a sync. -1 means it never has.",
        "gauge",
        [(float(age), {"connector_type": str(ctype)}) for ctype, age in rows],
    )

    # --- Alert flow --------------------------------------------------------
    # "Zero UniFi alerts for six hours" was true for a day and nobody knew.
    try:
        alert_rows = (
            await db.execute(
                text(
                    """
                    SELECT source_type, count(*)
                    FROM normalized_alerts
                    WHERE ingested_at > (now() AT TIME ZONE 'UTC') - interval '1 hour'
                    GROUP BY source_type
                    """
                )
            )
        ).all()
    except Exception:
        logger.exception("alert flow query failed")
        alert_rows = []
    emit(
        "revops_alerts_ingested_1h",
        "Alerts ingested in the last hour, by source.",
        "gauge",
        [(float(count), {"source_type": str(src)}) for src, count in alert_rows],
    )

    # --- Storage -----------------------------------------------------------
    db_bytes = await _scalar(db, "SELECT pg_database_size(current_database())")
    emit(
        "revops_database_bytes",
        "Database size. Shares a volume with the log store.",
        "gauge",
        [(db_bytes, None)],
    )

    emit("revops_up", "1 when the exporter completed a scrape.", "gauge", [(1, None)])

    body = "\n".join(out) + "\n"
    _cache["at"] = now
    _cache["body"] = body
    return body
