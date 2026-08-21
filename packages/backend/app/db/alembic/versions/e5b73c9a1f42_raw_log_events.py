"""raw log storage for directly-ingested sources

Revision ID: e5b73c9a1f42
Revises: d92f5b1c47ae
Create Date: 2026-08-17 17:30:00.000000

Adds ``raw_log_events``: the log lines from sources RevOps ingests directly
(UniFi syslog, the Falco webhook). Panther keeps its own logs in Snowflake, so
this deliberately covers only the sources where nothing else is the system of
record.

Design notes:

* Partitioned by day on ``event_time``. Retention then drops whole partitions
  instead of deleting millions of rows, and time-bounded searches prune to a
  handful of partitions.
* ``search_vector`` is a STORED generated column so full-text search does not
  re-parse the message on every query. It is indexed with GIN per partition.
* BRIN on ``event_time``: the table is append-ordered by time, so a BRIN index
  costs kilobytes where a btree would cost gigabytes.
* Indexes are declared on the parent; Postgres 15 propagates them to existing
  and future partitions automatically.

This creates today's partition plus a week ahead. Ongoing creation and
retention live in app/services/log_store.py, driven by the maintenance hook on
the connector sync loop -- so a gap in that job degrades to "cannot write new
logs", never to silent data loss in another table.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5b73c9a1f42"
down_revision: str | None = "d92f5b1c47ae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Keep in sync with log_store.PARTITION_PRECREATE_DAYS.
INITIAL_PARTITION_DAYS = 7


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE raw_log_events (
            id uuid NOT NULL,
            event_time timestamp without time zone NOT NULL,
            organization_id uuid NOT NULL,
            connector_id uuid NOT NULL,
            source_type varchar(50) NOT NULL,
            received_at timestamp without time zone NOT NULL,
            host varchar(255),
            source_ip varchar(45),
            severity varchar(20),
            message text NOT NULL,
            attributes jsonb,
            search_vector tsvector GENERATED ALWAYS AS (
                to_tsvector('english', message)
            ) STORED,
            PRIMARY KEY (id, event_time)
        ) PARTITION BY RANGE (event_time)
        """
    )

    op.execute(
        "CREATE INDEX ix_raw_log_events_org_time "
        "ON raw_log_events (organization_id, event_time DESC)"
    )
    op.execute(
        "CREATE INDEX ix_raw_log_events_org_source_time "
        "ON raw_log_events (organization_id, source_type, event_time DESC)"
    )
    op.execute("CREATE INDEX ix_raw_log_events_time_brin ON raw_log_events USING BRIN (event_time)")
    op.execute("CREATE INDEX ix_raw_log_events_search ON raw_log_events USING GIN (search_vector)")

    # Today plus a week, so ingestion works before the maintenance job first runs.
    op.execute(
        f"""
        DO $$
        DECLARE
            day date;
        BEGIN
            FOR day IN
                SELECT generate_series(
                    (now() AT TIME ZONE 'UTC')::date - 1,
                    (now() AT TIME ZONE 'UTC')::date + {INITIAL_PARTITION_DAYS},
                    interval '1 day'
                )::date
            LOOP
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF raw_log_events '
                    'FOR VALUES FROM (%L) TO (%L)',
                    'raw_log_events_' || to_char(day, 'YYYYMMDD'),
                    day,
                    day + 1
                );
            END LOOP;
        END $$
        """
    )


def downgrade() -> None:
    # Dropping the parent drops every partition and index with it.
    op.execute("DROP TABLE IF EXISTS raw_log_events CASCADE")


# Keep the linter happy about the unused import in a raw-SQL migration.
_ = sa
