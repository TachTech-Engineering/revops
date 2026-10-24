"""drop syslog staging (UniFi connectors removed)

Revision ID: b8d4f1a6c3e2
Revises: a3c9e81f5d27
Create Date: 2026-10-23 12:00:00.000000

The UniFi connectors (API and syslog) were removed 2026-10-23, and with them
the UDP/TCP syslog listener, which UniFi was the only consumer of. Its public
load balancers accepted datagrams from 0.0.0.0/0; dropping ingestion closes
that exposure rather than allowlisting senders.

syslog_ingest_events only ever held transient, already-drained messages, so it
is dropped outright. Existing unifi/unifi_api/unifi_syslog connector rows are
disabled rather than deleted: deleting a connector cascades its raw log
history, and the alerts they produced stay meaningful. Remove them from the
Connectors page once that history is no longer needed.

The downgrade recreates the empty table as a71c3e8d5b09 + d16f8b3a92c4 left
it; it does not re-enable the connectors.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b8d4f1a6c3e2"
down_revision: str | None = "a3c9e81f5d27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE connectors SET sync_enabled = false "
        "WHERE connector_type IN ('unifi', 'unifi_api', 'unifi_syslog')"
    )

    op.drop_index("ix_syslog_ingest_events_processed", table_name="syslog_ingest_events")
    op.drop_index("ix_syslog_ingest_events_connector_claim", table_name="syslog_ingest_events")
    op.drop_index("ix_syslog_ingest_events_connector_id", table_name="syslog_ingest_events")
    op.drop_index("ix_syslog_ingest_events_organization_id", table_name="syslog_ingest_events")
    op.drop_table("syslog_ingest_events")


def downgrade() -> None:
    op.create_table(
        "syslog_ingest_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["connectors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_syslog_ingest_events_organization_id",
        "syslog_ingest_events",
        ["organization_id"],
    )
    op.create_index(
        "ix_syslog_ingest_events_connector_id",
        "syslog_ingest_events",
        ["connector_id"],
    )
    op.create_index(
        "ix_syslog_ingest_events_connector_claim",
        "syslog_ingest_events",
        ["connector_id", "claimed_at", "received_at"],
    )
    op.create_index(
        "ix_syslog_ingest_events_processed",
        "syslog_ingest_events",
        ["connector_id", "processed_at", "received_at"],
    )
