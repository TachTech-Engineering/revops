"""durable staging for received syslog messages

Revision ID: a71c3e8d5b09
Revises: e5b73c9a1f42
Create Date: 2026-08-17 20:05:00.000000

Syslog messages were buffered in a process-local dict. Datagrams are
load-balanced across every backend replica while ``last_sync_at`` is a single
row, so the replica that ran the sync drained its own (usually empty) buffer
and marked the connector done -- and the replica actually holding the messages
skipped. Nothing was written down, so those messages and the alerts they would
have become were lost silently.

Same shape as ``falco_ingest_events``, which solved this exact problem for the
Falco webhook: any replica can drain what any other replica received.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a71c3e8d5b09"
down_revision: str | None = "e5b73c9a1f42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "syslog_ingest_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
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
    # The drain filters on connector_id + claimed_at and orders by received_at.
    op.create_index(
        "ix_syslog_ingest_events_connector_claim",
        "syslog_ingest_events",
        ["connector_id", "claimed_at", "received_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_syslog_ingest_events_connector_claim", table_name="syslog_ingest_events")
    op.drop_index("ix_syslog_ingest_events_connector_id", table_name="syslog_ingest_events")
    op.drop_index("ix_syslog_ingest_events_organization_id", table_name="syslog_ingest_events")
    op.drop_table("syslog_ingest_events")
