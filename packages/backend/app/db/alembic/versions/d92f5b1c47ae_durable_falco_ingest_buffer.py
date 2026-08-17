"""durable falco ingest buffer

Revision ID: d92f5b1c47ae
Revises: c1d4e7f20a83
Create Date: 2026-08-17 10:00:00.000000

Falco alerts pushed to the ingest webhook were held in a process-global
in-memory deque. The endpoint answers 202 Accepted immediately, so with
multiple replicas any pod restart between the webhook call and the next sync
tick (default sync_interval_minutes = 5) silently discarded accepted
runtime-security alerts.

No data migration: the in-memory buffer cannot be read from here, and anything
still resident is lost on the deploy that applies this regardless. Falco
re-sends nothing, so the window is simply accepted.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d92f5b1c47ae"
down_revision: str | None = "c1d4e7f20a83"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "falco_ingest_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["connectors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_falco_ingest_events_organization_id"),
        "falco_ingest_events",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_falco_ingest_events_connector_id"), "falco_ingest_events", ["connector_id"]
    )
    op.create_index(
        "ix_falco_ingest_events_connector_claim",
        "falco_ingest_events",
        ["connector_id", "claimed_at", "received_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_falco_ingest_events_connector_claim", table_name="falco_ingest_events")
    op.drop_index(op.f("ix_falco_ingest_events_connector_id"), table_name="falco_ingest_events")
    op.drop_index(op.f("ix_falco_ingest_events_organization_id"), table_name="falco_ingest_events")
    op.drop_table("falco_ingest_events")
