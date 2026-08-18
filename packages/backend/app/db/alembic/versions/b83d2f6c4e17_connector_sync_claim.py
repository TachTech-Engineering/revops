"""cross-replica sync claim for connectors

Revision ID: b83d2f6c4e17
Revises: a71c3e8d5b09
Create Date: 2026-08-18 17:20:00.000000

The connector sync scheduler runs on every backend replica and guarded against
double-syncing with a process-local set, which replicas do not share. All three
could therefore see the same connector as due and sync it at the same time,
multiplying the API calls made to Panther and every other source by the replica
count.

``sync_claimed_at`` is the lease a replica takes before syncing: the UPDATE is
atomic, so exactly one replica wins. It is deliberately separate from
``last_sync_at``, which is the sync *window start* -- writing that at claim time
would make each sync fetch from "now" and silently skip every alert since the
previous run.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b83d2f6c4e17"
down_revision: str | None = "a71c3e8d5b09"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("connectors", sa.Column("sync_claimed_at", sa.DateTime(), nullable=True))
    # The claim query filters on it alongside the due-ness check.
    op.create_index(
        "ix_connectors_sync_claimed_at",
        "connectors",
        ["sync_claimed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_connectors_sync_claimed_at", table_name="connectors")
    op.drop_column("connectors", "sync_claimed_at")
