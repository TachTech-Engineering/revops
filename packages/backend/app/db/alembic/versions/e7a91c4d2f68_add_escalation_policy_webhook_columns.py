"""add escalation_policies webhook columns for pre-baseline databases

Revision ID: e7a91c4d2f68
Revises: bc37e9737b84
Create Date: 2026-08-13 11:05:00.000000

The 2026-02 production database was built by Base.metadata.create_all from a
models.py that predated EscalationPolicy.webhook_secret / webhook_headers, so
it is stamped at the baseline while missing those two columns (verified by
diffing a live pg_dump against the baseline on 2026-08-13; this was the ONLY
divergence across all 76 tables). Databases created by the baseline itself
already have them -- hence ADD COLUMN IF NOT EXISTS, making this a no-op
everywhere except that legacy schema.

webhook_headers carries a server default of '{}' only for backfill parity
with the ORM default (models.py uses default=dict client-side); the column
was empty in production when this was written.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7a91c4d2f68"
down_revision: str | None = "bc37e9737b84"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE escalation_policies "
        "ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(255)"
    )
    op.execute(
        "ALTER TABLE escalation_policies "
        "ADD COLUMN IF NOT EXISTS webhook_headers JSON NOT NULL DEFAULT '{}'::json"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE escalation_policies DROP COLUMN IF EXISTS webhook_headers")
    op.execute("ALTER TABLE escalation_policies DROP COLUMN IF EXISTS webhook_secret")
