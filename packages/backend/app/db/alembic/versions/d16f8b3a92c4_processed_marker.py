"""mark staged ingest rows as processed

Revision ID: d16f8b3a92c4
Revises: c94e1a7b3d52
Create Date: 2026-08-20 18:30:00.000000

The staging buffers had no way to say "this row is done". A drain took a claim
(a lease), processed the row, and left it claimed; 15 minutes later that claim
looked stale -- indistinguishable from a sync that died mid-drain -- so the row
became eligible again. Claims are taken oldest-first, so the same rows were
re-claimed forever while newer messages were never reached, and the retention
purge never fired because every re-claim refreshed ``claimed_at``.

Measured in production on 2026-08-20: 8,000 rows received on 08-17 and 08-18
were still being re-claimed, 23,526 messages from 08-19 and 08-20 had never
been claimed once, and the pending count had grown 13,533 -> 38,321 over two
days while drains ran normally at 2,000 per cycle.

``processed_at`` separates "in flight" from "done": a processed row is never
claimed again, and retention deletes on it. Both buffers share the design and
therefore shared the defect, so both get the column -- the Falco buffer's
volume was simply too low for anyone to notice.

Existing claimed rows are backfilled as processed. They were converted into
alerts on their first pass (many times over, in fact); leaving them unmarked
would let the loop continue for another retention window.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d16f8b3a92c4"
down_revision: str | None = "c94e1a7b3d52"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("syslog_ingest_events", "falco_ingest_events")


def upgrade() -> None:
    for table in TABLES:
        op.add_column(table, sa.Column("processed_at", sa.DateTime(), nullable=True))
        # The claim query filters on processed_at alongside connector_id and
        # orders by received_at.
        op.create_index(
            f"ix_{table}_processed",
            table,
            ["connector_id", "processed_at", "received_at"],
        )
        # Anything already claimed has been through a drain. Mark it done so
        # the re-claim loop stops immediately rather than on the next purge.
        op.execute(
            f"UPDATE {table} SET processed_at = claimed_at WHERE claimed_at IS NOT NULL"  # noqa: S608
        )


def downgrade() -> None:
    for table in TABLES:
        op.drop_index(f"ix_{table}_processed", table_name=table)
        op.drop_column(table, "processed_at")
