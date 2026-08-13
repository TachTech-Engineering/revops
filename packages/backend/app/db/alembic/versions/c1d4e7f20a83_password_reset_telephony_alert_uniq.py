"""password reset tokens, per-org telephony config, alert dedupe constraint

Revision ID: c1d4e7f20a83
Revises: f4b82d5c9a13
Create Date: 2026-08-13 22:30:00.000000

Three schema changes from the bug-bash backlog:

1. ``password_reset_tokens`` -- reset tokens lived in a module-level dict, so
   with multiple replicas a token minted on one pod was rejected by the others
   and all tokens were lost on restart. Only the hash is stored.

2. ``organization_telephony_config`` -- Fonoster credentials were held in a
   process-global singleton, so one tenant's carrier account overwrote
   another's and escalation calls dialled out under the wrong identity.

3. Unique index on ``normalized_alerts (organization_id, connector_id,
   external_id)`` -- the connector sync does a check-then-insert, so two
   overlapping syncs both miss the check and duplicate the alert.

   The upgrade DELETES pre-existing duplicates before creating the index,
   keeping the earliest ingested row of each group. Without that the index
   creation fails on any database that has already accumulated duplicates,
   which the production database very likely has (the sync has been running
   unguarded with a 60s scheduler tick).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1d4e7f20a83"
down_revision: str | None = "f4b82d5c9a13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_password_reset_tokens_user_id"), "password_reset_tokens", ["user_id"])
    op.create_index(
        op.f("ix_password_reset_tokens_token_hash"),
        "password_reset_tokens",
        ["token_hash"],
        unique=True,
    )

    op.create_table(
        "organization_telephony_config",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("api_endpoint", sa.String(length=255), nullable=False),
        sa.Column("access_key_id", sa.String(length=255), nullable=False),
        sa.Column("access_key_secret_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("default_caller_id", sa.String(length=50), nullable=False),
        sa.Column("tts_voice", sa.String(length=50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_organization_telephony_config_organization_id"),
        "organization_telephony_config",
        ["organization_id"],
    )
    op.create_index(
        "ix_org_telephony_org", "organization_telephony_config", ["organization_id"], unique=True
    )

    # Drop duplicate alerts before enforcing uniqueness, keeping the earliest
    # ingested row per (org, connector, external_id).
    op.execute(
        """
        DELETE FROM normalized_alerts a
        USING normalized_alerts b
        WHERE a.organization_id = b.organization_id
          AND a.connector_id = b.connector_id
          AND a.external_id = b.external_id
          AND (a.ingested_at, a.id) > (b.ingested_at, b.id)
        """
    )
    op.create_index(
        "uq_normalized_alerts_org_connector_external",
        "normalized_alerts",
        ["organization_id", "connector_id", "external_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_normalized_alerts_org_connector_external", table_name="normalized_alerts")

    op.drop_index("ix_org_telephony_org", table_name="organization_telephony_config")
    op.drop_index(
        op.f("ix_organization_telephony_config_organization_id"),
        table_name="organization_telephony_config",
    )
    op.drop_table("organization_telephony_config")

    op.drop_index(op.f("ix_password_reset_tokens_token_hash"), table_name="password_reset_tokens")
    op.drop_index(op.f("ix_password_reset_tokens_user_id"), table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")
