"""drop on-call scheduler tables (feature removed)

Revision ID: f4b82d5c9a13
Revises: e7a91c4d2f68
Create Date: 2026-08-13 12:00:00.000000

The on-call scheduler (schedules, rotation members, overrides, shift
handoffs) was removed 2026-08-13: SIEM-class products integrate with
dedicated on-call tools (PagerDuty/Opsgenie via the escalation policies'
webhook channel) rather than owning rotation scheduling, and every one of
these tables had zero rows after six months in production. Escalation
policies remain; only the never-wired use_oncall_schedule/oncall_schedule_id
fields are dropped from escalation_steps (escalation_service never read
them).

The downgrade recreates the empty structures exactly as the baseline
(bc37e9737b84) defined them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f4b82d5c9a13"
down_revision: str | None = "e7a91c4d2f68"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index(op.f("ix_oncall_members_schedule_order"), table_name="oncall_rotation_members")
    op.drop_index(
        op.f("ix_oncall_rotation_members_schedule_id"), table_name="oncall_rotation_members"
    )
    op.drop_table("oncall_rotation_members")

    op.drop_index(op.f("ix_oncall_overrides_organization_id"), table_name="oncall_overrides")
    op.drop_index(op.f("ix_oncall_overrides_schedule_id"), table_name="oncall_overrides")
    op.drop_table("oncall_overrides")

    op.drop_index(op.f("ix_oncall_schedules_organization_id"), table_name="oncall_schedules")
    op.drop_table("oncall_schedules")

    op.drop_index(op.f("ix_shift_handoffs_organization_id"), table_name="shift_handoffs")
    op.drop_table("shift_handoffs")

    sa.Enum(name="rotationtype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="oncallrole").drop(op.get_bind(), checkfirst=True)

    op.drop_column("escalation_steps", "use_oncall_schedule")
    op.drop_column("escalation_steps", "oncall_schedule_id")


def downgrade() -> None:
    op.add_column(
        "escalation_steps",
        sa.Column("use_oncall_schedule", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "escalation_steps",
        sa.Column("oncall_schedule_id", sa.UUID(), nullable=True),
    )

    op.create_table(
        "oncall_schedules",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("timezone", sa.String(length=50), nullable=False),
        sa.Column(
            "rotation_type",
            sa.Enum("DAILY", "WEEKLY", "CUSTOM", name="rotationtype"),
            nullable=False,
        ),
        sa.Column("handoff_time", sa.String(length=10), nullable=False),
        sa.Column("handoff_day", sa.Integer(), nullable=True),
        sa.Column("rotation_length_days", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_oncall_schedules_organization_id"),
        "oncall_schedules",
        ["organization_id"],
        unique=False,
    )

    op.create_table(
        "oncall_rotation_members",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("schedule_id", sa.UUID(), nullable=False),
        sa.Column("user_email", sa.String(length=255), nullable=False),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        sa.Column("rotation_order", sa.Integer(), nullable=False),
        sa.Column("role", sa.Enum("PRIMARY", "BACKUP", name="oncallrole"), nullable=False),
        sa.Column("phone_number", sa.String(length=50), nullable=True),
        sa.Column("slack_user_id", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["schedule_id"], ["oncall_schedules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_oncall_rotation_members_schedule_id"),
        "oncall_rotation_members",
        ["schedule_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oncall_members_schedule_order"),
        "oncall_rotation_members",
        ["schedule_id", "rotation_order"],
        unique=False,
    )

    op.create_table(
        "oncall_overrides",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("schedule_id", sa.UUID(), nullable=False),
        sa.Column("override_user_email", sa.String(length=255), nullable=False),
        sa.Column("original_user_email", sa.String(length=255), nullable=True),
        sa.Column("start_time", sa.DateTime(), nullable=False),
        sa.Column("end_time", sa.DateTime(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_oncall_overrides_organization_id"),
        "oncall_overrides",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_oncall_overrides_schedule_id"), "oncall_overrides", ["schedule_id"], unique=False
    )

    op.create_table(
        "shift_handoffs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("shift_date", sa.DateTime(), nullable=False),
        sa.Column("outgoing_analyst", sa.String(length=255), nullable=False),
        sa.Column("incoming_analyst", sa.String(length=255), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("ongoing_investigations", sa.JSON(), nullable=False),
        sa.Column("priority_items", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("open_alerts_count", sa.Integer(), nullable=False),
        sa.Column("open_cases_count", sa.Integer(), nullable=False),
        sa.Column("critical_alerts_count", sa.Integer(), nullable=False),
        sa.Column("is_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_shift_handoffs_organization_id"),
        "shift_handoffs",
        ["organization_id"],
        unique=False,
    )
