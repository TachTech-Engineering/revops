"""cascade refresh tokens when a user is deleted

Revision ID: c94e1a7b3d52
Revises: b83d2f6c4e17
Create Date: 2026-08-18 17:35:00.000000

refresh_tokens.user_id had no ON DELETE behaviour, so deleting a user raised a
foreign-key violation as soon as they had ever logged in -- which is every real
user. Offboarding and erasure requests both hit it, and the sibling table
password_reset_tokens already cascaded, so this was an inconsistency rather
than a deliberate constraint. A refresh token is worthless without its user.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c94e1a7b3d52"
down_revision: str | None = "b83d2f6c4e17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("refresh_tokens_user_id_fkey", "refresh_tokens", type_="foreignkey")
    op.create_foreign_key(
        "refresh_tokens_user_id_fkey",
        "refresh_tokens",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("refresh_tokens_user_id_fkey", "refresh_tokens", type_="foreignkey")
    op.create_foreign_key(
        "refresh_tokens_user_id_fkey",
        "refresh_tokens",
        "users",
        ["user_id"],
        ["id"],
    )
