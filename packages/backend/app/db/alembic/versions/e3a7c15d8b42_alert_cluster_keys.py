"""cross-source alert grouping keys

Revision ID: e3a7c15d8b42
Revises: a3c9e81f5d27
Create Date: 2026-09-24 10:00:00.000000

``uq_normalized_alerts_org_connector_external`` deduplicates within one
connector, which is all it can do: the external_id it keys on is the source
product's own alert id and means nothing outside that product. When two SIEMs
watch the same estate -- CrowdStrike and Sentinel on the same hosts, Okta and
Entra on the same directory -- one real event becomes one alert per product,
and the analyst works the same incident several times over.

``alert_cluster_keys`` holds the fingerprints that route an incoming alert to
an existing AlertCluster: one row per (entity, signature) pair the cluster has
seen, so an alert joins on any entity it shares with the cluster rather than
only on the one that named it. See app.services.alert_grouping.

The partial unique index is the load-bearing part. Connectors sync
concurrently and cross-source duplicates arrive on *different* connectors by
definition, so two syncs racing to cluster the same event is the ordinary case
here rather than an edge case, and a check-then-insert in the sync path cannot
settle it. With at most one active cluster per fingerprint per org, the loser
of that race gets an IntegrityError and attaches to the winner's cluster.

It is partial on ``expires_at IS NOT NULL`` because the window is a sliding
one: a lapsed key is released to NULL and stops routing, leaving the next alert
with that fingerprint free to start a fresh cluster -- the same brute force
against the same host next month is a new investigation. Released rows are kept
as the cluster's provenance, and NULLs are outside the index so any number of
them can accumulate.

``alert_clusters.representative_alert_id`` names the member that stands in for
the cluster when the alert list is collapsed. Storing it makes collapsing an
equality join on one column; deriving it per request would be a DISTINCT ON
over every member row in the org on every page load.

No backfill. Existing alerts stay ungrouped and keep listing individually
(collapse only hides members of a cluster, so an alert in no cluster is always
shown); the manual POST /alert-clusters/generate still covers retro-clustering
history.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e3a7c15d8b42"
down_revision: str | None = "a3c9e81f5d27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "alert_clusters",
        sa.Column("representative_alert_id", sa.UUID(), nullable=True),
    )
    op.create_table(
        "alert_cluster_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("cluster_id", sa.UUID(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("entity_kind", sa.String(length=32), nullable=False),
        sa.Column("entity_value", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["cluster_id"], ["alert_clusters.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_alert_cluster_keys_organization_id"),
        "alert_cluster_keys",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_alert_cluster_keys_cluster_id"),
        "alert_cluster_keys",
        ["cluster_id"],
    )
    op.create_index(
        "ix_alert_cluster_keys_org_fingerprint",
        "alert_cluster_keys",
        ["organization_id", "fingerprint"],
    )
    op.create_index(
        "uq_alert_cluster_keys_active",
        "alert_cluster_keys",
        ["organization_id", "fingerprint"],
        unique=True,
        postgresql_where=sa.text("expires_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_alert_cluster_keys_active", table_name="alert_cluster_keys")
    op.drop_index("ix_alert_cluster_keys_org_fingerprint", table_name="alert_cluster_keys")
    op.drop_index(op.f("ix_alert_cluster_keys_cluster_id"), table_name="alert_cluster_keys")
    op.drop_index(op.f("ix_alert_cluster_keys_organization_id"), table_name="alert_cluster_keys")
    op.drop_table("alert_cluster_keys")
    op.drop_column("alert_clusters", "representative_alert_id")
