"""cnapp assets, attack paths, cve enrichment, generic ingest buffer

Revision ID: a3c9e81f5d27
Revises: d92f5b1c47ae
Create Date: 2026-08-21 10:00:00.000000

Adds the CNAPP layer: a cloud asset inventory (cloud_assets,
asset_relationships, asset_alert_links) populated from Prowler/Trivy/Falco
findings and bulk inventory imports; toxic-combination findings
(attack_path_findings); CVE exploitability enrichment (cve_enrichment,
EPSS + CISA KEV); and a generic webhook ingest buffer (ingest_events) for
push-based connectors added after Falco (Trivy today).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "a3c9e81f5d27"
down_revision: str | None = "d92f5b1c47ae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ASSET_TYPE_ENUM = sa.Enum(
    "HOST",
    "VM_INSTANCE",
    "CONTAINER",
    "CONTAINER_IMAGE",
    "K8S_POD",
    "K8S_NAMESPACE",
    "K8S_CLUSTER",
    "CLOUD_ACCOUNT",
    "STORAGE_BUCKET",
    "DATABASE",
    "IAM_IDENTITY",
    "IAM_ROLE",
    "NETWORK",
    "SERVERLESS_FUNCTION",
    "LOAD_BALANCER",
    "SERVICE",
    "OTHER",
    name="assettype",
)
ATTACK_PATH_STATUS_ENUM = sa.Enum("OPEN", "RESOLVED", "DISMISSED", name="attackpathstatus")


def upgrade() -> None:
    op.create_table(
        "ingest_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column("connector_type", sa.String(length=50), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["connectors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ingest_events_organization_id"), "ingest_events", ["organization_id"]
    )
    op.create_index(op.f("ix_ingest_events_connector_id"), "ingest_events", ["connector_id"])
    op.create_index(
        "ix_ingest_events_connector_claim",
        "ingest_events",
        ["connector_id", "claimed_at", "received_at"],
    )

    op.create_table(
        "cve_enrichment",
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("in_kev", sa.Boolean(), nullable=False),
        sa.Column("kev_date_added", sa.DateTime(), nullable=True),
        sa.Column("kev_ransomware", sa.Boolean(), nullable=False),
        sa.Column("kev_vulnerability_name", sa.String(length=500), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_index(op.f("ix_cve_enrichment_in_kev"), "cve_enrichment", ["in_kev"])

    op.create_table(
        "cloud_assets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("external_id", sa.String(length=1000), nullable=False),
        sa.Column("asset_type", ASSET_TYPE_ENUM, nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=True),
        sa.Column("account_id", sa.String(length=255), nullable=True),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column("internet_exposed", sa.Boolean(), nullable=False),
        sa.Column("criticality", sa.Integer(), nullable=False),
        sa.Column("data_classification", sa.String(length=100), nullable=True),
        sa.Column("labels", JSONB(), nullable=False),
        sa.Column("attrs", JSONB(), nullable=False),
        sa.Column("sources", JSONB(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_cloud_assets_organization_id"), "cloud_assets", ["organization_id"]
    )
    op.create_index(
        op.f("ix_cloud_assets_internet_exposed"), "cloud_assets", ["internet_exposed"]
    )
    op.create_index(
        "uq_cloud_assets_org_external",
        "cloud_assets",
        ["organization_id", "external_id"],
        unique=True,
    )
    op.create_index("ix_cloud_assets_org_type", "cloud_assets", ["organization_id", "asset_type"])

    op.create_table(
        "asset_relationships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("source_asset_id", sa.UUID(), nullable=False),
        sa.Column("target_asset_id", sa.UUID(), nullable=False),
        sa.Column("relationship_type", sa.String(length=50), nullable=False),
        sa.Column("attrs", JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["source_asset_id"], ["cloud_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_asset_id"], ["cloud_assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_asset_relationships_organization_id"),
        "asset_relationships",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_asset_relationships_source_asset_id"),
        "asset_relationships",
        ["source_asset_id"],
    )
    op.create_index(
        op.f("ix_asset_relationships_target_asset_id"),
        "asset_relationships",
        ["target_asset_id"],
    )
    op.create_index(
        "uq_asset_relationships_edge",
        "asset_relationships",
        ["organization_id", "source_asset_id", "target_asset_id", "relationship_type"],
        unique=True,
    )

    op.create_table(
        "asset_alert_links",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["cloud_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_id"], ["normalized_alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_asset_alert_links_organization_id"), "asset_alert_links", ["organization_id"]
    )
    op.create_index(op.f("ix_asset_alert_links_asset_id"), "asset_alert_links", ["asset_id"])
    op.create_index(op.f("ix_asset_alert_links_alert_id"), "asset_alert_links", ["alert_id"])
    op.create_index(
        "uq_asset_alert_links_pair",
        "asset_alert_links",
        ["asset_id", "alert_id"],
        unique=True,
    )

    op.create_table(
        "attack_path_findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("rule_key", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=1000), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", ATTACK_PATH_STATUS_ENUM, nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("path", JSONB(), nullable=False),
        sa.Column("alert_ids", JSONB(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("first_detected", sa.DateTime(), nullable=False),
        sa.Column("last_evaluated", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["cloud_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_attack_path_findings_organization_id"),
        "attack_path_findings",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_attack_path_findings_asset_id"), "attack_path_findings", ["asset_id"]
    )
    op.create_index(op.f("ix_attack_path_findings_status"), "attack_path_findings", ["status"])
    op.create_index(
        "uq_attack_path_findings_rule_asset",
        "attack_path_findings",
        ["organization_id", "rule_key", "asset_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("attack_path_findings")
    op.drop_table("asset_alert_links")
    op.drop_table("asset_relationships")
    op.drop_table("cloud_assets")
    op.drop_table("cve_enrichment")
    op.drop_table("ingest_events")
    ATTACK_PATH_STATUS_ENUM.drop(op.get_bind(), checkfirst=True)
    ASSET_TYPE_ENUM.drop(op.get_bind(), checkfirst=True)
