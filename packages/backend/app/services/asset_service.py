"""
Asset Service

Builds and maintains the cloud asset inventory (CloudAsset /
AssetRelationship) and links normalized alerts to the assets they concern.

Assets arrive from two directions:

1. Finding-derived (cheap, automatic): every ingested Prowler, Trivy, or
   Falco alert carries enough identity to upsert the asset it concerns --
   hostname/container/pod from Falco, artifact from Trivy, provider resource
   from Prowler's finding UID. Called from the connector sync path.

2. Inventory-import (authoritative): bulk upsert from an external inventory
   tool (Cartography, CloudQuery) via POST /api/v1/assets/import, which also
   carries relationships and exposure facts the finding stream cannot see.

Everything is keyed on (organization_id, external_id); concurrent syncs are
settled by the unique index via ON CONFLICT upserts, same pattern as alert
dedup.
"""

import logging
import re
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import (
    AssetAlertLink,
    AssetRelationship,
    AssetType,
    CloudAsset,
    NormalizedAlert,
)

logger = logging.getLogger(__name__)

# Words in a check id/title that indicate the finding is about internet
# exposure. Deliberately conservative: these mark the *asset* as exposed.
EXPOSURE_PATTERN = re.compile(
    r"public|internet[-_ ]?facing|internet[-_ ]?exposed|0\.0\.0\.0|open[-_ ]to[-_ ]the[-_ ]world",
    re.IGNORECASE,
)

# Prowler service name -> asset type for the resource the finding concerns
PROWLER_SERVICE_ASSET_TYPES: dict[str, AssetType] = {
    "s3": AssetType.STORAGE_BUCKET,
    "gcs": AssetType.STORAGE_BUCKET,
    "storage": AssetType.STORAGE_BUCKET,
    "rds": AssetType.DATABASE,
    "dynamodb": AssetType.DATABASE,
    "sql": AssetType.DATABASE,
    "cloudsql": AssetType.DATABASE,
    "cosmosdb": AssetType.DATABASE,
    "ec2": AssetType.VM_INSTANCE,
    "compute": AssetType.VM_INSTANCE,
    "vm": AssetType.VM_INSTANCE,
    "iam": AssetType.IAM_IDENTITY,
    "sts": AssetType.IAM_IDENTITY,
    "entra": AssetType.IAM_IDENTITY,
    "lambda": AssetType.SERVERLESS_FUNCTION,
    "cloudfunctions": AssetType.SERVERLESS_FUNCTION,
    "elb": AssetType.LOAD_BALANCER,
    "elbv2": AssetType.LOAD_BALANCER,
    "eks": AssetType.K8S_CLUSTER,
    "gke": AssetType.K8S_CLUSTER,
    "aks": AssetType.K8S_CLUSTER,
    "vpc": AssetType.NETWORK,
    "networkfirewall": AssetType.NETWORK,
}


def _tag_value(tags: list, prefix: str) -> str | None:
    """Extract 'value' from the first 'prefix:value' tag."""
    marker = f"{prefix}:"
    for tag in tags or []:
        if isinstance(tag, str) and tag.startswith(marker):
            return tag[len(marker):]
    return None


async def upsert_asset(
    db: AsyncSession,
    organization_id: UUID,
    external_id: str,
    asset_type: AssetType,
    name: str,
    source: str,
    provider: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    internet_exposed: bool | None = None,
    criticality: int | None = None,
    data_classification: str | None = None,
    labels: dict | None = None,
    attrs: dict | None = None,
) -> CloudAsset:
    """Insert or refresh one asset, merging observation sources.

    ``internet_exposed`` only upgrades on None: a finding proves exposure but
    its absence proves nothing, so False from a finding never clears a flag an
    inventory import set. Pass an explicit False only from authoritative
    imports (handled by the caller passing it through).
    """
    now = utcnow()
    insert_values: dict[str, Any] = {
        "organization_id": organization_id,
        "external_id": external_id[:1000],
        "asset_type": asset_type,
        "name": name[:500],
        "provider": provider,
        "account_id": account_id,
        "region": region,
        "internet_exposed": bool(internet_exposed),
        "labels": labels or {},
        "attrs": attrs or {},
        "sources": [source],
        "first_seen": now,
        "last_seen": now,
    }
    if criticality is not None:
        insert_values["criticality"] = criticality
    if data_classification is not None:
        insert_values["data_classification"] = data_classification

    stmt = pg_insert(CloudAsset).values(**insert_values)
    update_set: dict[str, Any] = {
        "last_seen": now,
        "updated_at": now,
        "name": stmt.excluded.name,
    }
    if provider:
        update_set["provider"] = provider
    if account_id:
        update_set["account_id"] = account_id
    if region:
        update_set["region"] = region
    if internet_exposed:
        update_set["internet_exposed"] = True
    if criticality is not None:
        update_set["criticality"] = criticality
    if data_classification is not None:
        update_set["data_classification"] = data_classification

    stmt = stmt.on_conflict_do_update(
        index_elements=[CloudAsset.organization_id, CloudAsset.external_id],
        set_=update_set,
    )
    await db.execute(stmt)

    result = await db.execute(
        select(CloudAsset).where(
            and_(
                CloudAsset.organization_id == organization_id,
                CloudAsset.external_id == external_id[:1000],
            )
        )
    )
    asset = result.scalar_one()

    # Merge the observing source into the JSONB list (small, so read-modify-
    # write is fine; the upsert above already settled the insert race).
    sources = list(asset.sources or [])
    if source not in sources:
        sources.append(source)
        asset.sources = sources

    return asset


async def upsert_relationship(
    db: AsyncSession,
    organization_id: UUID,
    source_asset_id: UUID,
    target_asset_id: UUID,
    relationship_type: str,
    attrs: dict | None = None,
) -> None:
    """Insert a directed asset edge if it does not already exist."""
    if source_asset_id == target_asset_id:
        return
    stmt = pg_insert(AssetRelationship).values(
        organization_id=organization_id,
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        relationship_type=relationship_type,
        attrs=attrs or {},
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=[
            AssetRelationship.organization_id,
            AssetRelationship.source_asset_id,
            AssetRelationship.target_asset_id,
            AssetRelationship.relationship_type,
        ]
    )
    await db.execute(stmt)


async def link_alert_to_asset(
    db: AsyncSession, organization_id: UUID, asset_id: UUID, alert_id: UUID
) -> None:
    """Record that an alert concerns an asset (idempotent)."""
    stmt = pg_insert(AssetAlertLink).values(
        organization_id=organization_id,
        asset_id=asset_id,
        alert_id=alert_id,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=[AssetAlertLink.asset_id, AssetAlertLink.alert_id]
    )
    await db.execute(stmt)


# ==================== Finding-derived extraction ====================


async def _extract_falco_assets(
    db: AsyncSession, alert: NormalizedAlert
) -> list[CloudAsset]:
    """Falco alerts identify host / container / pod / namespace via tags."""
    org = alert.organization_id
    assets: list[CloudAsset] = []

    hostname = _tag_value(alert.tags, "host")
    host_asset = None
    if hostname and hostname != "unknown":
        host_asset = await upsert_asset(
            db, org, f"host:{hostname}", AssetType.HOST, hostname, source="falco"
        )
        assets.append(host_asset)

    container = _tag_value(alert.tags, "container")
    container_asset = None
    if container:
        container_asset = await upsert_asset(
            db,
            org,
            f"container:{hostname or 'unknown'}:{container}",
            AssetType.CONTAINER,
            container,
            source="falco",
        )
        assets.append(container_asset)
        if host_asset:
            await upsert_relationship(
                db, org, container_asset.id, host_asset.id, "runs_on"
            )

    namespace = _tag_value(alert.tags, "namespace")
    namespace_asset = None
    if namespace:
        namespace_asset = await upsert_asset(
            db,
            org,
            f"k8s_namespace:{namespace}",
            AssetType.K8S_NAMESPACE,
            namespace,
            source="falco",
        )
        assets.append(namespace_asset)

    pod = _tag_value(alert.tags, "pod")
    if pod:
        pod_asset = await upsert_asset(
            db,
            org,
            f"k8s_pod:{namespace or 'default'}:{pod}",
            AssetType.K8S_POD,
            pod,
            source="falco",
        )
        assets.append(pod_asset)
        if namespace_asset:
            await upsert_relationship(
                db, org, namespace_asset.id, pod_asset.id, "contains"
            )
        if container_asset:
            await upsert_relationship(
                db, org, pod_asset.id, container_asset.id, "contains"
            )

    return assets


async def _extract_trivy_assets(
    db: AsyncSession, alert: NormalizedAlert
) -> list[CloudAsset]:
    """Trivy alerts identify the scanned artifact (image, fs, repo)."""
    org = alert.organization_id
    raw = alert.raw_data or {}
    artifact = raw.get("artifact") or _tag_value(alert.tags, "artifact")
    if not artifact or artifact == "unknown":
        return []

    artifact_type = raw.get("artifact_type") or _tag_value(alert.tags, "artifact_type") or ""
    if artifact_type == "container_image":
        asset_type = AssetType.CONTAINER_IMAGE
        external_id = f"image:{artifact}"
    elif artifact_type in ("filesystem", "vm"):
        asset_type = AssetType.HOST
        external_id = f"host:{artifact}"
    else:
        asset_type = AssetType.OTHER
        external_id = f"artifact:{artifact}"

    asset = await upsert_asset(
        db,
        org,
        external_id,
        asset_type,
        artifact,
        source="trivy",
        attrs={"artifact_type": artifact_type},
    )
    return [asset]


async def _extract_prowler_assets(
    db: AsyncSession, alert: NormalizedAlert
) -> list[CloudAsset]:
    """Prowler alerts identify a provider resource within a cloud account.

    Resource identity is parsed from the finding UID
    ("prowler-{provider}-{check_id}-{account}-{region}-{resource}") with the
    provider/service tags as fallback context.
    """
    org = alert.organization_id
    provider = _tag_value(alert.tags, "provider")
    service = _tag_value(alert.tags, "service") or ""

    account_id = None
    region = None
    resource_name = None
    uid = alert.external_id or ""
    check_id = alert.rule_id or ""
    if uid.startswith("prowler-") and check_id:
        # Strip the static prefix and the check id, leaving account-region-resource
        remainder = uid[len("prowler-"):]
        if provider and remainder.startswith(f"{provider}-"):
            remainder = remainder[len(provider) + 1:]
        if remainder.startswith(f"{check_id}-"):
            remainder = remainder[len(check_id) + 1:]
            parts = remainder.split("-", 1)
            if parts:
                account_id = parts[0] or None
            if len(parts) > 1 and parts[1]:
                # region is the leading aws-style token(s); resource is the rest.
                # Regions look like us-east-1 / europe-west2; take up to 3 tokens
                # ending in a digit if present.
                region_match = re.match(r"^([a-z]+-[a-z]+-?\d?\d?)-(.+)$", parts[1])
                if region_match:
                    region = region_match.group(1)
                    resource_name = region_match.group(2)
                else:
                    resource_name = parts[1]

    assets: list[CloudAsset] = []

    account_asset = None
    if account_id and provider:
        account_asset = await upsert_asset(
            db,
            org,
            f"account:{provider}:{account_id}",
            AssetType.CLOUD_ACCOUNT,
            f"{provider}:{account_id}",
            source="prowler",
            provider=provider,
            account_id=account_id,
        )
        assets.append(account_asset)

    # The finding text proves exposure for the specific resource it names
    exposed = bool(
        EXPOSURE_PATTERN.search(check_id)
        or EXPOSURE_PATTERN.search(alert.title or "")
    )

    if resource_name:
        asset_type = PROWLER_SERVICE_ASSET_TYPES.get(service.lower(), AssetType.SERVICE)
        resource_asset = await upsert_asset(
            db,
            org,
            f"{provider or 'cloud'}:{service or 'resource'}:{account_id or ''}:{resource_name}",
            asset_type,
            resource_name,
            source="prowler",
            provider=provider,
            account_id=account_id,
            region=region,
            internet_exposed=exposed or None,
            attrs={"service": service},
        )
        assets.append(resource_asset)
        if account_asset:
            await upsert_relationship(
                db, org, account_asset.id, resource_asset.id, "contains"
            )
    elif account_asset and exposed:
        # Exposure finding with no parseable resource: flag at account level
        account_asset.internet_exposed = True

    return assets


_EXTRACTORS = {
    "falco": _extract_falco_assets,
    "trivy": _extract_trivy_assets,
    "prowler": _extract_prowler_assets,
}


async def link_alerts_batch(
    db: AsyncSession, alerts: list[NormalizedAlert], organization_id: UUID
) -> set[UUID]:
    """Extract/upsert assets for a batch of new alerts and link them.

    Returns the ids of every asset touched, for attack-path re-evaluation.
    Failures are contained per alert: asset extraction must never abort the
    alert sync that called it.
    """
    touched: set[UUID] = set()
    for alert in alerts:
        extractor = _EXTRACTORS.get(alert.source_type)
        if not extractor:
            continue
        try:
            assets = await extractor(db, alert)
            for asset in assets:
                await link_alert_to_asset(db, organization_id, asset.id, alert.id)
                touched.add(asset.id)
        except Exception:
            logger.exception(
                f"Asset extraction failed for alert {alert.id} ({alert.source_type})"
            )
    return touched
