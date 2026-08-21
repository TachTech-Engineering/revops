"""
CVE Enrichment Service

Syncs exploitability context from two free public feeds and applies it to
vulnerability alerts:

- FIRST EPSS (https://api.first.org/data/v1/epss): probability a CVE is
  exploited in the wild within 30 days.
- CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed
  exploitation.

This is the Wiz-style prioritization layer: a medium-CVSS CVE that is in KEV
outranks a critical-CVSS CVE nobody exploits. Enrichment is applied to open
Trivy alerts by tagging them (kev, epss_high) and promoting KEV findings to
critical severity.
"""

import logging

import httpx
from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import CveEnrichment, NormalizedAlert

logger = logging.getLogger(__name__)

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# EPSS score at or above which a finding is treated as "likely exploited"
EPSS_HIGH_THRESHOLD = 0.5

# EPSS API accepts comma-separated CVE lists; keep requests reasonably sized
EPSS_BATCH_SIZE = 100


async def _referenced_cve_ids(db: AsyncSession) -> list[str]:
    """Distinct CVE ids referenced by vulnerability alerts (Trivy rule_id)."""
    result = await db.execute(
        select(NormalizedAlert.rule_id)
        .where(
            and_(
                NormalizedAlert.source_type == "trivy",
                NormalizedAlert.rule_id.ilike("CVE-%"),
            )
        )
        .distinct()
    )
    return [row[0].upper() for row in result.all() if row[0]]


async def sync_kev_catalog(db: AsyncSession, client: httpx.AsyncClient) -> int:
    """Upsert the full CISA KEV catalog. Returns the number of KEV CVEs."""
    response = await client.get(KEV_CATALOG_URL)
    response.raise_for_status()
    catalog = response.json()

    vulnerabilities = catalog.get("vulnerabilities") or []
    for entry in vulnerabilities:
        cve_id = str(entry.get("cveID", "")).upper()
        if not cve_id.startswith("CVE-"):
            continue
        date_added = None
        if entry.get("dateAdded"):
            try:
                from datetime import datetime

                date_added = datetime.fromisoformat(entry["dateAdded"])
            except (ValueError, TypeError):
                pass
        stmt = pg_insert(CveEnrichment).values(
            cve_id=cve_id,
            in_kev=True,
            kev_date_added=date_added,
            kev_ransomware=(
                str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
            ),
            kev_vulnerability_name=entry.get("vulnerabilityName"),
            updated_at=utcnow(),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[CveEnrichment.cve_id],
            set_={
                "in_kev": True,
                "kev_date_added": stmt.excluded.kev_date_added,
                "kev_ransomware": stmt.excluded.kev_ransomware,
                "kev_vulnerability_name": stmt.excluded.kev_vulnerability_name,
                "updated_at": utcnow(),
            },
        )
        await db.execute(stmt)

    logger.info(f"KEV catalog synced: {len(vulnerabilities)} entries")
    return len(vulnerabilities)


async def sync_epss_scores(
    db: AsyncSession, client: httpx.AsyncClient, cve_ids: list[str]
) -> int:
    """Fetch and upsert EPSS scores for the given CVEs. Returns count updated."""
    updated = 0
    for start in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[start : start + EPSS_BATCH_SIZE]
        response = await client.get(EPSS_API_URL, params={"cve": ",".join(batch)})
        response.raise_for_status()
        for item in response.json().get("data") or []:
            cve_id = str(item.get("cve", "")).upper()
            if not cve_id.startswith("CVE-"):
                continue
            try:
                epss_score = float(item.get("epss", 0))
                epss_percentile = float(item.get("percentile", 0))
            except (TypeError, ValueError):
                continue
            stmt = pg_insert(CveEnrichment).values(
                cve_id=cve_id,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                updated_at=utcnow(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[CveEnrichment.cve_id],
                set_={
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "updated_at": utcnow(),
                },
            )
            await db.execute(stmt)
            updated += 1
    return updated


async def apply_enrichment_to_alerts(db: AsyncSession) -> int:
    """Tag open Trivy alerts with exploitability context.

    - in KEV: add 'kev' tag and promote severity to critical
    - EPSS >= threshold: add 'epss_high' tag and an 'epss:<score>' tag

    Returns the number of alerts updated. Idempotent: already-tagged alerts
    are skipped.
    """
    result = await db.execute(
        select(NormalizedAlert, CveEnrichment)
        .join(
            CveEnrichment,
            CveEnrichment.cve_id == NormalizedAlert.rule_id,
        )
        .where(
            and_(
                NormalizedAlert.source_type == "trivy",
                NormalizedAlert.status.in_(["open", "acknowledged"]),
            )
        )
    )

    updated = 0
    for alert, enrichment in result.all():
        tags = list(alert.tags or [])
        changed = False

        if enrichment.in_kev and "kev" not in tags:
            tags.append("kev")
            if enrichment.kev_ransomware and "kev_ransomware" not in tags:
                tags.append("kev_ransomware")
            if alert.severity != "critical":
                alert.severity = "critical"
            changed = True

        if (
            enrichment.epss_score is not None
            and enrichment.epss_score >= EPSS_HIGH_THRESHOLD
            and "epss_high" not in tags
        ):
            tags.append("epss_high")
            tags.append(f"epss:{enrichment.epss_score:.2f}")
            changed = True

        if changed:
            alert.tags = tags
            updated += 1

    return updated


async def sync_cve_feeds(db: AsyncSession) -> dict:
    """Full enrichment cycle: KEV catalog, EPSS for referenced CVEs, tagging."""
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        kev_count = await sync_kev_catalog(db, client)
        cve_ids = await _referenced_cve_ids(db)
        epss_count = await sync_epss_scores(db, client, cve_ids)
    tagged = await apply_enrichment_to_alerts(db)
    return {
        "kev_entries": kev_count,
        "referenced_cves": len(cve_ids),
        "epss_scores_updated": epss_count,
        "alerts_enriched": tagged,
    }


async def get_enrichment_for_cves(
    db: AsyncSession, cve_ids: list[str]
) -> dict[str, CveEnrichment]:
    """Fetch enrichment rows for a set of CVE ids, keyed by CVE id."""
    if not cve_ids:
        return {}
    result = await db.execute(
        select(CveEnrichment).where(CveEnrichment.cve_id.in_([c.upper() for c in cve_ids]))
    )
    return {row.cve_id: row for row in result.scalars().all()}
