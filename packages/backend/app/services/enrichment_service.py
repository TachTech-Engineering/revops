import hashlib
import logging
import os
from datetime import timedelta
from uuid import UUID

import httpx
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db import (
    AlertEnrichment,
    EnrichmentCache,
    EnrichmentPipeline,
    EnrichmentType,
)

logger = logging.getLogger(__name__)


async def get_cache_key(value: str) -> str:
    """Generate a cache key hash for a value."""
    return hashlib.sha256(value.encode()).hexdigest()


async def get_cached_enrichment(
    db: AsyncSession,
    pipeline_id: UUID,
    input_value: str,
) -> dict | None:
    """Check if we have a valid cached enrichment result."""
    input_hash = await get_cache_key(input_value)

    result = await db.execute(
        select(EnrichmentCache).where(
            and_(
                EnrichmentCache.pipeline_id == pipeline_id,
                EnrichmentCache.input_hash == input_hash,
                EnrichmentCache.expires_at > utcnow(),
            )
        )
    )
    cache_entry = result.scalar_one_or_none()

    if cache_entry:
        return cache_entry.result

    return None


async def store_cached_enrichment(
    db: AsyncSession,
    pipeline_id: UUID,
    input_value: str,
    result: dict,
    ttl_minutes: int,
    error_message: str | None = None,
) -> EnrichmentCache:
    """Store an enrichment result in the cache."""
    input_hash = await get_cache_key(input_value)
    expires_at = utcnow() + timedelta(minutes=ttl_minutes)

    # Check if entry exists and update, otherwise create
    existing = await db.execute(
        select(EnrichmentCache).where(
            and_(
                EnrichmentCache.pipeline_id == pipeline_id,
                EnrichmentCache.input_hash == input_hash,
            )
        )
    )
    cache_entry = existing.scalar_one_or_none()

    if cache_entry:
        cache_entry.result = result
        cache_entry.error_message = error_message
        cache_entry.expires_at = expires_at
    else:
        cache_entry = EnrichmentCache(
            pipeline_id=pipeline_id,
            input_value=input_value,
            input_hash=input_hash,
            result=result,
            error_message=error_message,
            expires_at=expires_at,
        )
        db.add(cache_entry)

    await db.flush()
    return cache_entry


async def enrich_ip_geolocation(ip_address: str) -> dict:
    """Enrich IP address with geolocation data using ip-api.com (free)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"http://ip-api.com/json/{ip_address}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                    }
    except Exception as e:
        logger.exception("Enrichment lookup failed")
        return {"error": str(e)}

    return {"error": "Failed to get geolocation data"}


async def enrich_ip_reputation(ip_address: str) -> dict:
    """Check IP reputation. Uses AbuseIPDB if configured."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "AbuseIPDB API key not configured"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip_address, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_public": data.get("isPublic"),
                    "is_whitelisted": data.get("isWhitelisted"),
                    "total_reports": data.get("totalReports"),
                    "last_reported_at": data.get("lastReportedAt"),
                }
    except Exception as e:
        logger.exception("Enrichment lookup failed")
        return {"error": str(e)}

    return {"error": "Failed to get IP reputation data"}


async def enrich_domain_whois(domain: str) -> dict:
    """Get WHOIS information for a domain."""
    # In production, this would use a WHOIS API service
    return {
        "status": "not_configured",
        "message": "WHOIS lookup requires a paid API service",
        "domain": domain,
    }


async def enrich_file_hash(file_hash: str) -> dict:
    """Check file hash against VirusTotal."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": api_key},
            )
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "sha256": data.get("sha256"),
                    "sha1": data.get("sha1"),
                    "md5": data.get("md5"),
                    "file_type": data.get("type_description"),
                    "file_size": data.get("size"),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "first_seen": data.get("first_submission_date"),
                    "last_seen": data.get("last_analysis_date"),
                }
            elif response.status_code == 404:
                return {"status": "not_found", "hash": file_hash}
    except Exception as e:
        logger.exception("Enrichment lookup failed")
        return {"error": str(e)}

    return {"error": "Failed to get file hash data"}


async def enrich_custom_api(
    value: str,
    api_endpoint: str,
    api_headers: dict,
    api_key_env: str | None = None,
) -> dict:
    """Call a custom API for enrichment."""
    headers = dict(api_headers)

    if api_key_env:
        api_key = os.getenv(api_key_env)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

    try:
        # Replace {value} placeholder in endpoint
        endpoint = api_endpoint.replace("{value}", value)

        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(endpoint, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": f"API returned status {response.status_code}",
                    "response": response.text[:500],
                }
    except Exception as e:
        logger.exception("Enrichment lookup failed")
        return {"error": str(e)}


async def run_enrichment(
    db: AsyncSession,
    pipeline: EnrichmentPipeline,
    value: str,
) -> dict:
    """Run enrichment for a given value using the specified pipeline."""
    # Check cache first
    cached = await get_cached_enrichment(db, pipeline.id, value)
    if cached:
        return {"source": "cache", "data": cached}

    # Run the appropriate enrichment
    result = {}
    enrichment_type = pipeline.enrichment_type

    if enrichment_type == EnrichmentType.IP_GEOLOCATION:
        result = await enrich_ip_geolocation(value)
    elif enrichment_type == EnrichmentType.IP_REPUTATION:
        result = await enrich_ip_reputation(value)
    elif enrichment_type == EnrichmentType.DOMAIN_WHOIS:
        result = await enrich_domain_whois(value)
    elif enrichment_type == EnrichmentType.FILE_HASH:
        result = await enrich_file_hash(value)
    elif enrichment_type == EnrichmentType.CUSTOM_API:
        if pipeline.api_endpoint:
            result = await enrich_custom_api(
                value,
                pipeline.api_endpoint,
                pipeline.api_headers,
                pipeline.api_key_env,
            )
        else:
            result = {"error": "No API endpoint configured"}
    else:
        result = {"error": f"Unsupported enrichment type: {enrichment_type}"}

    # Store in cache
    error_message = result.get("error") if "error" in result else None
    await store_cached_enrichment(
        db, pipeline.id, value, result, pipeline.cache_ttl_minutes, error_message
    )

    return {"source": "live", "data": result}


async def enrich_alert(
    db: AsyncSession,
    alert_id: str,
    alert_data: dict,
    user_email: str,
    pipeline_ids: list[UUID] | None = None,
) -> list[dict]:
    """Enrich an alert using all active pipelines or specified pipelines."""
    if pipeline_ids:
        query = select(EnrichmentPipeline).where(
            and_(
                EnrichmentPipeline.id.in_(pipeline_ids),
                EnrichmentPipeline.is_active.is_(True),
            )
        )
    else:
        query = select(EnrichmentPipeline).where(EnrichmentPipeline.is_active.is_(True))

    result = await db.execute(query)
    pipelines = result.scalars().all()

    enrichments = []

    for pipeline in pipelines:
        # Extract value from alert data using source_field
        # Support nested fields like "p_alert.context.source_ip"
        value = alert_data
        for key in pipeline.source_field.split("."):
            if isinstance(value, dict):
                value = value.get(key)
            else:
                value = None
                break

        if not value:
            continue

        # Run enrichment
        enrichment_result = await run_enrichment(db, pipeline, str(value))

        # Store enrichment for this alert
        alert_enrichment = AlertEnrichment(
            alert_id=alert_id,
            pipeline_id=pipeline.id,
            source_field=pipeline.source_field,
            source_value=str(value),
            enrichment_data=enrichment_result.get("data", {}),
            enriched_by=user_email,
        )
        db.add(alert_enrichment)

        enrichments.append(
            {
                "pipeline_id": str(pipeline.id),
                "pipeline_name": pipeline.name,
                "source_field": pipeline.source_field,
                "source_value": str(value),
                "target_field": pipeline.target_field,
                "source": enrichment_result.get("source"),
                "data": enrichment_result.get("data", {}),
            }
        )

    await db.flush()
    return enrichments


async def get_alert_enrichments(
    db: AsyncSession,
    alert_id: str,
) -> list[dict]:
    """Get all enrichments for an alert."""
    result = await db.execute(
        select(AlertEnrichment, EnrichmentPipeline)
        .join(EnrichmentPipeline, AlertEnrichment.pipeline_id == EnrichmentPipeline.id)
        .where(AlertEnrichment.alert_id == alert_id)
        .order_by(AlertEnrichment.created_at.desc())
    )

    enrichments = []
    for enrichment, pipeline in result.all():
        enrichments.append(
            {
                "id": str(enrichment.id),
                "pipeline_id": str(pipeline.id),
                "pipeline_name": pipeline.name,
                "enrichment_type": pipeline.enrichment_type.value,
                "source_field": enrichment.source_field,
                "source_value": enrichment.source_value,
                "target_field": pipeline.target_field,
                "data": enrichment.enrichment_data,
                "enriched_by": enrichment.enriched_by,
                "created_at": enrichment.created_at.isoformat(),
            }
        )

    return enrichments
