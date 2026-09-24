"""
Trivy Ingest Webhook

Receives Trivy JSON scan reports pushed by CI jobs, cron scans, or
trivy-operator webhooks and buffers them for the Trivy connector's sync cycle.

These endpoints cannot carry a user JWT (the scan job calls them directly), so
they are authenticated by a per-connector shared ingest token, accepted as an
Authorization: Bearer header, an X-Ingest-Token header, or a ?token= query
param (mirrors the Falco ingest webhook).
"""

import hmac
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.db.models import Connector, ConnectorCategory, ConnectorStatus
from app.services.encryption import get_encryption_service
from app.services.ingest_buffer import count_pending, push_events

logger = logging.getLogger(__name__)

router = APIRouter()

# Reports are large (one per scanned artifact), so the cap is per-report, not
# per-finding. One CI run posting a report per image stays well under this.
MAX_REPORTS_PER_REQUEST = 50


def _extract_token(request: Request) -> str | None:
    """Pull the ingest token from header or query param."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    header_token = request.headers.get("X-Ingest-Token")
    if header_token:
        return header_token.strip()

    return request.query_params.get("token")


@router.post("/trivy/{connector_id}", status_code=status.HTTP_202_ACCEPTED)
async def ingest_trivy_reports(
    connector_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Accept Trivy reports (single object or list) and buffer them for sync."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.connector_type == "trivy",
                Connector.category == ConnectorCategory.DATA_SOURCE,
            )
        )
    )
    connector = result.scalar_one_or_none()
    # 404 for missing, wrong-type, and disabled connectors alike, so the
    # endpoint doesn't confirm which connector IDs exist to unauthenticated
    # callers.
    if not connector or connector.status == ConnectorStatus.DISABLED:
        raise HTTPException(status_code=404, detail="Connector not found")

    expected_token = None
    if connector.credentials_encrypted:
        try:
            credentials = get_encryption_service().decrypt(connector.credentials_encrypted)
            expected_token = credentials.get("ingest_token")
        except Exception:
            logger.exception(f"Failed to decrypt credentials for Trivy connector {connector_id}")

    provided_token = _extract_token(request)
    if (
        not expected_token
        or not provided_token
        or not hmac.compare_digest(expected_token, provided_token)
    ):
        raise HTTPException(status_code=401, detail="Invalid ingest token")

    try:
        body: Any = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be valid JSON")

    if isinstance(body, dict):
        reports = [body]
    elif isinstance(body, list):
        reports = [report for report in body if isinstance(report, dict)]
    else:
        raise HTTPException(
            status_code=400, detail="Body must be a JSON object or array of objects"
        )

    if not reports:
        raise HTTPException(status_code=400, detail="No report objects in body")
    if len(reports) > MAX_REPORTS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"Too many reports in one request (max {MAX_REPORTS_PER_REQUEST})",
        )

    accepted = await push_events(
        db,
        connector_id=connector_id,
        organization_id=connector.organization_id,
        connector_type="trivy",
        events=reports,
    )
    pending = await count_pending(db, connector_id)
    await db.commit()

    return {
        "accepted": accepted,
        "buffered": pending,
    }
