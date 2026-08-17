"""
Alert Status Sync

Pushes RevOps alert status changes back to the originating security tool
(two-way sync). Best-effort by design: the local status update always wins,
and a failed push is reported in the API response rather than blocking it.

Connectors opt in by overriding DataSourceConnector.push_status_update();
everything else inherits the base "not supported" result. Users can turn
push-back off per connector with config {"two_way_sync": false}.
"""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Connector, NormalizedAlert
from app.services.connectors.base import StatusPushResult, get_connector_registry
from app.services.encryption import get_encryption_service

logger = logging.getLogger(__name__)


def _result_dict(result: StatusPushResult, source_type: str) -> dict[str, Any]:
    return {
        "source_type": source_type,
        "supported": result.supported,
        "success": result.success,
        "message": result.message,
    }


async def push_alert_status_to_source(
    db: AsyncSession, alert: NormalizedAlert, new_status: str
) -> dict[str, Any]:
    """
    Push an alert's new status to its source tool.

    Returns a JSON-safe summary of the outcome. Never raises: any failure is
    captured in the returned dict so callers can surface it without aborting
    the local status change.
    """
    source_type = alert.source_type or "unknown"
    try:
        result = await db.execute(
            select(Connector).where(
                Connector.id == alert.connector_id,
                Connector.organization_id == alert.organization_id,
            )
        )
        connector = result.scalar_one_or_none()
        if not connector:
            return _result_dict(
                StatusPushResult(
                    supported=False,
                    success=False,
                    message="Originating connector no longer exists",
                ),
                source_type,
            )

        if (connector.config or {}).get("two_way_sync", True) is False:
            return _result_dict(
                StatusPushResult(
                    supported=True,
                    success=False,
                    message="Two-way sync is disabled for this connector",
                ),
                source_type,
            )

        connector_cls = get_connector_registry().get_data_source(connector.connector_type)
        if not connector_cls:
            return _result_dict(
                StatusPushResult(
                    supported=False,
                    success=False,
                    message=f"Unknown connector type '{connector.connector_type}'",
                ),
                source_type,
            )

        credentials: dict[str, Any] = {}
        if connector.credentials_encrypted:
            credentials = get_encryption_service().decrypt(connector.credentials_encrypted)

        instance = connector_cls(connector.id, connector.config or {}, credentials)
        push_result = await instance.push_status_update(alert, new_status)

        if push_result.supported and not push_result.success:
            logger.warning(
                f"Status push-back failed for alert {alert.id} "
                f"({connector.connector_type}): {push_result.message}"
            )
        return _result_dict(push_result, source_type)

    except Exception as e:
        logger.exception(f"Status push-back errored for alert {alert.id}: {e}")
        return _result_dict(
            StatusPushResult(
                supported=True,
                success=False,
                message=f"Push-back error: {str(e)}",
            ),
            source_type,
        )
