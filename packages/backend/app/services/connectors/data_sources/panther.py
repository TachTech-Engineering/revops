"""
Panther Data Source Connector

Integrates with Panther SIEM to fetch and normalize alerts.
Wraps the existing PantherService for connector framework compatibility.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx

from app.db.models import NormalizedAlert, ConnectorCategory
from app.services.connectors.base import (
    DataSourceConnector,
    ConnectorMetadata,
    ConnectionTestResult,
)


class PantherDataSourceConnector(DataSourceConnector):
    """
    Panther SIEM data source connector.

    Fetches alerts from Panther's GraphQL API and normalizes them
    to the unified alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="panther",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Panther",
            description="Panther SIEM - Cloud-native security analytics platform",
            icon="panther",
            config_schema={
                "type": "object",
                "properties": {
                    "api_host": {
                        "type": "string",
                        "title": "API Host",
                        "description": "Panther instance hostname (e.g., your-org.runpanther.net)",
                    },
                },
                "required": ["api_host"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "Panther API token with alerts read permission",
                        "format": "password",
                    },
                },
                "required": ["api_token"],
            },
        )

    def _get_api_url(self) -> str:
        """Get the Panther GraphQL API URL."""
        host = self.config.get("api_host", "")
        if not host.startswith("http"):
            host = f"https://{host}"
        return f"{host}/public/graphql"

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.credentials.get("api_token", ""),
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Panther API."""
        import logging
        logger = logging.getLogger(__name__)

        start_time = time.time()
        try:
            # Query users list - doesn't require date range
            query = """
            query TestConnection {
                users {
                    id
                }
            }
            """

            url = self._get_api_url()
            headers = self._get_headers()
            logger.info(f"Testing Panther connection to: {url}")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    headers=headers,
                    json={"query": query},
                )

            logger.info(f"Panther response status: {response.status_code}")

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                if "errors" in data:
                    return ConnectionTestResult(
                        success=False,
                        message=f"GraphQL error: {data['errors'][0].get('message', 'Unknown error')}",
                        latency_ms=latency_ms,
                    )
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Panther",
                    details={"api_host": self.config.get("api_host")},
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check API token",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}",
                    latency_ms=latency_ms,
                )

        except httpx.TimeoutException:
            logger.error("Panther connection timed out")
            return ConnectionTestResult(
                success=False,
                message="Connection timed out",
            )
        except Exception as e:
            logger.exception(f"Panther connection error: {e}")
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        """Fetch alerts from Panther API."""
        query = """
        query ListAlerts($input: AlertsInput!) {
            alerts(input: $input) {
                edges {
                    node {
                        id
                        title
                        severity
                        status
                        createdAt
                        updatedAt
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        # Panther requires both createdAtAfter and createdAtBefore
        now = datetime.utcnow()
        variables = {
            "input": {
                "createdAtAfter": since.isoformat() + "Z",
                "createdAtBefore": now.isoformat() + "Z",
            }
        }

        if cursor:
            variables["input"]["cursor"] = cursor

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    self._get_api_url(),
                    headers=self._get_headers(),
                    json={"query": query, "variables": variables},
                )

            data = response.json()
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Panther fetch_alerts response: status={response.status_code}, body={data}")

            if response.status_code != 200:
                error_msg = data.get("errors", [{}])[0].get("message", f"API returned status {response.status_code}")
                raise Exception(error_msg)

            if "errors" in data:
                raise Exception(data["errors"][0].get("message", "GraphQL error"))

            alerts_data = data.get("data", {}).get("alerts", {})
            edges = alerts_data.get("edges", [])
            page_info = alerts_data.get("pageInfo", {})

            normalized_alerts = []
            for edge in edges:
                raw_alert = edge.get("node", {})
                normalized = self.normalize_alert(raw_alert)
                normalized_alerts.append(normalized)

            next_cursor = None
            if page_info.get("hasNextPage"):
                next_cursor = page_info.get("endCursor")

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from Panther: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Panther alert to the unified schema."""
        # Parse timestamps - convert to naive datetime (no timezone) for PostgreSQL
        created_at_str = raw_alert.get("createdAt", "")
        if created_at_str:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00")).replace(tzinfo=None)
        else:
            created_at = datetime.utcnow()

        updated_at = None
        if raw_alert.get("updatedAt"):
            updated_at = datetime.fromisoformat(raw_alert["updatedAt"].replace("Z", "+00:00")).replace(tzinfo=None)

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="panther",
            external_id=raw_alert.get("id", ""),
            title=raw_alert.get("title", "Untitled Alert"),
            description=None,
            severity=self.normalize_severity(raw_alert.get("severity", "MEDIUM")),
            status=self.normalize_status(raw_alert.get("status", "OPEN")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=None,
            rule_name=raw_alert.get("title"),
            tags=[],
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Panther severity to standard values."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }
        return severity_map.get(source_severity.upper(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize Panther status to standard values."""
        status_map = {
            "OPEN": "open",
            "TRIAGED": "acknowledged",
            "CLOSED": "closed",
            "RESOLVED": "resolved",
        }
        return status_map.get(source_status.upper(), "open")
