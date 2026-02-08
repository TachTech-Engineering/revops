"""
CrowdStrike Falcon Data Source Connector

Integrates with CrowdStrike Falcon to fetch and normalize alerts.
Uses the new Alerts API v2 (the old detects API was decommissioned).
"""

import time
import uuid
from datetime import datetime
from typing import Any, Optional

import httpx

from app.db.models import NormalizedAlert, ConnectorCategory
from app.services.connectors.base import (
    DataSourceConnector,
    ConnectorMetadata,
    ConnectionTestResult,
)


class CrowdStrikeFalconConnector(DataSourceConnector):
    """
    CrowdStrike Falcon data source connector.

    Fetches alerts from CrowdStrike Falcon using the Alerts API v2
    and normalizes them to the unified alert schema.
    """

    _access_token: Optional[str] = None
    _token_expires_at: float = 0

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="crowdstrike_falcon",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="CrowdStrike Falcon",
            description="CrowdStrike Falcon - Endpoint detection and response platform",
            icon="crowdstrike",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "API Base URL",
                        "description": "CrowdStrike API base URL for your cloud region",
                        "enum": [
                            "https://api.crowdstrike.com",
                            "https://api.us-2.crowdstrike.com",
                            "https://api.eu-1.crowdstrike.com",
                            "https://api.laggar.gcw.crowdstrike.com",
                        ],
                        "default": "https://api.crowdstrike.com",
                    },
                },
                "required": ["base_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "title": "Client ID",
                        "description": "CrowdStrike API client ID (OAuth2)",
                    },
                    "client_secret": {
                        "type": "string",
                        "title": "Client Secret",
                        "description": "CrowdStrike API client secret",
                        "format": "password",
                    },
                },
                "required": ["client_id", "client_secret"],
            },
        )

    async def _get_access_token(self) -> str:
        """Get OAuth2 access token from CrowdStrike (with caching)."""
        # Return cached token if still valid
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/oauth2/token",
                data={
                    "client_id": self.credentials.get("client_id", ""),
                    "client_secret": self.credentials.get("client_secret", ""),
                },
            )

        if response.status_code != 201:
            raise Exception(f"Failed to get access token: {response.status_code} - {response.text}")

        data = response.json()
        self._access_token = data.get("access_token", "")
        # Token typically expires in 30 minutes
        self._token_expires_at = time.time() + data.get("expires_in", 1800)

        return self._access_token

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to CrowdStrike Falcon API."""
        start_time = time.time()
        try:
            token = await self._get_access_token()
            base_url = self.config.get("base_url", "https://api.crowdstrike.com")

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test using the Alerts API v2
                response = await client.get(
                    f"{base_url}/alerts/queries/alerts/v2",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": 1},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to CrowdStrike Falcon",
                    details={
                        "api_url": base_url,
                        "alerts_available": len(data.get("resources", [])) > 0,
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check client ID and secret",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Access denied - API client needs 'Alerts: Read' scope",
                    latency_ms=latency_ms,
                )
            else:
                error_detail = ""
                try:
                    error_data = response.json()
                    if "errors" in error_data:
                        error_detail = ": " + str(error_data["errors"])
                except Exception:
                    pass
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}{error_detail}",
                    latency_ms=latency_ms,
                )

        except Exception as e:
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
        """Fetch alerts from CrowdStrike Falcon using Alerts API v2."""
        try:
            token = await self._get_access_token()
            base_url = self.config.get("base_url", "https://api.crowdstrike.com")

            # Build FQL filter for alerts
            since_timestamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_query = f"created_timestamp:>='{since_timestamp}'"

            params = {
                "filter": filter_query,
                "limit": min(limit, 100),  # Max 100 per request
                "sort": "created_timestamp|asc",
            }
            if cursor:
                params["offset"] = int(cursor)

            async with httpx.AsyncClient(timeout=60.0) as client:
                # Step 1: Query alert IDs
                response = await client.get(
                    f"{base_url}/alerts/queries/alerts/v2",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                )

                if response.status_code != 200:
                    error_msg = f"Failed to query alerts: {response.status_code}"
                    try:
                        error_data = response.json()
                        if "errors" in error_data:
                            error_msg += f" - {error_data['errors']}"
                    except Exception:
                        pass
                    raise Exception(error_msg)

                query_data = response.json()
                alert_ids = query_data.get("resources", [])

                if not alert_ids:
                    return [], None

                # Step 2: Get alert details using POST
                response = await client.post(
                    f"{base_url}/alerts/entities/alerts/v2",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    json={"composite_ids": alert_ids},
                )

                if response.status_code != 200:
                    error_msg = f"Failed to get alert details: {response.status_code}"
                    try:
                        error_data = response.json()
                        if "errors" in error_data:
                            error_msg += f" - {error_data['errors']}"
                    except Exception:
                        pass
                    raise Exception(error_msg)

                details_data = response.json()
                alerts = details_data.get("resources", [])

            # Normalize alerts
            normalized_alerts = []
            for alert in alerts:
                normalized = self.normalize_alert(alert)
                normalized_alerts.append(normalized)

            # Calculate next cursor
            next_cursor = None
            meta = query_data.get("meta", {}).get("pagination", {})
            total = meta.get("total", 0)
            offset = meta.get("offset", 0)
            if offset + len(alert_ids) < total:
                next_cursor = str(offset + len(alert_ids))

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from CrowdStrike Falcon: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a CrowdStrike alert to the unified schema."""
        # Parse timestamps (must be timezone-naive for database)
        created_at = datetime.utcnow()
        created_timestamp = raw_alert.get("created_timestamp", "")
        if created_timestamp:
            try:
                dt = datetime.fromisoformat(created_timestamp.replace("Z", "+00:00"))
                created_at = dt.replace(tzinfo=None)  # Convert to naive
            except (ValueError, TypeError):
                pass

        updated_at = None
        updated_timestamp = raw_alert.get("updated_timestamp", "")
        if updated_timestamp:
            try:
                dt = datetime.fromisoformat(updated_timestamp.replace("Z", "+00:00"))
                updated_at = dt.replace(tzinfo=None)  # Convert to naive
            except (ValueError, TypeError):
                pass

        # Build title
        tactic = raw_alert.get("tactic", "")
        technique = raw_alert.get("technique", "")
        hostname = raw_alert.get("hostname", "Unknown Host")

        title = raw_alert.get("name", "CrowdStrike Alert")
        if not title or title == "CrowdStrike Alert":
            if tactic and technique:
                title = f"{tactic}: {technique}"
            elif tactic:
                title = tactic
            elif technique:
                title = technique
        title = f"{title} on {hostname}"

        # Build description
        description = raw_alert.get("description", "")
        if not description:
            description_parts = []
            if raw_alert.get("scenario"):
                description_parts.append(f"Scenario: {raw_alert['scenario']}")
            if raw_alert.get("objective"):
                description_parts.append(f"Objective: {raw_alert['objective']}")
            if raw_alert.get("pattern_id"):
                description_parts.append(f"Pattern: {raw_alert['pattern_id']}")
            description = " | ".join(description_parts)

        # Extract MITRE info
        mitre_tactics = []
        mitre_techniques = []
        if raw_alert.get("tactic_id"):
            mitre_tactics.append(raw_alert["tactic_id"])
        if raw_alert.get("technique_id"):
            mitre_techniques.append(raw_alert["technique_id"])

        # Ensure rule_id and rule_name are strings
        rule_id = raw_alert.get("pattern_id")
        if rule_id is not None:
            rule_id = str(rule_id)

        rule_name = raw_alert.get("scenario") or raw_alert.get("name")
        if rule_name is not None:
            rule_name = str(rule_name)

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="crowdstrike_falcon",
            external_id=str(raw_alert.get("composite_id") or raw_alert.get("id", uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=self.normalize_severity(raw_alert.get("severity", "medium")),
            status=self.normalize_status(raw_alert.get("status", "new")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=rule_id,
            rule_name=rule_name,
            tags=self._extract_tags(raw_alert),
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def _extract_tags(self, raw_alert: dict[str, Any]) -> list[str]:
        """Extract tags from CrowdStrike alert."""
        tags = []

        # Add platform/OS info
        if raw_alert.get("platform"):
            tags.append(f"platform:{raw_alert['platform']}")
        if raw_alert.get("product"):
            tags.append(f"product:{raw_alert['product']}")

        # Add hostname
        if raw_alert.get("hostname"):
            tags.append(f"host:{raw_alert['hostname']}")

        # Add agent info
        if raw_alert.get("agent_id"):
            tags.append(f"agent:{raw_alert['agent_id'][:8]}...")

        # Add scenario/objective as tags
        if raw_alert.get("scenario"):
            tags.append(f"scenario:{raw_alert['scenario'].lower().replace(' ', '_')}")
        if raw_alert.get("objective"):
            tags.append(f"objective:{raw_alert['objective'].lower().replace(' ', '_')}")

        # Add severity as tag
        if raw_alert.get("severity"):
            tags.append(f"severity:{raw_alert['severity']}")

        return tags[:20]  # Limit tags

    def normalize_severity(self, source_severity) -> str:
        """Normalize CrowdStrike severity to standard values."""
        # CrowdStrike uses numeric severity (0-100) or string values
        if isinstance(source_severity, int):
            if source_severity >= 80:
                return "critical"
            elif source_severity >= 60:
                return "high"
            elif source_severity >= 40:
                return "medium"
            elif source_severity >= 20:
                return "low"
            else:
                return "info"

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
        }
        return severity_map.get(str(source_severity).lower(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize CrowdStrike status to standard values."""
        status_map = {
            "new": "open",
            "in_progress": "acknowledged",
            "reopened": "open",
            "closed": "closed",
        }
        return status_map.get(source_status.lower(), "open")
