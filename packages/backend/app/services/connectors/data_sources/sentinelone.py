"""
SentinelOne Data Source Connector

Integrates with SentinelOne to fetch and normalize endpoint threats and alerts.
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


class SentinelOneConnector(DataSourceConnector):
    """
    SentinelOne data source connector.

    Fetches threats and alerts from SentinelOne EDR platform including:
    - Active threats
    - Behavioral AI detections
    - Static AI detections
    - Suspicious activities
    - Application vulnerabilities
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="sentinelone",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="SentinelOne",
            description="SentinelOne - Autonomous endpoint protection and EDR",
            icon="sentinelone",
            config_schema={
                "type": "object",
                "properties": {
                    "console_url": {
                        "type": "string",
                        "title": "Console URL",
                        "description": "SentinelOne management console URL (e.g., https://usea1-partners.sentinelone.net)",
                    },
                    "account_ids": {
                        "type": "array",
                        "title": "Account IDs",
                        "description": "Filter by specific account IDs (empty = all accessible)",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "site_ids": {
                        "type": "array",
                        "title": "Site IDs",
                        "description": "Filter by specific site IDs (empty = all accessible)",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "threat_status_filter": {
                        "type": "array",
                        "title": "Threat Status Filter",
                        "description": "Only fetch threats with these statuses",
                        "items": {
                            "type": "string",
                            "enum": ["active", "mitigated", "blocked", "suspicious", "pending", "suspicious_resolved"],
                        },
                        "default": ["active", "suspicious"],
                    },
                    "include_alerts": {
                        "type": "boolean",
                        "title": "Include Alerts",
                        "description": "Also fetch alerts (in addition to threats)",
                        "default": True,
                    },
                },
                "required": ["console_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "SentinelOne API token",
                        "format": "password",
                    },
                },
                "required": ["api_token"],
            },
        )

    def _get_base_url(self) -> str:
        """Get the SentinelOne API base URL."""
        console_url = self.config.get("console_url", "").strip()
        if not console_url.startswith("https://"):
            console_url = f"https://{console_url}"
        return console_url.rstrip("/")

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"ApiToken {self.credentials.get('api_token', '')}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to SentinelOne API."""
        start_time = time.time()
        try:
            base_url = self._get_base_url()

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test by getting system info
                response = await client.get(
                    f"{base_url}/web/api/v2.1/system/info",
                    headers=self._get_headers(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json().get("data", {})
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to SentinelOne",
                    details={
                        "deployment": data.get("deployment"),
                        "version": data.get("version"),
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check API token",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Access denied - ensure token has required permissions",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}",
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
        """Fetch threats from SentinelOne."""
        try:
            base_url = self._get_base_url()

            # Build query parameters
            params: dict[str, Any] = {
                "createdAt__gte": since.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                "limit": min(limit, 1000),
                "sortBy": "createdAt",
                "sortOrder": "asc",
            }

            # Add status filter
            status_filter = self.config.get("threat_status_filter", ["active", "suspicious"])
            if status_filter:
                params["mitigationStatuses"] = ",".join(status_filter)

            # Add account/site filters
            account_ids = self.config.get("account_ids", [])
            if account_ids:
                params["accountIds"] = ",".join(account_ids)

            site_ids = self.config.get("site_ids", [])
            if site_ids:
                params["siteIds"] = ",".join(site_ids)

            # Handle pagination
            if cursor:
                params["cursor"] = cursor

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"{base_url}/web/api/v2.1/threats",
                    headers=self._get_headers(),
                    params=params,
                )

                if response.status_code != 200:
                    raise Exception(f"Failed to fetch threats: {response.status_code} - {response.text}")

                data = response.json()

            threats = data.get("data", [])
            pagination = data.get("pagination", {})
            next_cursor = pagination.get("nextCursor")

            # Normalize threats
            normalized_alerts = []
            for threat in threats:
                normalized = self.normalize_alert(threat)
                normalized_alerts.append(normalized)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch threats from SentinelOne: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a SentinelOne threat to the unified schema."""
        threat_info = raw_alert.get("threatInfo", {})
        agent_info = raw_alert.get("agentRealtimeInfo", {}) or raw_alert.get("agentDetectionInfo", {})

        # Parse timestamps
        created_at = datetime.utcnow()
        if threat_info.get("createdAt"):
            try:
                created_at = datetime.fromisoformat(threat_info["createdAt"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        updated_at = None
        if threat_info.get("updatedAt"):
            try:
                updated_at = datetime.fromisoformat(threat_info["updatedAt"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Build title
        threat_name = threat_info.get("threatName", "Unknown Threat")
        classification = threat_info.get("classification", "")
        computer_name = agent_info.get("agentComputerName", "Unknown Host")
        title = f"{threat_name} on {computer_name}"
        if classification:
            title = f"[{classification}] {title}"

        # Build description
        description_parts = []
        description_parts.append(f"Threat: {threat_name}")
        description_parts.append(f"Classification: {classification or 'Unknown'}")
        description_parts.append(f"Confidence: {threat_info.get('confidenceLevel', 'Unknown')}")
        description_parts.append(f"Engine: {threat_info.get('detectionEngines', [])}")

        if threat_info.get("filePath"):
            description_parts.append(f"File Path: {threat_info['filePath']}")
        if threat_info.get("sha256"):
            description_parts.append(f"SHA256: {threat_info['sha256']}")

        description_parts.append(f"\nHost: {computer_name}")
        if agent_info.get("agentOsName"):
            description_parts.append(f"OS: {agent_info['agentOsName']}")
        if agent_info.get("agentIp"):
            description_parts.append(f"IP: {agent_info['agentIp']}")

        # Mitigation status
        if threat_info.get("mitigationStatus"):
            description_parts.append(f"\nMitigation Status: {threat_info['mitigationStatus']}")
        if threat_info.get("mitigationStatusDescription"):
            description_parts.append(f"Actions: {threat_info['mitigationStatusDescription']}")

        description = "\n".join(description_parts)

        # Build tags
        tags = []
        if classification:
            tags.append(f"classification:{classification.lower()}")
        if threat_info.get("mitigationStatus"):
            tags.append(f"status:{threat_info['mitigationStatus'].lower()}")
        for engine in threat_info.get("detectionEngines", []):
            tags.append(f"engine:{engine.lower()}")
        if computer_name:
            tags.append(f"host:{computer_name}")
        if agent_info.get("agentOsName"):
            tags.append(f"os:{agent_info['agentOsName'].lower()}")
        if threat_info.get("sha256"):
            tags.append(f"sha256:{threat_info['sha256'][:16]}...")

        # Extract MITRE info
        mitre_tactics = []
        mitre_techniques = []
        indicators = threat_info.get("indicators", [])
        for indicator in indicators:
            if indicator.get("tactics"):
                mitre_tactics.extend(indicator["tactics"])
            if indicator.get("techniques"):
                mitre_techniques.extend(indicator["techniques"])

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="sentinelone",
            external_id=raw_alert.get("id", str(uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=self.normalize_severity(threat_info.get("confidenceLevel", "medium")),
            status=self.normalize_status(threat_info.get("mitigationStatus", "active")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=threat_info.get("detectionType"),
            rule_name=f"{classification}: {threat_info.get('detectionType', 'Unknown')}" if classification else threat_info.get("detectionType"),
            tags=tags[:20],
            mitre_tactics=list(set(mitre_tactics)),
            mitre_techniques=list(set(mitre_techniques)),
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, confidence_level: str) -> str:
        """Normalize SentinelOne confidence level to standard severity."""
        severity_map = {
            "malicious": "critical",
            "suspicious": "high",
            "n/a": "medium",
        }
        return severity_map.get(confidence_level.lower(), "medium")

    def normalize_status(self, mitigation_status: str) -> str:
        """Normalize SentinelOne mitigation status to standard status."""
        status_map = {
            "active": "open",
            "suspicious": "open",
            "pending": "open",
            "mitigated": "resolved",
            "blocked": "resolved",
            "suspicious_resolved": "resolved",
            "resolved": "resolved",
        }
        return status_map.get(mitigation_status.lower(), "open")
