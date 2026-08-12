"""
Microsoft Defender XDR Data Source Connector

Integrates with Microsoft Defender XDR (formerly Microsoft 365 Defender) to fetch
and normalize security alerts and incidents.
"""

import time
import uuid
from datetime import datetime
from typing import Any

import httpx

from app.db.models import ConnectorCategory, NormalizedAlert
from app.services.connectors.base import (
    ConnectionTestResult,
    ConnectorMetadata,
    DataSourceConnector,
)


class MicrosoftDefenderConnector(DataSourceConnector):
    """
    Microsoft Defender XDR data source connector.

    Fetches alerts from Microsoft Defender XDR (unified security portal)
    which includes:
    - Microsoft Defender for Endpoint
    - Microsoft Defender for Office 365
    - Microsoft Defender for Identity
    - Microsoft Defender for Cloud Apps

    Uses Microsoft Graph Security API.
    """

    _access_token: str | None = None
    _token_expires_at: float = 0

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="microsoft_defender",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Microsoft Defender XDR",
            description=(
                "Microsoft Defender XDR - Unified security across endpoints, "
                "email, identity, and cloud apps"
            ),
            icon="microsoft",
            config_schema={
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "title": "Tenant ID",
                        "description": "Azure AD tenant ID (directory ID)",
                    },
                    "fetch_incidents": {
                        "type": "boolean",
                        "title": "Fetch Incidents",
                        "description": "Also fetch incidents (correlated alerts)",
                        "default": True,
                    },
                    "severity_filter": {
                        "type": "array",
                        "title": "Severity Filter",
                        "description": "Only fetch alerts with these severities",
                        "items": {
                            "type": "string",
                            "enum": ["high", "medium", "low", "informational"],
                        },
                        "default": ["high", "medium"],
                    },
                    "service_source_filter": {
                        "type": "array",
                        "title": "Service Source Filter",
                        "description": "Only fetch from these Defender products",
                        "items": {
                            "type": "string",
                            "enum": [
                                "microsoftDefenderForEndpoint",
                                "microsoftDefenderForIdentity",
                                "microsoftDefenderForOffice365",
                                "microsoftCloudAppSecurity",
                                "azureAdIdentityProtection",
                                "microsoftDefenderForCloud",
                            ],
                        },
                        "default": [],
                    },
                },
                "required": ["tenant_id"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "title": "Client ID",
                        "description": "Azure AD application (client) ID",
                    },
                    "client_secret": {
                        "type": "string",
                        "title": "Client Secret",
                        "description": "Azure AD application client secret",
                        "format": "password",
                    },
                },
                "required": ["client_id", "client_secret"],
            },
        )

    async def _get_access_token(self) -> str:
        """Get OAuth2 access token from Azure AD (with caching)."""
        # Return cached token if still valid
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        tenant_id = self.config.get("tenant_id")
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                token_url,
                data={
                    "client_id": self.credentials.get("client_id", ""),
                    "client_secret": self.credentials.get("client_secret", ""),
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )

        if response.status_code != 200:
            raise Exception(f"Failed to get access token: {response.status_code} - {response.text}")

        data = response.json()
        self._access_token = data.get("access_token", "")
        self._token_expires_at = time.time() + data.get("expires_in", 3600)

        return self._access_token

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Microsoft Graph Security API."""
        start_time = time.time()
        try:
            token = await self._get_access_token()

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test by querying alerts (top 1)
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/security/alerts_v2",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"$top": 1},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Microsoft Defender XDR",
                    details={"tenant_id": self.config.get("tenant_id")},
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
                    message="Access denied - ensure app has SecurityAlert.Read.All permission",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}: {response.text}",
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
        cursor: str | None = None,
    ) -> tuple[list[NormalizedAlert], str | None]:
        """Fetch alerts from Microsoft Defender XDR."""
        try:
            token = await self._get_access_token()

            # Build OData filter
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_parts = [f"createdDateTime ge {since_str}"]

            # Add severity filter
            severity_filter = self.config.get("severity_filter", [])
            if severity_filter:
                sev_conditions = " or ".join([f"severity eq '{sev}'" for sev in severity_filter])
                filter_parts.append(f"({sev_conditions})")

            # Add service source filter
            service_filter = self.config.get("service_source_filter", [])
            if service_filter:
                svc_conditions = " or ".join(
                    [f"serviceSource eq '{svc}'" for svc in service_filter]
                )
                filter_parts.append(f"({svc_conditions})")

            odata_filter = " and ".join(filter_parts)

            params = {
                "$filter": odata_filter,
                "$top": min(limit, 100),
                "$orderby": "createdDateTime asc",
            }

            url = cursor if cursor else "https://graph.microsoft.com/v1.0/security/alerts_v2"

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    params=params if not cursor else None,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"Failed to fetch alerts: {response.status_code} - {response.text}"
                    )

                data = response.json()

            alerts = data.get("value", [])
            next_cursor = data.get("@odata.nextLink")

            # Normalize alerts
            normalized_alerts = []
            for alert in alerts:
                normalized = self.normalize_alert(alert)
                normalized_alerts.append(normalized)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from Microsoft Defender: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Microsoft Defender alert to the unified schema."""
        # Parse timestamps
        created_at = datetime.utcnow()
        if raw_alert.get("createdDateTime"):
            try:
                created_at = datetime.fromisoformat(
                    raw_alert["createdDateTime"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        updated_at = None
        if raw_alert.get("lastUpdateDateTime"):
            try:
                updated_at = datetime.fromisoformat(
                    raw_alert["lastUpdateDateTime"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # Build description
        description = raw_alert.get("description", "")

        # Add evidence summary
        evidence = raw_alert.get("evidence", [])
        if evidence:
            evidence_summary = []
            for e in evidence[:5]:  # Limit to 5 evidence items
                e_type = e.get("@odata.type", "").replace("#microsoft.graph.security.", "")
                if e.get("deviceDnsName"):
                    evidence_summary.append(f"{e_type}: {e['deviceDnsName']}")
                elif e.get("fileName"):
                    evidence_summary.append(f"{e_type}: {e['fileName']}")
                elif e.get("userAccount", {}).get("accountName"):
                    evidence_summary.append(f"{e_type}: {e['userAccount']['accountName']}")
            if evidence_summary:
                description += f"\n\nEvidence: {', '.join(evidence_summary)}"

        # Extract MITRE info
        mitre_tactics = []
        mitre_techniques = []
        for technique in raw_alert.get("mitreTechniques", []):
            # Format: T1234.001 or just T1234
            mitre_techniques.append(technique)

        # Microsoft provides tactics in the alert
        if raw_alert.get("tactics"):
            mitre_tactics = raw_alert["tactics"]

        # Build tags
        tags = []
        if raw_alert.get("serviceSource"):
            tags.append(f"source:{raw_alert['serviceSource']}")
        if raw_alert.get("detectionSource"):
            tags.append(f"detection:{raw_alert['detectionSource']}")
        if raw_alert.get("category"):
            tags.append(f"category:{raw_alert['category']}")
        for evidence_item in evidence[:3]:
            if evidence_item.get("deviceDnsName"):
                tags.append(f"host:{evidence_item['deviceDnsName']}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="microsoft_defender",
            external_id=raw_alert.get("id", str(uuid.uuid4())),
            title=raw_alert.get("title", "Microsoft Defender Alert")[:500],
            description=description[:2000] if description else None,
            severity=self.normalize_severity(raw_alert.get("severity", "medium")),
            status=self.normalize_status(raw_alert.get("status", "new")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=raw_alert.get("detectorId"),
            rule_name=raw_alert.get("category") or raw_alert.get("title", "")[:100],
            tags=tags[:20],
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Microsoft severity to standard values."""
        severity_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "unknown": "medium",
        }
        return severity_map.get(source_severity.lower(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize Microsoft status to standard values."""
        status_map = {
            "new": "open",
            "inProgress": "acknowledged",
            "resolved": "resolved",
            "unknownFutureValue": "open",
        }
        return status_map.get(source_status, "open")
