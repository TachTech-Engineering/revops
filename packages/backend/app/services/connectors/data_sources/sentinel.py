"""
Microsoft Sentinel Data Source Connector

Integrates with Microsoft Sentinel to fetch and normalize security alerts.
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


class SentinelConnector(DataSourceConnector):
    """
    Microsoft Sentinel data source connector.

    Fetches security alerts from Sentinel via Azure Security Insights API
    and normalizes them to the unified alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="sentinel",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Microsoft Sentinel",
            description="Microsoft Sentinel - Cloud-native SIEM on Azure",
            icon="sentinel",
            config_schema={
                "type": "object",
                "properties": {
                    "subscription_id": {
                        "type": "string",
                        "title": "Subscription ID",
                        "description": "Azure subscription ID",
                    },
                    "resource_group": {
                        "type": "string",
                        "title": "Resource Group",
                        "description": "Azure resource group containing Sentinel workspace",
                    },
                    "workspace_name": {
                        "type": "string",
                        "title": "Workspace Name",
                        "description": "Log Analytics workspace name",
                    },
                },
                "required": ["subscription_id", "resource_group", "workspace_name"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "title": "Tenant ID",
                        "description": "Azure AD tenant ID",
                    },
                    "client_id": {
                        "type": "string",
                        "title": "Client ID",
                        "description": "Azure AD application (client) ID",
                    },
                    "client_secret": {
                        "type": "string",
                        "title": "Client Secret",
                        "description": "Azure AD client secret",
                        "format": "password",
                    },
                },
                "required": ["tenant_id", "client_id", "client_secret"],
            },
        )

    async def _get_access_token(self) -> str:
        """Get OAuth2 access token from Azure AD."""
        tenant_id = self.credentials.get("tenant_id", "")
        client_id = self.credentials.get("client_id", "")
        client_secret = self.credentials.get("client_secret", "")

        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://management.azure.com/.default",
                },
            )

        if response.status_code != 200:
            raise Exception(f"Failed to get access token: {response.status_code}")

        data = response.json()
        return data.get("access_token", "")

    def _get_api_url(self) -> str:
        """Get the Sentinel API URL."""
        subscription_id = self.config.get("subscription_id", "")
        resource_group = self.config.get("resource_group", "")
        workspace_name = self.config.get("workspace_name", "")

        return (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights"
        )

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Sentinel API."""
        start_time = time.time()
        try:
            token = await self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self._get_api_url()}/incidents?api-version=2023-02-01&$top=1",
                    headers=headers,
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Microsoft Sentinel",
                    details={
                        "workspace": self.config.get("workspace_name"),
                        "subscription": self.config.get("subscription_id"),
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check Azure AD credentials",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Permission denied - check Azure RBAC permissions",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}",
                    details={"response": response.text[:500]},
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
        """Fetch incidents/alerts from Sentinel API."""
        try:
            token = await self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            # Build filter for time-based query
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            params = {
                "api-version": "2023-02-01",
                "$top": limit,
                "$filter": f"properties/createdTimeUtc ge {since_str}",
                "$orderby": "properties/createdTimeUtc asc",
            }

            url = f"{self._get_api_url()}/incidents"
            if cursor:
                url = cursor  # Azure uses full URL as cursor

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    url, headers=headers, params=params if not cursor else None
                )

            if response.status_code != 200:
                raise Exception(f"API returned status {response.status_code}")

            data = response.json()
            incidents = data.get("value", [])

            normalized_alerts = []
            for incident in incidents:
                normalized = self.normalize_alert(incident)
                normalized_alerts.append(normalized)

            # Azure uses nextLink for pagination
            next_cursor = data.get("nextLink")
            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from Sentinel: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Sentinel incident to the unified schema."""
        properties = raw_alert.get("properties", {})

        # Parse timestamps
        created_at = datetime.fromisoformat(
            properties.get("createdTimeUtc", datetime.utcnow().isoformat()).replace("Z", "+00:00")
        )
        updated_at = None
        if properties.get("lastModifiedTimeUtc"):
            updated_at = datetime.fromisoformat(
                properties["lastModifiedTimeUtc"].replace("Z", "+00:00")
            )

        # Extract labels as tags
        labels = properties.get("labels", [])
        tags = [label.get("labelName", "") for label in labels if label.get("labelName")]

        # Extract MITRE info from additional data
        additional_data = properties.get("additionalData", {})
        tactics = additional_data.get("tactics", [])
        techniques = additional_data.get("techniques", [])

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="sentinel",
            external_id=raw_alert.get("name", properties.get("incidentNumber", "")),
            title=properties.get("title", "Sentinel Incident"),
            description=properties.get("description", ""),
            severity=self.normalize_severity(properties.get("severity", "Medium")),
            status=self.normalize_status(properties.get("status", "New")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=properties.get("relatedAnalyticRuleIds", [""])[0]
            if properties.get("relatedAnalyticRuleIds")
            else None,
            rule_name=None,  # Would need additional API call
            tags=tags,
            mitre_tactics=tactics if isinstance(tactics, list) else [],
            mitre_techniques=techniques if isinstance(techniques, list) else [],
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Sentinel severity to standard values."""
        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
        }
        return severity_map.get(source_severity, "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize Sentinel status to standard values."""
        status_map = {
            "New": "open",
            "Active": "acknowledged",
            "Closed": "closed",
        }
        return status_map.get(source_status, "open")
