"""
Google SecOps (Chronicle) Data Source Connector

Integrates with Google SecOps/Chronicle to fetch and normalize alerts.
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


class GoogleSecOpsConnector(DataSourceConnector):
    """
    Google SecOps (Chronicle) data source connector.

    Fetches alerts from Chronicle's Detection API and normalizes them
    to the unified alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="google_secops",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Google SecOps",
            description="Google SecOps (Chronicle) - Cloud-native security operations platform",
            icon="google_secops",
            config_schema={
                "type": "object",
                "properties": {
                    "region": {
                        "type": "string",
                        "title": "Region",
                        "description": "Chronicle region (e.g., us, europe, asia-southeast1)",
                        "enum": ["us", "europe", "asia-southeast1"],
                        "default": "us",
                    },
                    "customer_id": {
                        "type": "string",
                        "title": "Customer ID",
                        "description": "Chronicle customer ID",
                    },
                },
                "required": ["region", "customer_id"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "service_account_json": {
                        "type": "string",
                        "title": "Service Account JSON",
                        "description": "Google Cloud service account credentials JSON",
                        "format": "textarea",
                    },
                },
                "required": ["service_account_json"],
            },
        )

    def _get_api_url(self) -> str:
        """Get the Chronicle API URL based on region."""
        region = self.config.get("region", "us")
        customer_id = self.config.get("customer_id", "")
        return f"https://{region}-chronicle.googleapis.com/v1alpha/projects/{customer_id}/locations/{region}/instances/-"

    async def _get_access_token(self) -> str:
        """Get OAuth2 access token from service account credentials."""
        import json
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request

        try:
            creds_json = json.loads(self.credentials.get("service_account_json", "{}"))
            credentials = service_account.Credentials.from_service_account_info(
                creds_json,
                scopes=["https://www.googleapis.com/auth/chronicle-backstory"]
            )
            credentials.refresh(Request())
            return credentials.token
        except Exception as e:
            raise Exception(f"Failed to get access token: {str(e)}")

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Chronicle API."""
        start_time = time.time()
        try:
            token = await self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self._get_api_url()}/detections",
                    headers=headers,
                    params={"page_size": 1},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Google SecOps",
                    details={"region": self.config.get("region")},
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check service account credentials",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Permission denied - check service account permissions",
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
        """Fetch detections from Chronicle API."""
        try:
            token = await self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            params = {
                "page_size": limit,
                "start_time": since.isoformat() + "Z",
            }
            if cursor:
                params["page_token"] = cursor

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"{self._get_api_url()}/detections",
                    headers=headers,
                    params=params,
                )

            if response.status_code != 200:
                raise Exception(f"API returned status {response.status_code}")

            data = response.json()
            detections = data.get("detections", [])

            normalized_alerts = []
            for detection in detections:
                normalized = self.normalize_alert(detection)
                normalized_alerts.append(normalized)

            next_cursor = data.get("nextPageToken")
            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from Google SecOps: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Chronicle detection to the unified schema."""
        # Parse timestamps
        created_at = datetime.fromisoformat(
            raw_alert.get("createTime", datetime.utcnow().isoformat()).replace("Z", "+00:00")
        )
        updated_at = None
        if raw_alert.get("updateTime"):
            updated_at = datetime.fromisoformat(raw_alert["updateTime"].replace("Z", "+00:00"))

        # Extract rule info from detection
        detection_info = raw_alert.get("detection", {})
        rule_name = detection_info.get("ruleName", raw_alert.get("ruleId", ""))

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="google_secops",
            external_id=raw_alert.get("id", raw_alert.get("name", "")),
            title=rule_name or "Chronicle Detection",
            description=raw_alert.get("description", ""),
            severity=self.normalize_severity(raw_alert.get("severity", "MEDIUM")),
            status=self.normalize_status(raw_alert.get("state", "ACTIVE")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=raw_alert.get("ruleId"),
            rule_name=rule_name,
            tags=raw_alert.get("tags", []) or [],
            mitre_tactics=raw_alert.get("mitreTactics", []) or [],
            mitre_techniques=raw_alert.get("mitreTechniques", []) or [],
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Chronicle severity to standard values."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFORMATIONAL": "info",
        }
        return severity_map.get(source_severity.upper(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize Chronicle state to standard values."""
        status_map = {
            "ACTIVE": "open",
            "ALERTING": "open",
            "NEW": "open",
            "ACKNOWLEDGED": "acknowledged",
            "CLOSED": "closed",
            "RESOLVED": "resolved",
        }
        return status_map.get(source_status.upper(), "open")
