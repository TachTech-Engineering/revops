"""
Splunk Enterprise Security Data Source Connector

Integrates with Splunk ES to fetch and normalize notable events/alerts.
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


class SplunkConnector(DataSourceConnector):
    """
    Splunk Enterprise Security data source connector.

    Fetches notable events from Splunk ES and normalizes them
    to the unified alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="splunk",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Splunk",
            description="Splunk Enterprise Security - SIEM and security analytics platform",
            icon="splunk",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "Base URL",
                        "description": "Splunk server URL (e.g., https://splunk.company.com:8089)",
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "title": "Verify SSL",
                        "description": "Verify SSL certificates",
                        "default": True,
                    },
                    "index": {
                        "type": "string",
                        "title": "Index",
                        "description": "Splunk index for notable events",
                        "default": "notable",
                    },
                },
                "required": ["base_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "title": "Username",
                        "description": "Splunk username",
                    },
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "description": "Splunk password",
                        "format": "password",
                    },
                    "token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "Splunk API token (alternative to username/password)",
                        "format": "password",
                    },
                },
            },
        )

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}

        if self.credentials.get("token"):
            headers["Authorization"] = f"Bearer {self.credentials['token']}"
        else:
            # Basic auth will be handled by httpx
            pass

        return headers

    def _get_auth(self) -> tuple[str, str] | None:
        """Get basic auth credentials if not using token."""
        if not self.credentials.get("token"):
            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")
            if username and password:
                return (username, password)
        return None

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Splunk API."""
        start_time = time.time()
        try:
            base_url = self.config.get("base_url", "").rstrip("/")
            verify_ssl = self.config.get("verify_ssl", True)

            async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
                response = await client.get(
                    f"{base_url}/services/server/info",
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    params={"output_mode": "json"},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                server_info = data.get("entry", [{}])[0].get("content", {})
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Splunk",
                    details={
                        "version": server_info.get("version"),
                        "server_name": server_info.get("serverName"),
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check credentials",
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
        """Fetch notable events from Splunk ES."""
        try:
            base_url = self.config.get("base_url", "").rstrip("/")
            verify_ssl = self.config.get("verify_ssl", True)
            index = self.config.get("index", "notable")

            # Build SPL search for notable events
            earliest = since.strftime("%Y-%m-%dT%H:%M:%S")
            offset = int(cursor) if cursor else 0

            search_query = f'search index={index} earliest="{earliest}" | head {limit + offset} | tail {limit}'

            async with httpx.AsyncClient(timeout=120.0, verify=verify_ssl) as client:
                # Create a search job
                response = await client.post(
                    f"{base_url}/services/search/jobs",
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    data={
                        "search": search_query,
                        "output_mode": "json",
                        "exec_mode": "blocking",
                    },
                )

                if response.status_code != 201:
                    raise Exception(f"Failed to create search job: {response.status_code}")

                job_data = response.json()
                job_id = job_data.get("sid")

                # Get results
                results_response = await client.get(
                    f"{base_url}/services/search/jobs/{job_id}/results",
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    params={"output_mode": "json", "count": limit},
                )

            if results_response.status_code != 200:
                raise Exception(f"Failed to get results: {results_response.status_code}")

            data = results_response.json()
            events = data.get("results", [])

            normalized_alerts = []
            for event in events:
                normalized = self.normalize_alert(event)
                normalized_alerts.append(normalized)

            # Calculate next cursor
            next_cursor = None
            if len(events) == limit:
                next_cursor = str(offset + limit)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from Splunk: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Splunk notable event to the unified schema."""
        # Parse timestamps
        event_time = raw_alert.get("_time", raw_alert.get("info_min_time", ""))
        created_at = datetime.utcnow()
        if event_time:
            try:
                created_at = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Extract rule info
        rule_name = raw_alert.get("rule_name", raw_alert.get("search_name", ""))
        rule_id = raw_alert.get("rule_id", raw_alert.get("event_id", ""))

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="splunk",
            external_id=raw_alert.get("event_id", raw_alert.get("_serial", str(uuid.uuid4()))),
            title=rule_name or raw_alert.get("_raw", "Splunk Notable Event")[:200],
            description=raw_alert.get("description", raw_alert.get("_raw", "")),
            severity=self.normalize_severity(raw_alert.get("urgency", raw_alert.get("severity", "medium"))),
            status=self.normalize_status(raw_alert.get("status", raw_alert.get("status_label", "new"))),
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=rule_id,
            rule_name=rule_name,
            tags=raw_alert.get("tag", "").split(",") if raw_alert.get("tag") else [],
            mitre_tactics=raw_alert.get("mitre_tactic", "").split("|") if raw_alert.get("mitre_tactic") else [],
            mitre_techniques=raw_alert.get("mitre_technique", "").split("|") if raw_alert.get("mitre_technique") else [],
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Splunk urgency/severity to standard values."""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
        }
        return severity_map.get(source_severity.lower(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize Splunk status to standard values."""
        status_map = {
            "new": "open",
            "unassigned": "open",
            "in progress": "acknowledged",
            "pending": "acknowledged",
            "resolved": "resolved",
            "closed": "closed",
        }
        return status_map.get(source_status.lower(), "open")
