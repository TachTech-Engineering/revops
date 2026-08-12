"""
Elastic Security Data Source Connector

Integrates with Elastic Security to fetch and normalize detection alerts.
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


class ElasticConnector(DataSourceConnector):
    """
    Elastic Security data source connector.

    Fetches detection alerts from Elastic Security's Detection Engine API
    and normalizes them to the unified alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="elastic",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Elastic Security",
            description="Elastic Security - SIEM and endpoint protection platform",
            icon="elastic",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "Base URL",
                        "description": "Elasticsearch/Kibana URL (e.g., https://elastic.company.com:9200)",
                    },
                    "kibana_url": {
                        "type": "string",
                        "title": "Kibana URL",
                        "description": (
                            "Kibana URL for Security API (optional, defaults to base_url)"
                        ),
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "title": "Verify SSL",
                        "description": "Verify SSL certificates",
                        "default": True,
                    },
                    "space_id": {
                        "type": "string",
                        "title": "Space ID",
                        "description": "Kibana space ID (optional, defaults to 'default')",
                        "default": "default",
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
                        "description": "Elasticsearch username",
                    },
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "description": "Elasticsearch password",
                        "format": "password",
                    },
                    "api_key": {
                        "type": "string",
                        "title": "API Key",
                        "description": "Elasticsearch API key (alternative to username/password)",
                        "format": "password",
                    },
                },
            },
        )

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
        }

        if self.credentials.get("api_key"):
            headers["Authorization"] = f"ApiKey {self.credentials['api_key']}"

        return headers

    def _get_auth(self) -> tuple[str, str] | None:
        """Get basic auth credentials if not using API key."""
        if not self.credentials.get("api_key"):
            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")
            if username and password:
                return (username, password)
        return None

    def _get_kibana_url(self) -> str:
        """Get the Kibana API URL."""
        kibana_url = self.config.get("kibana_url") or self.config.get("base_url", "")
        kibana_url = kibana_url.rstrip("/")
        space_id = self.config.get("space_id", "default")

        if space_id and space_id != "default":
            return f"{kibana_url}/s/{space_id}"
        return kibana_url

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Elastic Security API."""
        start_time = time.time()
        try:
            kibana_url = self._get_kibana_url()
            verify_ssl = self.config.get("verify_ssl", True)

            async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
                response = await client.get(
                    f"{kibana_url}/api/detection_engine/rules/_find",
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    params={"per_page": 1},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Elastic Security",
                    details={
                        "total_rules": data.get("total", 0),
                        "space_id": self.config.get("space_id", "default"),
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check credentials",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Permission denied - check user privileges",
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
        cursor: str | None = None,
    ) -> tuple[list[NormalizedAlert], str | None]:
        """Fetch detection alerts from Elastic Security."""
        try:
            kibana_url = self._get_kibana_url()
            verify_ssl = self.config.get("verify_ssl", True)

            # Build query for alerts
            page = int(cursor) if cursor else 1
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": since.isoformat(),
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": limit,
                "from": (page - 1) * limit,
                "sort": [{"@timestamp": "asc"}],
            }

            async with httpx.AsyncClient(timeout=60.0, verify=verify_ssl) as client:
                response = await client.post(
                    f"{kibana_url}/api/detection_engine/signals/search",
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    json=query,
                )

            if response.status_code != 200:
                raise Exception(f"API returned status {response.status_code}")

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])

            normalized_alerts = []
            for hit in hits:
                normalized = self.normalize_alert(hit)
                normalized_alerts.append(normalized)

            # Calculate next cursor
            next_cursor = None
            total_hits = data.get("hits", {}).get("total", {})
            total = total_hits.get("value", 0) if isinstance(total_hits, dict) else total_hits
            if page * limit < total:
                next_cursor = str(page + 1)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch alerts from Elastic Security: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize an Elastic Security alert to the unified schema."""
        source = raw_alert.get("_source", {})
        signal = source.get("signal", source.get("kibana.alert", {}))
        rule = signal.get("rule", {})

        # Parse timestamps
        timestamp = source.get("@timestamp", datetime.utcnow().isoformat())
        created_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        # Extract MITRE info from rule threat
        threat = rule.get("threat", [])
        tactics = []
        techniques = []
        for t in threat:
            if t.get("tactic", {}).get("id"):
                tactics.append(t["tactic"]["id"])
            for technique in t.get("technique", []):
                if technique.get("id"):
                    techniques.append(technique["id"])

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="elastic",
            external_id=raw_alert.get("_id", source.get("signal.group.id", "")),
            title=rule.get("name", source.get("signal.rule.name", "Elastic Security Alert")),
            description=rule.get("description", ""),
            severity=self.normalize_severity(
                rule.get("severity", source.get("signal.rule.severity", "medium"))
            ),
            status=self.normalize_status(signal.get("status", source.get("signal.status", "open"))),
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=rule.get("id", source.get("signal.rule.id")),
            rule_name=rule.get("name", source.get("signal.rule.name")),
            tags=rule.get("tags", []) or [],
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Elastic severity to standard values."""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return severity_map.get(source_severity.lower(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize Elastic status to standard values."""
        status_map = {
            "open": "open",
            "acknowledged": "acknowledged",
            "in-progress": "acknowledged",
            "closed": "closed",
        }
        return status_map.get(source_status.lower(), "open")
