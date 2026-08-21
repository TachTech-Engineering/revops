"""
Prowler Data Source Connector

Integrates with the Prowler App API (Prowler Cloud or self-hosted) to fetch
and normalize cloud security posture findings across AWS, Azure, GCP,
Kubernetes, and other providers.
"""

import time
import uuid
from datetime import datetime
from typing import Any

import httpx

from app.core.time_utils import utcnow
from app.db.models import ConnectorCategory, NormalizedAlert
from app.services.connectors.base import (
    ConnectionTestResult,
    ConnectorMetadata,
    DataSourceConnector,
    StatusPushResult,
)

JSONAPI_CONTENT_TYPE = "application/vnd.api+json"


class ProwlerConnector(DataSourceConnector):
    """
    Prowler data source connector.

    Polls the Prowler API for security findings (misconfigurations and
    compliance failures) and normalizes them to the unified alert schema.

    Works with both Prowler Cloud (https://api.prowler.com) and self-hosted
    Prowler App deployments.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="prowler",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Prowler",
            description=(
                "Prowler - Cloud security posture findings for AWS, Azure, GCP, and Kubernetes"
            ),
            icon="prowler",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "API Base URL",
                        "description": "Prowler API URL (Prowler Cloud or self-hosted)",
                        "default": "https://api.prowler.com",
                    },
                    "only_failed": {
                        "type": "boolean",
                        "title": "Only Failed Findings",
                        "description": "Only ingest findings with status FAIL",
                        "default": True,
                    },
                    "severity_filter": {
                        "type": "array",
                        "title": "Severity Filter",
                        "description": "Only fetch findings with these severities (empty = all)",
                        "items": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "informational"],
                        },
                        "default": ["critical", "high", "medium"],
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "title": "Verify SSL",
                        "description": "Verify SSL certificates (disable for self-signed)",
                        "default": True,
                    },
                },
                "required": ["base_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "title": "Email",
                        "description": "Prowler account email (used to obtain an API token)",
                    },
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "description": "Prowler account password",
                        "format": "password",
                    },
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": (
                            "Static bearer token (used instead of email/password if set)"
                        ),
                        "format": "password",
                    },
                },
                "required": [],
            },
        )

    def _base_url(self) -> str:
        return self.config.get("base_url", "https://api.prowler.com").rstrip("/")

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        """Get a bearer token, either static or via the tokens endpoint."""
        api_token = self.credentials.get("api_token")
        if api_token:
            return api_token

        email = self.credentials.get("email")
        password = self.credentials.get("password")
        if not email or not password:
            raise Exception(
                "Prowler credentials missing: provide either an API token or email + password"
            )

        response = await client.post(
            f"{self._base_url()}/api/v1/tokens",
            json={
                "data": {
                    "type": "tokens",
                    "attributes": {"email": email, "password": password},
                }
            },
            headers={"Content-Type": JSONAPI_CONTENT_TYPE, "Accept": JSONAPI_CONTENT_TYPE},
        )
        if response.status_code == 401:
            raise Exception("Authentication failed: invalid Prowler email or password")
        response.raise_for_status()

        access = response.json().get("data", {}).get("attributes", {}).get("access")
        if not access:
            raise Exception("Prowler token endpoint returned no access token")
        return access

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=30.0,
            verify=self.config.get("verify_ssl", True),
        )

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection by authenticating and fetching a single finding."""
        start_time = time.time()
        try:
            async with self._client() as client:
                token = await self._authenticate(client)

                response = await client.get(
                    f"{self._base_url()}/api/v1/findings",
                    params={"page[size]": 1},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": JSONAPI_CONTENT_TYPE,
                    },
                )
                if response.status_code in (401, 403):
                    return ConnectionTestResult(
                        success=False,
                        message="Authenticated but not authorized to read findings "
                        "(check the account's role/permissions)",
                    )
                response.raise_for_status()

                total = response.json().get("meta", {}).get("pagination", {}).get("count")
                latency_ms = int((time.time() - start_time) * 1000)

                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Prowler API",
                    details={
                        "base_url": self._base_url(),
                        "total_findings": total,
                    },
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
        """Fetch findings from the Prowler API, one page per call."""
        try:
            page = int(cursor) if cursor else 1
        except ValueError:
            page = 1

        params: dict[str, Any] = {
            "page[number]": page,
            "page[size]": min(limit, 100),
            "sort": "inserted_at",
            "filter[inserted_at__gte]": since.date().isoformat(),
        }
        if self.config.get("only_failed", True):
            params["filter[status]"] = "FAIL"
        severity_filter = self.config.get("severity_filter") or []
        if severity_filter:
            params["filter[severity__in]"] = ",".join(severity_filter)

        try:
            async with self._client() as client:
                token = await self._authenticate(client)
                response = await client.get(
                    f"{self._base_url()}/api/v1/findings",
                    params=params,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": JSONAPI_CONTENT_TYPE,
                    },
                )
                response.raise_for_status()
                body = response.json()

            findings = body.get("data", [])
            pagination = body.get("meta", {}).get("pagination", {})
            total_pages = pagination.get("pages", page)
            next_cursor = str(page + 1) if page < total_pages and findings else None

            normalized_alerts = [self.normalize_alert(finding) for finding in findings]
            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch findings from Prowler: {str(e)}")

    async def push_status_update(self, alert, new_status: str) -> StatusPushResult:
        """Prowler findings reflect scan state and cannot be closed remotely."""
        return StatusPushResult(
            supported=False,
            success=False,
            message="Prowler findings track scan results - they resolve in Prowler "
            "when the misconfiguration is fixed and the next scan runs; the API has "
            "no per-finding close",
        )

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Prowler JSON:API finding to the unified schema."""
        attributes = raw_alert.get("attributes", {})
        check_metadata = attributes.get("check_metadata", {}) or {}

        created_at = utcnow()
        if attributes.get("inserted_at"):
            try:
                created_at = datetime.fromisoformat(
                    attributes["inserted_at"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        updated_at = None
        if attributes.get("updated_at"):
            try:
                updated_at = datetime.fromisoformat(attributes["updated_at"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        check_id = attributes.get("check_id") or check_metadata.get("checkid", "")
        title = (
            check_metadata.get("checktitle")
            or attributes.get("status_extended")
            or f"Prowler Finding: {check_id or 'unknown'}"
        )

        description_parts = []
        if attributes.get("status_extended"):
            description_parts.append(attributes["status_extended"])
        if check_metadata.get("description"):
            description_parts.append(check_metadata["description"])
        if check_metadata.get("risk"):
            description_parts.append(f"Risk: {check_metadata['risk']}")
        recommendation = (check_metadata.get("remediation", {}) or {}).get(
            "recommendation", {}
        ) or {}
        if recommendation.get("text"):
            description_parts.append(f"Remediation: {recommendation['text']}")
        description = "\n\n".join(description_parts)

        tags = []
        if check_metadata.get("provider"):
            tags.append(f"provider:{check_metadata['provider']}")
        if check_metadata.get("servicename"):
            tags.append(f"service:{check_metadata['servicename']}")
        if attributes.get("status"):
            tags.append(f"prowler_status:{attributes['status']}")
        for category in check_metadata.get("categories") or []:
            tags.append(f"category:{category}")
        if attributes.get("muted"):
            tags.append("muted")

        # Prowler finding UIDs are stable per (check, account, region, resource),
        # so recurring findings from successive scans dedupe instead of flooding.
        external_id = attributes.get("uid") or raw_alert.get("id") or str(uuid.uuid4())

        status = "open"
        if attributes.get("muted"):
            status = "closed"
        elif str(attributes.get("status", "")).upper() == "PASS":
            status = "resolved"

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="prowler",
            external_id=external_id,
            title=title,
            description=description or None,
            severity=self.normalize_severity(str(attributes.get("severity", "medium"))),
            status=status,
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=check_id,
            rule_name=check_metadata.get("checktitle") or check_id or "Prowler Check",
            tags=tags[:20],
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data=raw_alert,
            ingested_at=utcnow(),
        )
