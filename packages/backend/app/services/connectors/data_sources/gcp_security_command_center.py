"""
Google Cloud Security Command Center Data Source Connector

Integrates with GCP Security Command Center to fetch and normalize security findings.
"""

import time
import uuid
from datetime import datetime
from typing import Any

from app.db.models import ConnectorCategory, NormalizedAlert
from app.services.connectors.base import (
    ConnectionTestResult,
    ConnectorMetadata,
    DataSourceConnector,
)


class GCPSecurityCommandCenterConnector(DataSourceConnector):
    """
    Google Cloud Security Command Center data source connector.

    Fetches security findings from GCP SCC including:
    - Security Health Analytics findings
    - Event Threat Detection findings
    - Container Threat Detection findings
    - Web Security Scanner findings
    - Third-party security tool findings
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="gcp_scc",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Google Cloud SCC",
            description=(
                "Google Cloud Security Command Center - Centralized security findings for GCP"
            ),
            icon="gcp",
            config_schema={
                "type": "object",
                "properties": {
                    "organization_id": {
                        "type": "string",
                        "title": "Organization ID",
                        "description": "GCP organization ID (numeric)",
                    },
                    "project_id": {
                        "type": "string",
                        "title": "Project ID",
                        "description": "GCP project ID (optional, for project-level SCC)",
                    },
                    "source_filter": {
                        "type": "array",
                        "title": "Source Filter",
                        "description": "Only fetch from these sources (empty = all)",
                        "items": {
                            "type": "string",
                            "enum": [
                                "SECURITY_HEALTH_ANALYTICS",
                                "EVENT_THREAT_DETECTION",
                                "CONTAINER_THREAT_DETECTION",
                                "WEB_SECURITY_SCANNER",
                                "SECURITY_CENTER",
                            ],
                        },
                        "default": [],
                    },
                    "severity_filter": {
                        "type": "array",
                        "title": "Severity Filter",
                        "description": "Only fetch findings with these severities",
                        "items": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        },
                        "default": ["CRITICAL", "HIGH", "MEDIUM"],
                    },
                    "state_filter": {
                        "type": "string",
                        "title": "State Filter",
                        "description": "Finding state to fetch",
                        "enum": ["ACTIVE", "INACTIVE", "ALL"],
                        "default": "ACTIVE",
                    },
                },
                "required": ["organization_id"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "service_account_json": {
                        "type": "string",
                        "title": "Service Account JSON",
                        "description": (
                            "GCP service account key JSON "
                            "(with securitycenter.findings.list permission)"
                        ),
                        "format": "password",
                    },
                },
                "required": ["service_account_json"],
            },
        )

    def _get_scc_client(self):
        """Get Google Cloud SCC client."""
        try:
            import json

            from google.cloud import securitycenter_v1
            from google.oauth2 import service_account
        except ImportError:
            raise Exception(
                "google-cloud-securitycenter is required. "
                "Install with: pip install google-cloud-securitycenter"
            )

        # Parse service account JSON
        sa_json = self.credentials.get("service_account_json", "{}")
        if isinstance(sa_json, str):
            sa_info = json.loads(sa_json)
        else:
            sa_info = sa_json

        credentials = service_account.Credentials.from_service_account_info(
            sa_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

        return securitycenter_v1.SecurityCenterClient(credentials=credentials)

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to GCP Security Command Center."""
        start_time = time.time()
        try:
            client = self._get_scc_client()
            org_id = self.config.get("organization_id")

            # Test by listing sources
            parent = f"organizations/{org_id}"
            sources = list(client.list_sources(request={"parent": parent}))

            latency_ms = int((time.time() - start_time) * 1000)

            return ConnectionTestResult(
                success=True,
                message="Successfully connected to GCP Security Command Center",
                details={
                    "organization_id": org_id,
                    "sources_count": len(sources),
                },
                latency_ms=latency_ms,
            )

        except Exception as e:
            error_msg = str(e)
            if "PERMISSION_DENIED" in error_msg:
                error_msg = (
                    "Permission denied - ensure service account has "
                    "securitycenter.findings.list permission"
                )
            elif "NOT_FOUND" in error_msg:
                error_msg = "Organization not found - check organization ID"
            elif "INVALID_ARGUMENT" in error_msg:
                error_msg = "Invalid service account JSON"

            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {error_msg}",
            )

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[NormalizedAlert], str | None]:
        """Fetch findings from GCP Security Command Center."""
        try:
            from google.cloud import securitycenter_v1

            client = self._get_scc_client()
            org_id = self.config.get("organization_id")

            # Build filter
            filter_parts = []

            # Time filter
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_parts.append(f'event_time >= "{since_str}"')

            # State filter
            state_filter = self.config.get("state_filter", "ACTIVE")
            if state_filter != "ALL":
                filter_parts.append(f'state = "{state_filter}"')

            # Severity filter
            severity_filter = self.config.get("severity_filter", ["CRITICAL", "HIGH", "MEDIUM"])
            if severity_filter:
                sev_conditions = " OR ".join([f'severity = "{sev}"' for sev in severity_filter])
                filter_parts.append(f"({sev_conditions})")

            # Source filter
            source_filter = self.config.get("source_filter", [])
            if source_filter:
                # Source names are like "organizations/123/sources/456"
                # We filter by category instead
                cat_conditions = " OR ".join([f'category = "{src}"' for src in source_filter])
                filter_parts.append(f"({cat_conditions})")

            filter_str = " AND ".join(filter_parts)

            # Build request
            parent = f"organizations/{org_id}/sources/-"
            request = securitycenter_v1.ListFindingsRequest(
                parent=parent,
                filter=filter_str,
                page_size=min(limit, 1000),
                order_by="event_time asc",
            )

            if cursor:
                request.page_token = cursor

            # Fetch findings
            response = client.list_findings(request=request)

            findings = []
            next_cursor = None

            # Iterate through the page
            page = next(response.pages)
            for finding_result in page.list_findings_results:
                findings.append(finding_result.finding)

            next_cursor = page.next_page_token if page.next_page_token else None

            # Normalize findings
            normalized_alerts = []
            for finding in findings:
                normalized = self.normalize_alert(self._finding_to_dict(finding))
                normalized_alerts.append(normalized)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch findings from GCP SCC: {str(e)}")

    def _finding_to_dict(self, finding) -> dict[str, Any]:
        """Convert a Finding protobuf to a dictionary."""
        from google.protobuf.json_format import MessageToDict

        return MessageToDict(finding._pb)

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a GCP SCC finding to the unified schema."""
        # Parse timestamps
        created_at = datetime.utcnow()
        if raw_alert.get("eventTime"):
            try:
                created_at = datetime.fromisoformat(raw_alert["eventTime"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Build title
        category = raw_alert.get("category", "Unknown")
        resource_name = (
            raw_alert.get("resourceName", "").split("/")[-1]
            if raw_alert.get("resourceName")
            else "Unknown"
        )
        title = f"{category}: {resource_name}"

        # Build description
        description_parts = []
        description_parts.append(f"Category: {category}")
        description_parts.append(f"State: {raw_alert.get('state', 'Unknown')}")

        if raw_alert.get("description"):
            description_parts.append(f"\n{raw_alert['description']}")

        if raw_alert.get("resourceName"):
            description_parts.append(f"\nResource: {raw_alert['resourceName']}")

        # Add source properties
        source_properties = raw_alert.get("sourceProperties", {})
        if source_properties.get("Explanation"):
            description_parts.append(f"\nExplanation: {source_properties['Explanation']}")
        if source_properties.get("Recommendation"):
            description_parts.append(f"\nRecommendation: {source_properties['Recommendation']}")

        description = "\n".join(description_parts)

        # Build tags
        tags = []
        tags.append(f"category:{category.lower().replace(' ', '_')}")
        tags.append(f"state:{raw_alert.get('state', 'unknown').lower()}")

        # Parse resource for tags
        resource_name_full = raw_alert.get("resourceName", "")
        if "/projects/" in resource_name_full:
            project = resource_name_full.split("/projects/")[1].split("/")[0]
            tags.append(f"project:{project}")

        # Extract MITRE info
        mitre_tactics = []
        mitre_techniques = []
        mitre_attack = raw_alert.get("mitreAttack", {})
        if mitre_attack:
            if mitre_attack.get("primaryTactic"):
                mitre_tactics.append(mitre_attack["primaryTactic"])
            mitre_tactics.extend(mitre_attack.get("additionalTactics", []))
            if mitre_attack.get("primaryTechniques"):
                mitre_techniques.extend(mitre_attack["primaryTechniques"])
            mitre_techniques.extend(mitre_attack.get("additionalTechniques", []))

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="gcp_scc",
            external_id=raw_alert.get("name", str(uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=self.normalize_severity(raw_alert.get("severity", "MEDIUM")),
            status=self.normalize_status(raw_alert.get("state", "ACTIVE")),
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=category,
            rule_name=category,
            tags=tags[:20],
            mitre_tactics=list(set(mitre_tactics)),
            mitre_techniques=list(set(mitre_techniques)),
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize GCP SCC severity to standard values."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }
        return severity_map.get(source_severity.upper(), "medium")

    def normalize_status(self, source_state: str) -> str:
        """Normalize GCP SCC state to standard status."""
        status_map = {
            "ACTIVE": "open",
            "INACTIVE": "closed",
        }
        return status_map.get(source_state.upper(), "open")
