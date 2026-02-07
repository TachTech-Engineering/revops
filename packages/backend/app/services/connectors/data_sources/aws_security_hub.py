"""
AWS Security Hub Data Source Connector

Integrates with AWS Security Hub to fetch and normalize security findings.
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


class AWSSecurityHubConnector(DataSourceConnector):
    """
    AWS Security Hub data source connector.

    Fetches security findings from AWS Security Hub and normalizes them
    to the unified alert schema.

    Supports findings from:
    - AWS GuardDuty
    - AWS Inspector
    - AWS Macie
    - AWS IAM Access Analyzer
    - Third-party integrations
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="aws_security_hub",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="AWS Security Hub",
            description="AWS Security Hub - Centralized security findings from AWS services",
            icon="aws",
            config_schema={
                "type": "object",
                "properties": {
                    "region": {
                        "type": "string",
                        "title": "AWS Region",
                        "description": "AWS region for Security Hub",
                        "default": "us-east-1",
                    },
                    "account_id": {
                        "type": "string",
                        "title": "AWS Account ID",
                        "description": "AWS account ID (optional, for cross-account)",
                    },
                    "severity_filter": {
                        "type": "array",
                        "title": "Severity Filter",
                        "description": "Only fetch findings with these severities",
                        "items": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                        },
                        "default": ["CRITICAL", "HIGH", "MEDIUM"],
                    },
                    "product_filter": {
                        "type": "array",
                        "title": "Product Filter",
                        "description": "Only fetch findings from these products (empty = all)",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "required": ["region"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "access_key_id": {
                        "type": "string",
                        "title": "AWS Access Key ID",
                        "description": "AWS IAM access key ID",
                    },
                    "secret_access_key": {
                        "type": "string",
                        "title": "AWS Secret Access Key",
                        "description": "AWS IAM secret access key",
                        "format": "password",
                    },
                    "session_token": {
                        "type": "string",
                        "title": "Session Token",
                        "description": "AWS session token (optional, for temporary credentials)",
                        "format": "password",
                    },
                    "role_arn": {
                        "type": "string",
                        "title": "IAM Role ARN",
                        "description": "IAM role to assume (optional, for cross-account access)",
                    },
                },
                "required": ["access_key_id", "secret_access_key"],
            },
        )

    def _get_boto3_client(self):
        """Get boto3 Security Hub client."""
        try:
            import boto3
        except ImportError:
            raise Exception("boto3 is required for AWS Security Hub connector. Install with: pip install boto3")

        region = self.config.get("region", "us-east-1")

        session_kwargs = {
            "aws_access_key_id": self.credentials.get("access_key_id"),
            "aws_secret_access_key": self.credentials.get("secret_access_key"),
            "region_name": region,
        }

        if self.credentials.get("session_token"):
            session_kwargs["aws_session_token"] = self.credentials["session_token"]

        session = boto3.Session(**session_kwargs)

        # If role ARN is provided, assume the role
        if self.credentials.get("role_arn"):
            sts_client = session.client("sts")
            assumed_role = sts_client.assume_role(
                RoleArn=self.credentials["role_arn"],
                RoleSessionName="RevOpsSecurityHub",
            )
            credentials = assumed_role["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=region,
            )

        return session.client("securityhub")

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to AWS Security Hub."""
        start_time = time.time()
        try:
            client = self._get_boto3_client()

            # Test by describing the hub
            response = client.describe_hub()

            latency_ms = int((time.time() - start_time) * 1000)

            return ConnectionTestResult(
                success=True,
                message="Successfully connected to AWS Security Hub",
                details={
                    "hub_arn": response.get("HubArn"),
                    "subscribed_at": str(response.get("SubscribedAt")),
                },
                latency_ms=latency_ms,
            )

        except Exception as e:
            error_msg = str(e)
            if "AccessDenied" in error_msg:
                error_msg = "Access denied - check IAM permissions (securityhub:DescribeHub, securityhub:GetFindings)"
            elif "InvalidAccessKeyId" in error_msg:
                error_msg = "Invalid AWS access key ID"
            elif "SignatureDoesNotMatch" in error_msg:
                error_msg = "Invalid AWS secret access key"

            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {error_msg}",
            )

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        """Fetch findings from AWS Security Hub."""
        try:
            client = self._get_boto3_client()

            # Build filters
            filters = {
                "UpdatedAt": [
                    {
                        "Start": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "End": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    }
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [
                    {"Value": "NEW", "Comparison": "EQUALS"},
                    {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                ],
            }

            # Add severity filter
            severity_filter = self.config.get("severity_filter", ["CRITICAL", "HIGH", "MEDIUM"])
            if severity_filter:
                filters["SeverityLabel"] = [
                    {"Value": sev, "Comparison": "EQUALS"} for sev in severity_filter
                ]

            # Add product filter
            product_filter = self.config.get("product_filter", [])
            if product_filter:
                filters["ProductName"] = [
                    {"Value": prod, "Comparison": "EQUALS"} for prod in product_filter
                ]

            # Fetch findings
            kwargs = {
                "Filters": filters,
                "MaxResults": min(limit, 100),  # AWS max is 100
            }
            if cursor:
                kwargs["NextToken"] = cursor

            response = client.get_findings(**kwargs)

            findings = response.get("Findings", [])
            next_cursor = response.get("NextToken")

            # Normalize findings
            normalized_alerts = []
            for finding in findings:
                normalized = self.normalize_alert(finding)
                normalized_alerts.append(normalized)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch findings from AWS Security Hub: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize an AWS Security Hub finding to the unified schema."""
        # Parse timestamps
        created_at = datetime.utcnow()
        if raw_alert.get("CreatedAt"):
            try:
                created_at = datetime.fromisoformat(raw_alert["CreatedAt"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        updated_at = None
        if raw_alert.get("UpdatedAt"):
            try:
                updated_at = datetime.fromisoformat(raw_alert["UpdatedAt"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Extract product info
        product_name = raw_alert.get("ProductName", "AWS Security Hub")
        generator_id = raw_alert.get("GeneratorId", "")

        # Build title
        title = raw_alert.get("Title", "AWS Security Hub Finding")

        # Build description
        description = raw_alert.get("Description", "")
        if raw_alert.get("Remediation", {}).get("Recommendation", {}).get("Text"):
            description += f"\n\nRemediation: {raw_alert['Remediation']['Recommendation']['Text']}"

        # Extract resources
        resources = raw_alert.get("Resources", [])
        resource_tags = []
        for resource in resources:
            resource_type = resource.get("Type", "Unknown")
            resource_id = resource.get("Id", "")
            resource_tags.append(f"{resource_type}:{resource_id}")

        # Extract MITRE info if available
        mitre_tactics = []
        mitre_techniques = []
        for finding_provider in raw_alert.get("FindingProviderFields", {}).get("Types", []):
            if "TTPs/" in finding_provider:
                parts = finding_provider.split("/")
                if len(parts) >= 2:
                    mitre_tactics.append(parts[1])
                if len(parts) >= 3:
                    mitre_techniques.append(parts[2])

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="aws_security_hub",
            external_id=raw_alert.get("Id", str(uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=self.normalize_severity(raw_alert.get("Severity", {}).get("Label", "MEDIUM")),
            status=self.normalize_status(raw_alert.get("Workflow", {}).get("Status", "NEW")),
            created_at_source=created_at,
            updated_at_source=updated_at,
            rule_id=generator_id,
            rule_name=f"{product_name}: {generator_id.split('/')[-1]}" if generator_id else product_name,
            tags=resource_tags[:20],
            mitre_tactics=list(set(mitre_tactics)),
            mitre_techniques=list(set(mitre_techniques)),
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize AWS severity to standard values."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFORMATIONAL": "info",
        }
        return severity_map.get(source_severity.upper(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """Normalize AWS workflow status to standard values."""
        status_map = {
            "NEW": "open",
            "NOTIFIED": "open",
            "SUPPRESSED": "closed",
            "RESOLVED": "resolved",
        }
        return status_map.get(source_status.upper(), "open")
