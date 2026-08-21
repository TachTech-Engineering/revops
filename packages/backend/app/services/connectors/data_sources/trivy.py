"""
Trivy Data Source Connector

Integrates with Trivy (https://trivy.dev), the open-source vulnerability
scanner. Scan reports are pushed to the ingest webhook
(POST /api/v1/ingest/trivy/{connector_id}) -- typically from a CI job or a
cron running `trivy image --format json ... | curl`; this connector drains the
buffered reports on the normal sync cycle and expands each report into one
normalized alert per finding (vulnerability, misconfiguration, or secret).

Together with Prowler (posture) and Falco (runtime), this closes the workload
vulnerability gap of the CNAPP story; the attack path engine correlates the
three per asset.
"""

import hashlib
import uuid
from datetime import datetime
from typing import Any

from app.core.time_utils import utcnow
from app.db.models import ConnectorCategory, NormalizedAlert
from app.services.connectors.base import (
    ConnectionTestResult,
    ConnectorMetadata,
    DataSourceConnector,
    StatusPushResult,
)

SEVERITY_ORDER = ["unknown", "low", "medium", "high", "critical"]

# Trivy result classes and the report keys that hold their findings
FINDING_KINDS = [
    ("vulnerabilities", "Vulnerabilities"),
    ("misconfigurations", "Misconfigurations"),
    ("secrets", "Secrets"),
]


class TrivyConnector(DataSourceConnector):
    """
    Trivy vulnerability scanner data source connector.

    Receives Trivy JSON reports (image, filesystem, repo, or config scans)
    pushed to the ingest webhook and normalizes each finding to the unified
    alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="trivy",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Trivy",
            description=(
                "Trivy - Vulnerability, misconfiguration, and secrets findings "
                "for container images, filesystems, and IaC (webhook push)"
            ),
            icon="trivy",
            config_schema={
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "title": "Minimum Severity",
                        "description": "Only ingest findings at or above this severity",
                        "enum": ["unknown", "low", "medium", "high", "critical"],
                        "default": "high",
                    },
                    "include_classes": {
                        "type": "array",
                        "title": "Finding Classes",
                        "description": "Which Trivy finding classes to ingest",
                        "items": {
                            "type": "string",
                            "enum": ["vulnerabilities", "misconfigurations", "secrets"],
                        },
                        "default": ["vulnerabilities", "misconfigurations", "secrets"],
                    },
                    "only_fixed": {
                        "type": "boolean",
                        "title": "Only Fixable Vulnerabilities",
                        "description": "Only ingest vulnerabilities that have a fixed version",
                        "default": False,
                    },
                },
                "required": [],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "ingest_token": {
                        "type": "string",
                        "title": "Ingest Token",
                        "description": "Shared secret the scan job must send when posting "
                        "reports (Authorization: Bearer header, X-Ingest-Token header, "
                        "or ?token= query param)",
                        "format": "password",
                    },
                },
                "required": ["ingest_token"],
            },
        )

    def _webhook_path(self) -> str:
        return f"/api/v1/ingest/trivy/{self.connector_id}"

    async def test_connection(self) -> ConnectionTestResult:
        """Confirm the ingest endpoint is ready and report setup instructions."""
        try:
            from app.db.session import AsyncSessionLocal
            from app.services.ingest_buffer import count_pending

            if not self.credentials.get("ingest_token"):
                return ConnectionTestResult(
                    success=False,
                    message="No ingest token configured - set one so the webhook can "
                    "authenticate the scan job",
                )

            async with AsyncSessionLocal() as db:
                buffered = await count_pending(db, self.connector_id)

            return ConnectionTestResult(
                success=True,
                message="Ingest endpoint is ready. POST Trivy JSON reports to it "
                "from your scan job or CI pipeline.",
                details={
                    "mode": "webhook",
                    "webhook_path": self._webhook_path(),
                    "buffered_reports": buffered,
                    "instructions": "trivy image --format json <image> | "
                    "curl -X POST <server>"
                    + self._webhook_path()
                    + " -H 'Authorization: Bearer <ingest token>' "
                    "-H 'Content-Type: application/json' --data-binary @-",
                },
                latency_ms=0,
            )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Trivy ingest error: {str(e)}",
            )

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[NormalizedAlert], str | None]:
        """Drain buffered reports and expand them into per-finding alerts.

        limit bounds the number of *reports* claimed, not findings; one image
        report routinely expands to hundreds of findings, so claim few reports
        per cycle and let the cursor keep the sync loop draining.
        """
        from app.db.session import AsyncSessionLocal
        from app.services.ingest_buffer import claim_events, count_pending

        reports_per_cycle = max(1, min(limit // 10, 10))
        async with AsyncSessionLocal() as db:
            events = await claim_events(db, self.connector_id, reports_per_cycle)
            await db.commit()

        normalized_alerts = []
        for event in events:
            normalized_alerts.extend(self._expand_report(event.payload))

        async with AsyncSessionLocal() as db:
            remaining = await count_pending(db, self.connector_id)
        next_cursor = "more" if remaining > 0 else None
        return normalized_alerts, next_cursor

    def _expand_report(self, report: dict[str, Any]) -> list[NormalizedAlert]:
        """Expand one Trivy JSON report into per-finding normalized alerts."""
        min_severity = str(self.config.get("min_severity", "high")).lower()
        min_rank = (
            SEVERITY_ORDER.index(min_severity)
            if min_severity in SEVERITY_ORDER
            else SEVERITY_ORDER.index("high")
        )
        include_classes = set(
            self.config.get("include_classes")
            or ["vulnerabilities", "misconfigurations", "secrets"]
        )
        only_fixed = bool(self.config.get("only_fixed", False))

        artifact = report.get("ArtifactName", "unknown")
        artifact_type = report.get("ArtifactType", "unknown")
        created_at = report.get("CreatedAt")

        alerts = []
        for result in report.get("Results") or []:
            target = result.get("Target", artifact)
            result_class = result.get("Class", "")
            for kind, key in FINDING_KINDS:
                if kind not in include_classes:
                    continue
                for finding in result.get(key) or []:
                    severity = str(finding.get("Severity", "UNKNOWN")).lower()
                    rank = (
                        SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0
                    )
                    if rank < min_rank:
                        continue
                    if (
                        kind == "vulnerabilities"
                        and only_fixed
                        and not finding.get("FixedVersion")
                    ):
                        continue
                    alerts.append(
                        self.normalize_alert(
                            {
                                "finding_kind": kind,
                                "artifact": artifact,
                                "artifact_type": artifact_type,
                                "target": target,
                                "class": result_class,
                                "created_at": created_at,
                                "data": finding,
                            }
                        )
                    )
        return alerts

    async def push_status_update(self, alert, new_status: str) -> StatusPushResult:
        """Trivy reports are point-in-time scans; there is no finding to update."""
        return StatusPushResult(
            supported=False,
            success=False,
            message="Trivy findings track scan results - they resolve when the "
            "vulnerable package is patched and the next scan runs; there is no "
            "per-finding state in Trivy",
        )

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize one expanded Trivy finding to the unified schema."""
        kind = raw_alert.get("finding_kind", "vulnerabilities")
        artifact = raw_alert.get("artifact", "unknown")
        data = raw_alert.get("data", {}) or {}

        created_at = utcnow()
        if raw_alert.get("created_at"):
            try:
                created_at = datetime.fromisoformat(
                    str(raw_alert["created_at"]).replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        tags = [
            f"artifact:{artifact}",
            f"artifact_type:{raw_alert.get('artifact_type', 'unknown')}",
            f"class:{raw_alert.get('class', '')}",
        ]

        if kind == "vulnerabilities":
            vuln_id = data.get("VulnerabilityID", "UNKNOWN")
            pkg = data.get("PkgName", "unknown")
            installed = data.get("InstalledVersion", "")
            fixed = data.get("FixedVersion", "")
            rule_id = vuln_id
            title = f"Trivy: {vuln_id} in {pkg} ({artifact})"
            description_parts = []
            if data.get("Title"):
                description_parts.append(data["Title"])
            if data.get("Description"):
                description_parts.append(data["Description"])
            description_parts.append(
                f"Package: {pkg} {installed}"
                + (f" (fixed in {fixed})" if fixed else " (no fix available)")
            )
            if data.get("PrimaryURL"):
                description_parts.append(f"Reference: {data['PrimaryURL']}")
            description = "\n\n".join(description_parts)
            tags.append(f"pkg:{pkg}")
            if vuln_id.upper().startswith("CVE-"):
                tags.append(f"cve:{vuln_id.upper()}")
            tags.append("fix_available" if fixed else "no_fix")
            fingerprint_src = f"{artifact}|{vuln_id}|{pkg}|{installed}"
        elif kind == "misconfigurations":
            check_id = data.get("AVDID") or data.get("ID", "UNKNOWN")
            rule_id = check_id
            title = f"Trivy: {data.get('Title', check_id)} ({raw_alert.get('target', artifact)})"
            description_parts = []
            if data.get("Message"):
                description_parts.append(data["Message"])
            if data.get("Description"):
                description_parts.append(data["Description"])
            if data.get("Resolution"):
                description_parts.append(f"Resolution: {data['Resolution']}")
            description = "\n\n".join(description_parts)
            tags.append(f"check:{check_id}")
            fingerprint_src = f"{artifact}|{check_id}|{raw_alert.get('target', '')}"
        else:  # secrets
            rule_id = data.get("RuleID", "secret")
            title = (
                f"Trivy: exposed secret - {data.get('Title', rule_id)} "
                f"({raw_alert.get('target', artifact)})"
            )
            description = (
                f"Secret matching rule '{rule_id}' found in "
                f"{raw_alert.get('target', artifact)}"
                + (f" at line {data['StartLine']}" if data.get("StartLine") else "")
                + ". Rotate the credential and remove it from the artifact."
            )
            tags.append(f"secret_rule:{rule_id}")
            if data.get("Category"):
                tags.append(f"category:{data['Category']}")
            fingerprint_src = (
                f"{artifact}|{rule_id}|{raw_alert.get('target', '')}|{data.get('StartLine', '')}"
            )

        tags.append(f"trivy_kind:{kind}")

        # Trivy findings have no native ID; derive a stable one so the same
        # finding across repeated scans of the same artifact dedupes.
        fingerprint = hashlib.sha256(fingerprint_src.encode()).hexdigest()
        external_id = f"trivy-{fingerprint[:32]}"

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="trivy",
            external_id=external_id,
            title=title,
            description=description or None,
            severity=self.normalize_severity(str(data.get("Severity", "UNKNOWN"))),
            status="open",
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=rule_id,
            rule_name=rule_id,
            tags=tags[:20],
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data=raw_alert,
            ingested_at=utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Trivy severity to standard values."""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "unknown": "info",
        }
        return severity_map.get(source_severity.lower(), "medium")
