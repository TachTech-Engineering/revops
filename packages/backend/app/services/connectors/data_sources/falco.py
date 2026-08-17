"""
Falco Data Source Connector

Integrates with Falco runtime security. Falco pushes alerts to the ingest
webhook (POST /api/v1/ingest/falco/{connector_id}) via its http_output or
Falcosidekick; this connector drains the buffered events on the normal sync
cycle and normalizes them to the unified alert schema.
"""

import hashlib
import re
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

# Falco priorities, lowest to highest
PRIORITY_ORDER = [
    "debug",
    "informational",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
]

# Matches MITRE technique IDs in Falco rule tags (e.g. T1555, T1059.004)
MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class FalcoConnector(DataSourceConnector):
    """
    Falco runtime security data source connector.

    Receives Falco alerts (syscall, k8s audit, and plugin events) pushed via
    Falco's http_output or Falcosidekick and normalizes them to the unified
    alert schema.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="falco",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Falco",
            description=(
                "Falco - Runtime security alerts for containers, Kubernetes, "
                "and hosts (webhook push)"
            ),
            icon="falco",
            config_schema={
                "type": "object",
                "properties": {
                    "min_priority": {
                        "type": "string",
                        "title": "Minimum Priority",
                        "description": "Only ingest alerts at or above this Falco priority",
                        "enum": [
                            "debug",
                            "informational",
                            "notice",
                            "warning",
                            "error",
                            "critical",
                            "alert",
                            "emergency",
                        ],
                        "default": "notice",
                    },
                    "rule_filter": {
                        "type": "array",
                        "title": "Rule Filter",
                        "description": "Only ingest alerts from these Falco rules (empty = all)",
                        "items": {"type": "string"},
                        "default": [],
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
                        "description": "Shared secret Falco must send when posting alerts "
                        "(Authorization: Bearer header, X-Falco-Token header, "
                        "or ?token= query param)",
                        "format": "password",
                    },
                },
                "required": ["ingest_token"],
            },
        )

    def _webhook_path(self) -> str:
        return f"/api/v1/ingest/falco/{self.connector_id}"

    async def test_connection(self) -> ConnectionTestResult:
        """Confirm the ingest endpoint is ready and report setup instructions."""
        try:
            from app.services.falco_event_buffer import get_falco_event_buffer

            if not self.credentials.get("ingest_token"):
                return ConnectionTestResult(
                    success=False,
                    message="No ingest token configured - set one so the webhook can "
                    "authenticate Falco",
                )

            buffered = get_falco_event_buffer().size(self.connector_id)

            return ConnectionTestResult(
                success=True,
                message="Ingest endpoint is ready. Point Falco's http_output or "
                "Falcosidekick webhook at this server.",
                details={
                    "mode": "webhook",
                    "webhook_path": self._webhook_path(),
                    "buffered_events": buffered,
                    "instructions": "In falco.yaml set http_output.url to this endpoint "
                    "with ?token=<ingest token>, or configure a Falcosidekick webhook "
                    "output with an Authorization: Bearer <ingest token> custom header",
                },
                latency_ms=0,
            )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Falco ingest error: {str(e)}",
            )

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[NormalizedAlert], str | None]:
        """Drain buffered webhook events and normalize them."""
        from app.services.falco_event_buffer import get_falco_event_buffer

        buffer = get_falco_event_buffer()
        events = buffer.drain(self.connector_id, limit)

        min_priority = self.config.get("min_priority", "notice")
        min_rank = (
            PRIORITY_ORDER.index(min_priority)
            if min_priority in PRIORITY_ORDER
            else PRIORITY_ORDER.index("notice")
        )
        rule_filter = set(self.config.get("rule_filter") or [])

        normalized_alerts = []
        for event in events:
            payload = event.payload

            priority = str(payload.get("priority", "")).lower()
            rank = PRIORITY_ORDER.index(priority) if priority in PRIORITY_ORDER else min_rank
            if rank < min_rank:
                continue

            if rule_filter and payload.get("rule") not in rule_filter:
                continue

            normalized_alerts.append(self.normalize_alert(payload))

        # Signal the sync loop to keep draining if the buffer still has events
        next_cursor = "more" if buffer.size(self.connector_id) > 0 else None
        return normalized_alerts, next_cursor

    async def push_status_update(self, alert, new_status: str) -> StatusPushResult:
        """Falco emits fire-and-forget events; there is no alert to update."""
        return StatusPushResult(
            supported=False,
            success=False,
            message="Falco is a stateless event stream - alerts exist only in "
            "RevOps once emitted, so there is nothing to close in Falco",
        )

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Falco alert JSON payload to the unified schema."""
        rule = raw_alert.get("rule", "Unknown Falco Rule")
        output = raw_alert.get("output", "")
        hostname = raw_alert.get("hostname", "unknown")
        output_fields = raw_alert.get("output_fields", {}) or {}

        created_at = utcnow()
        if raw_alert.get("time"):
            try:
                created_at = datetime.fromisoformat(
                    str(raw_alert["time"]).replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # Falco alerts have no native ID; derive a stable one so the same
        # event delivered twice (e.g. Falcosidekick retries) dedupes.
        fingerprint = hashlib.sha256(
            f"{hostname}|{rule}|{raw_alert.get('time', '')}|{output}".encode()
        ).hexdigest()
        external_id = f"falco-{fingerprint[:32]}"

        description_parts = []
        if output:
            description_parts.append(output)
        detail_keys = [
            "proc.cmdline",
            "proc.name",
            "user.name",
            "fd.name",
            "container.id",
            "container.name",
            "k8s.ns.name",
            "k8s.pod.name",
        ]
        details = [
            f"{key}: {output_fields[key]}" for key in detail_keys if output_fields.get(key)
        ]
        if details:
            description_parts.append("\n".join(details))
        description = "\n\n".join(description_parts)

        # Falco rule tags carry MITRE mappings, e.g. "mitre_credential_access", "T1555"
        mitre_tactics = []
        mitre_techniques = []
        tags = []
        for tag in raw_alert.get("tags") or []:
            tag_str = str(tag)
            if MITRE_TECHNIQUE_PATTERN.match(tag_str):
                mitre_techniques.append(tag_str.upper())
            elif tag_str.lower().startswith("mitre_"):
                mitre_tactics.append(tag_str[len("mitre_") :].replace("_", " ").title())
            else:
                tags.append(tag_str)

        tags.append(f"host:{hostname}")
        if raw_alert.get("source"):
            tags.append(f"source:{raw_alert['source']}")
        if output_fields.get("container.name"):
            tags.append(f"container:{output_fields['container.name']}")
        if output_fields.get("k8s.ns.name"):
            tags.append(f"namespace:{output_fields['k8s.ns.name']}")
        if output_fields.get("k8s.pod.name"):
            tags.append(f"pod:{output_fields['k8s.pod.name']}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="falco",
            external_id=external_id,
            title=f"Falco: {rule}",
            description=description or None,
            severity=self.normalize_severity(str(raw_alert.get("priority", "notice"))),
            status="open",
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=rule,
            rule_name=rule,
            tags=tags[:20],
            mitre_tactics=list(dict.fromkeys(mitre_tactics)),
            mitre_techniques=list(dict.fromkeys(mitre_techniques)),
            raw_data=raw_alert,
            ingested_at=utcnow(),
        )

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize Falco priority to standard values."""
        severity_map = {
            "emergency": "critical",
            "alert": "critical",
            "critical": "critical",
            "error": "high",
            "warning": "medium",
            "notice": "low",
            "informational": "info",
            "debug": "info",
        }
        return severity_map.get(source_severity.lower(), "medium")
