"""
UniFi Network Data Source Connector

Fetches security events (IDS/IPS threats, alarms, and security-related system events)
from Ubiquiti UniFi Network controllers.

Supports two modes:
1. Syslog (recommended) - UniFi pushes logs to our syslog receiver
2. API - Polls UniFi controller directly (requires network access)
"""

import logging
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
)
from app.services.syslog_receiver import SyslogMessage, get_syslog_receiver

logger = logging.getLogger(__name__)


# UniFi log patterns for parsing syslog messages
UNIFI_PATTERNS = {
    # IDS/IPS events from Suricata
    "ids_alert": re.compile(
        r"(?:suricata|snort).*?\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
        r"(?P<signature>.*?)\s+\[Classification:\s*(?P<classification>.*?)\]\s+"
        r"\[Priority:\s*(?P<priority>\d+)\].*?"
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<src_port>\d+))?\s*->\s*"
        r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<dst_port>\d+))?",
        re.IGNORECASE,
    ),
    # Firewall block events
    "firewall_block": re.compile(
        r"\[(?P<rule_name>.*?)\].*?"
        r"IN=(?P<in_iface>\S*)\s+OUT=(?P<out_iface>\S*)\s+"
        r"(?:MAC=(?P<mac>\S+)\s+)?"
        r"SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+"
        r".*?PROTO=(?P<proto>\S+)"
        r"(?:.*?SPT=(?P<src_port>\d+))?"
        r"(?:.*?DPT=(?P<dst_port>\d+))?",
        re.IGNORECASE,
    ),
    # Admin login events
    "admin_login": re.compile(
        r"(?:admin|ubnt-systemmgr).*?"
        r"(?P<action>login|logout|failed login)\s+"
        r"(?:from\s+)?(?P<src_ip>\d+\.\d+\.\d+\.\d+)?",
        re.IGNORECASE,
    ),
    # VPN events
    "vpn_event": re.compile(
        r"(?:ipsec|openvpn|wireguard|l2tp).*?"
        r"(?P<action>established|terminated|failed|connected|disconnected)\s*"
        r"(?:.*?peer[=:\s]+(?P<peer>\S+))?",
        re.IGNORECASE,
    ),
    # Threat detection
    "threat_detection": re.compile(
        r"(?:threat|malware|botnet|suspicious).*?"
        r"(?P<threat_type>\S+).*?"
        r"(?:from|src)[=:\s]+(?P<src_ip>\d+\.\d+\.\d+\.\d+)?.*?"
        r"(?:to|dst)[=:\s]+(?P<dst_ip>\d+\.\d+\.\d+\.\d+)?",
        re.IGNORECASE,
    ),
}

# Severity mapping for different event types
SEVERITY_MAP = {
    "ids_alert": "high",
    "firewall_block": "info",
    "admin_login": "medium",
    "vpn_event": "medium",
    "threat_detection": "critical",
}

# MITRE ATT&CK mappings
MITRE_MAPPINGS = {
    "ids_alert": {"tactics": ["Initial Access", "Execution"], "techniques": ["T1190", "T1059"]},
    "firewall_block": {"tactics": ["Defense Evasion"], "techniques": ["T1036"]},
    "admin_login": {"tactics": ["Initial Access", "Persistence"], "techniques": ["T1078"]},
    "vpn_event": {"tactics": ["Command and Control"], "techniques": ["T1573"]},
    "threat_detection": {"tactics": ["Command and Control"], "techniques": ["T1071"]},
}


class UnifiConnector(DataSourceConnector):
    """
    UniFi Network data source connector.

    Receives security events via syslog from UniFi controllers.
    Configure your UniFi to send syslog to this server's IP on port 5514.
    """

    _registered_handlers: set[uuid.UUID] = set()

    def __init__(
        self, connector_id: uuid.UUID, config: dict[str, Any], credentials: dict[str, Any]
    ):
        super().__init__(connector_id, config, credentials)
        self._register_syslog_handler()

    def _register_syslog_handler(self) -> None:
        """Register this connector with the syslog receiver."""
        if self.connector_id in self._registered_handlers:
            return

        syslog_receiver = get_syslog_receiver()
        source_ip = self.config.get("source_ip", "")

        syslog_receiver.register_handler(
            connector_id=self.connector_id,
            callback=self._on_syslog_message,
            source_ips=[source_ip] if source_ip else [],
            hostname_patterns=[
                r"UDM",
                r"USG",
                r"UAP",
                r"USW",
                r"UniFi",
                r"Dream Machine",
                r"Dream.Machine",
            ],
        )
        self._registered_handlers.add(self.connector_id)
        logger.info(f"UniFi connector {self.connector_id} registered for syslog")

    def _on_syslog_message(self, message: SyslogMessage) -> None:
        """Callback for incoming syslog messages (used for real-time processing if needed)."""
        pass  # Messages are buffered by the syslog receiver

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="unifi",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="UniFi Network",
            description="Ubiquiti UniFi Network - IDS/IPS events via Syslog",
            icon="ubiquiti",
            config_schema={
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "title": "UniFi Source IP",
                        "description": "IP address of your UniFi controller (for filtering "
                        "syslog messages). Leave empty to accept from any IP.",
                        "default": "",
                    },
                    "syslog_info": {
                        "type": "string",
                        "title": "Syslog Configuration",
                        "description": "Configure your UniFi to send syslog to: {server_ip}:5514",
                        "readOnly": True,
                    },
                },
                "required": [],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "syslog_token": {
                        "type": "string",
                        "title": "Verification Token (Optional)",
                        "description": "Optional token to verify syslog messages "
                        "are from your UniFi",
                        "format": "password",
                    },
                },
                "required": [],
            },
        )

    async def _pending_count(self) -> int:
        """Staged syslog messages for this connector awaiting a sync."""
        from app.db.session import AsyncSessionLocal
        from app.services import syslog_event_buffer

        async with AsyncSessionLocal() as db:
            return await syslog_event_buffer.count_pending(db, self.connector_id)

    async def test_connection(self) -> ConnectionTestResult:
        """Test that syslog receiver is running and ready."""
        try:
            # Staged rows awaiting a sync, not this process's memory: with
            # several replicas the local buffer is empty on most of them, so
            # reporting it would show "0 buffered" on a busy connector.
            buffer_size = await self._pending_count()

            # Re-register handler if needed
            self._register_syslog_handler()

            return ConnectionTestResult(
                success=True,
                message="Syslog receiver is ready. Configure your UniFi to send logs "
                "to this server on port 5514.",
                details={
                    "mode": "syslog",
                    "port": 5514,
                    "buffered_messages": buffer_size,
                    "source_ip_filter": self.config.get("source_ip", "any"),
                    "instructions": "In UniFi: Settings → Integrations → "
                    "Activity Logging → SIEM Server",
                },
                latency_ms=0,
            )

        except Exception as e:
            logger.exception(f"UniFi syslog test error: {e}")
            return ConnectionTestResult(
                success=False,
                message=f"Syslog receiver error: {str(e)}",
            )

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[NormalizedAlert], str | None]:
        """Fetch alerts from the durable syslog buffer.

        Claimed from ``syslog_ingest_events`` rather than from this process's
        memory: datagrams are load-balanced across replicas while the sync runs
        on whichever replica gets there first, so a process-local buffer is
        drained by nobody. Same reasoning as UniFiSyslogConnector.
        """
        try:
            from app.db.session import AsyncSessionLocal
            from app.services import syslog_event_buffer
            from app.services.connectors.data_sources.unifi_syslog import SYSLOG_DRAIN_BATCH
            from app.services.syslog_receiver import SyslogReceiverService

            # Keep this replica listening even when another runs the syncs.
            self._register_syslog_handler()

            async with AsyncSessionLocal() as db:
                claimed = await syslog_event_buffer.claim_events(
                    db, self.connector_id, max(limit, SYSLOG_DRAIN_BATCH)
                )
                await db.commit()
            messages = [SyslogReceiverService.from_payload(c.payload) for c in claimed]

            normalized_alerts = []
            for msg in messages:
                # Deliberately NOT filtered against `since` -- see
                # UniFiSyslogConnector.fetch_alerts. Anything sitting in a
                # durable queue is older than the last sync by definition, so
                # that filter silently discarded the entire backlog. Claiming
                # a message is the delivery guarantee; a claimed message is
                # always processed.
                alert = self._normalize_syslog_message(msg)
                if alert:
                    normalized_alerts.append(alert)

            # Close out the lease. An unclosed lease goes stale and the rows
            # are re-claimed forever; see syslog_event_buffer.mark_processed.
            try:
                async with AsyncSessionLocal() as db:
                    await syslog_event_buffer.mark_processed(db, [c.id for c in claimed])
                    await db.commit()
            except Exception:
                logger.exception(
                    "Could not mark %s syslog row(s) processed; they will be retried",
                    len(claimed),
                )

            logger.info(
                f"UniFi syslog: processed {len(normalized_alerts)} alerts "
                f"from {len(messages)} messages"
            )

            return normalized_alerts, None

        except Exception as e:
            raise Exception(f"Failed to fetch UniFi syslog alerts: {str(e)}")

    def _normalize_syslog_message(self, msg: SyslogMessage) -> NormalizedAlert | None:
        """Normalize a syslog message to the unified alert schema."""
        # Try to match against known patterns
        event_type = None
        event_data: dict[str, Any] = {}

        for pattern_name, pattern in UNIFI_PATTERNS.items():
            match = pattern.search(msg.message)
            if match:
                event_type = pattern_name
                event_data = match.groupdict()
                break

        # If no specific pattern matched, use generic parsing
        if not event_type:
            event_type = "system_event"
            event_data = {"message": msg.message}

        # Build title
        title = self._build_title(event_type, event_data, msg)

        # Build description
        description = self._build_description(event_type, event_data, msg)

        # Get severity
        severity = self._get_severity(event_type, event_data, msg)

        # Get MITRE mappings
        mitre = MITRE_MAPPINGS.get(event_type, {})

        # Build tags
        tags = [
            f"source:{msg.hostname}",
            f"event_type:{event_type}",
            f"facility:{msg.facility_name}",
        ]
        if event_data.get("src_ip"):
            tags.append(f"src_ip:{event_data['src_ip']}")
        if event_data.get("dst_ip"):
            tags.append(f"dst_ip:{event_data['dst_ip']}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=f"unifi-{msg.source_ip}-{msg.timestamp.timestamp()}",
            title=title,
            description=description,
            severity=severity,
            status="open",
            created_at_source=msg.timestamp,
            updated_at_source=None,
            rule_id=event_type,
            rule_name=f"UniFi {event_type.replace('_', ' ').title()}",
            tags=tags,
            mitre_tactics=mitre.get("tactics", []),
            mitre_techniques=mitre.get("techniques", []),
            raw_data={
                "syslog": {
                    "facility": msg.facility_name,
                    "severity": msg.severity_name,
                    "hostname": msg.hostname,
                    "app_name": msg.app_name,
                    "source_ip": msg.source_ip,
                },
                "parsed": event_data,
                "raw_message": msg.raw,
            },
            ingested_at=utcnow(),
        )

    def _build_title(self, event_type: str, data: dict, msg: SyslogMessage) -> str:
        """Build alert title based on event type."""
        if event_type == "ids_alert":
            return f"IDS Alert: {data.get('signature', 'Unknown threat')}"
        elif event_type == "firewall_block":
            return (
                f"Firewall Block: {data.get('src_ip', '?')} → "
                f"{data.get('dst_ip', '?')}:{data.get('dst_port', '?')}"
            )
        elif event_type == "admin_login":
            action = data.get("action", "event").title()
            return f"Admin {action} from {data.get('src_ip', 'unknown')}"
        elif event_type == "vpn_event":
            return f"VPN {data.get('action', 'event').title()}: {data.get('peer', 'unknown')}"
        elif event_type == "threat_detection":
            return f"Threat Detected: {data.get('threat_type', 'unknown')}"
        else:
            return f"UniFi Event: {msg.message[:100]}"

    def _build_description(self, event_type: str, data: dict, msg: SyslogMessage) -> str:
        """Build alert description."""
        lines = [
            f"Source Device: {msg.hostname} ({msg.source_ip})",
            f"Facility: {msg.facility_name}, Severity: {msg.severity_name}",
            "",
        ]

        if event_type == "ids_alert":
            lines.extend(
                [
                    f"Signature: {data.get('signature', 'Unknown')}",
                    f"Classification: {data.get('classification', 'Unknown')}",
                    f"Priority: {data.get('priority', '?')}",
                    f"Source: {data.get('src_ip', '?')}:{data.get('src_port', '?')}",
                    f"Destination: {data.get('dst_ip', '?')}:{data.get('dst_port', '?')}",
                ]
            )
        elif event_type == "firewall_block":
            lines.extend(
                [
                    f"Rule: {data.get('rule_name', 'Unknown')}",
                    f"Protocol: {data.get('proto', '?')}",
                    f"Source: {data.get('src_ip', '?')}:{data.get('src_port', '?')}",
                    f"Destination: {data.get('dst_ip', '?')}:{data.get('dst_port', '?')}",
                    f"Interface: {data.get('in_iface', '?')} → {data.get('out_iface', '?')}",
                ]
            )
        else:
            lines.append(f"Message: {msg.message}")

        return "\n".join(lines)

    def _get_severity(self, event_type: str, data: dict, msg: SyslogMessage) -> str:
        """Determine alert severity."""
        # IDS alerts use their priority
        if event_type == "ids_alert":
            priority = data.get("priority", "3")
            try:
                p = int(priority)
                if p <= 1:
                    return "critical"
                elif p == 2:
                    return "high"
                else:
                    return "medium"
            except ValueError:
                return "high"

        # Admin login failures are high severity
        if event_type == "admin_login" and "failed" in str(data.get("action", "")).lower():
            return "high"

        # Use syslog severity
        if msg.severity <= 2:  # emerg, alert, crit
            return "critical"
        elif msg.severity == 3:  # err
            return "high"
        elif msg.severity == 4:  # warning
            return "medium"
        elif msg.severity <= 5:  # notice
            return "low"
        else:
            return "info"

        return SEVERITY_MAP.get(event_type, "info")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a raw alert (not used in syslog mode)."""
        # This is required by the base class but not used in syslog mode
        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=str(uuid.uuid4()),
            title="UniFi Event",
            description=str(raw_alert),
            severity="info",
            status="open",
            created_at_source=utcnow(),
            updated_at_source=None,
            rule_id="unknown",
            rule_name="Unknown",
            tags=[],
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data=raw_alert,
            ingested_at=utcnow(),
        )
