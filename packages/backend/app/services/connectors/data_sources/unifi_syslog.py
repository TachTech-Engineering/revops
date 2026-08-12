"""
UniFi Data Source Connector

Integrates with Ubiquiti UniFi devices via:
1. Network API (recommended) - polls events using API key
2. Syslog (optional) - receives pushed logs

Supports UDM, UDM-Pro, UDM-SE, USG, UAP, USW devices.
"""

import re
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
)


class UniFiSyslogConnector(DataSourceConnector):
    """
    UniFi Syslog data source connector.

    Receives syslog messages from UniFi devices (UDM, USG, UAP, USW)
    and normalizes them to the unified alert schema.
    """

    # UniFi log category patterns
    PATTERNS = {
        # Firewall events (UDM/USG)
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
        # IDS/IPS events
        "ids_alert": re.compile(
            r"(?:suricata|snort).*?\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
            r"(?P<signature>.*?)\s+\[Classification:\s*(?P<classification>.*?)\]\s+"
            r"\[Priority:\s*(?P<priority>\d+)\].*?"
            r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<src_port>\d+))?\s*->\s*"
            r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<dst_port>\d+))?",
            re.IGNORECASE,
        ),
        # Wireless client events (UAP)
        "wireless_assoc": re.compile(
            r"(?P<ap_name>\S+).*?(?:hostapd|wevent).*?"
            r"(?:STA|sta)\s+(?P<client_mac>[0-9a-fA-F:]+)\s+"
            r"(?P<action>associated|disassociated|deauthenticated|authenticated)",
            re.IGNORECASE,
        ),
        # Wireless roaming
        "wireless_roam": re.compile(
            r"(?P<ap_name>\S+).*?"
            r"(?P<client_mac>[0-9a-fA-F:]+)\s+roamed\s+from\s+(?P<from_ap>\S+)\s+to\s+(?P<to_ap>\S+)",
            re.IGNORECASE,
        ),
        # Admin login events
        "admin_login": re.compile(
            r"(?:admin|ubnt-systemmgr).*?"
            r"(?P<action>login|logout|failed login)\s+"
            r"(?:from\s+)?(?P<src_ip>\d+\.\d+\.\d+\.\d+)?",
            re.IGNORECASE,
        ),
        # DHCP events
        "dhcp_event": re.compile(
            r"dhcp(?:d|client)?.*?"
            r"(?P<action>DHCPACK|DHCPNAK|DHCPOFFER|DHCPREQUEST|DHCPDISCOVER|DHCPRELEASE)\s+"
            r"(?:on|for)?\s*(?P<ip>\d+\.\d+\.\d+\.\d+)?\s*"
            r"(?:to|from)?\s*(?P<mac>[0-9a-fA-F:]+)?",
            re.IGNORECASE,
        ),
        # VPN events
        "vpn_event": re.compile(
            r"(?:ipsec|openvpn|wireguard|l2tp).*?"
            r"(?P<action>established|terminated|failed|connected|disconnected)\s*"
            r"(?:.*?peer[=:\s]+(?P<peer>\S+))?",
            re.IGNORECASE,
        ),
        # System events
        "system_event": re.compile(
            r"(?P<component>kernel|systemd|ubnt-systemmgr|unifi-os).*?"
            r"(?P<message>.*)",
            re.IGNORECASE,
        ),
        # Configuration changes
        "config_change": re.compile(
            r"(?:config|setting).*?(?P<action>changed|updated|modified|created|deleted)\s+"
            r"(?:by\s+(?P<user>\S+))?",
            re.IGNORECASE,
        ),
        # Switch port events (USW)
        "switch_port": re.compile(
            r"(?:port|interface)\s*(?P<port>\S+)\s+"
            r"(?P<action>link up|link down|speed changed|duplex changed)",
            re.IGNORECASE,
        ),
        # DPI (Deep Packet Inspection) events
        "dpi_event": re.compile(
            r"dpi.*?(?P<client_mac>[0-9a-fA-F:]+).*?"
            r"app[=:\s]+(?P<app_name>\S+).*?"
            r"(?:cat[=:\s]+(?P<category>\S+))?",
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
        # Honeypot events
        "honeypot": re.compile(
            r"honeypot.*?"
            r"(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?"
            r"(?:port[=:\s]+(?P<port>\d+))?",
            re.IGNORECASE,
        ),
    }

    # Event type to severity mapping
    SEVERITY_MAP = {
        "firewall_block": "info",
        "ids_alert": "high",
        "wireless_assoc": "info",
        "wireless_roam": "info",
        "admin_login": "medium",
        "dhcp_event": "info",
        "vpn_event": "medium",
        "system_event": "info",
        "config_change": "medium",
        "switch_port": "info",
        "dpi_event": "info",
        "threat_detection": "critical",
        "honeypot": "high",
    }

    # MITRE ATT&CK mappings for UniFi events
    MITRE_MAPPINGS = {
        "firewall_block": {"tactics": ["Defense Evasion"], "techniques": ["T1036"]},
        "ids_alert": {"tactics": ["Initial Access", "Execution"], "techniques": ["T1190", "T1059"]},
        "admin_login": {"tactics": ["Initial Access", "Persistence"], "techniques": ["T1078"]},
        "vpn_event": {"tactics": ["Command and Control"], "techniques": ["T1573"]},
        "config_change": {
            "tactics": ["Defense Evasion", "Persistence"],
            "techniques": ["T1562", "T1098"],
        },
        "threat_detection": {"tactics": ["Command and Control"], "techniques": ["T1071"]},
        "honeypot": {"tactics": ["Discovery", "Reconnaissance"], "techniques": ["T1046", "T1595"]},
    }

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="unifi_syslog",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="UniFi Network (Syslog)",
            description="Receive security events from UniFi devices via Syslog push",
            icon="ubiquiti",
            config_schema={
                "type": "object",
                "properties": {
                    "site": {
                        "type": "string",
                        "title": "Site Name",
                        "description": "UniFi site name (default: 'default')",
                        "default": "default",
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "title": "Verify SSL",
                        "description": "Verify SSL certificates (disable for self-signed)",
                        "default": False,
                    },
                    "event_types": {
                        "type": "array",
                        "title": "Event Types",
                        "description": "Types of events to collect (empty = all)",
                        "items": {
                            "type": "string",
                            "enum": [
                                "EVT_IDS",
                                "EVT_AD_LOGIN",
                                "EVT_WU_Connected",
                                "EVT_WU_Disconnected",
                                "EVT_WU_Roam",
                                "EVT_LU_Connected",
                                "EVT_LU_Disconnected",
                                "EVT_GW_WANTransition",
                                "EVT_GW_PortForward",
                                "EVT_SW_Connected",
                                "EVT_SW_Disconnected",
                                "EVT_AP_Connected",
                                "EVT_AP_Disconnected",
                            ],
                        },
                        "default": [],
                    },
                    "include_alarms": {
                        "type": "boolean",
                        "title": "Include Alarms",
                        "description": "Also fetch UniFi alarms/alerts",
                        "default": True,
                    },
                    "lookback_hours": {
                        "type": "integer",
                        "title": "Initial Lookback (hours)",
                        "description": "Hours of history to fetch on first sync",
                        "default": 24,
                        "minimum": 1,
                        "maximum": 168,
                    },
                },
                "required": [],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "controller_url": {
                        "type": "string",
                        "title": "Controller URL",
                        "description": "UniFi Controller URL (e.g., https://192.168.1.1)",
                    },
                    "api_key": {
                        "type": "string",
                        "title": "API Key",
                        "description": "UniFi Network API key (create in Settings > Integrations)",
                        "format": "password",
                    },
                },
                "required": ["controller_url", "api_key"],
            },
        )

    def __init__(
        self, connector_id: uuid.UUID, config: dict[str, Any], credentials: dict[str, Any]
    ):
        super().__init__(connector_id, config, credentials)
        self._http_client: httpx.AsyncClient | None = None
        self._handler_registered = False

    def _register_syslog_handler(self) -> None:
        """Register this connector with the syslog receiver."""
        if self._handler_registered:
            return

        import logging

        from app.services.syslog_receiver import get_syslog_receiver

        logger = logging.getLogger(__name__)

        syslog_receiver = get_syslog_receiver()

        # Get source IPs from config if specified
        source_ips = self.config.get("source_ips", [])

        # Register handler - match all messages if no filters specified
        # UniFi devices send CEF format or standard syslog
        syslog_receiver.register_handler(
            connector_id=self.connector_id,
            callback=None,  # We use buffering, not callbacks
            source_ips=source_ips if source_ips else None,
            hostname_patterns=None,  # Accept all hostnames
            app_name_patterns=None,  # Accept all app names
        )
        self._handler_registered = True
        logger.info(f"Registered syslog handler for UniFi connector {self.connector_id}")

    def _get_base_url(self) -> str:
        """Get the UniFi controller base URL."""
        return self.credentials.get("controller_url", "").rstrip("/")

    def _get_headers(self) -> dict[str, str]:
        """Get API request headers."""
        return {
            "X-API-KEY": self.credentials.get("api_key", ""),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            verify_ssl = self.config.get("verify_ssl", False)
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                verify=verify_ssl,
                headers=self._get_headers(),
            )
        return self._http_client

    async def test_connection(self) -> ConnectionTestResult:
        """Test that syslog receiver is ready for UniFi logs."""
        try:
            from app.services.syslog_receiver import get_syslog_receiver

            # Register handler if not already registered
            self._register_syslog_handler()

            syslog_receiver = get_syslog_receiver()
            buffer_size = syslog_receiver.get_buffer_size(self.connector_id)

            return ConnectionTestResult(
                success=True,
                message="Syslog receiver is ready. Configure your UniFi "
                "to send logs to this server.",
                details={
                    "mode": "syslog",
                    "port": 5514,
                    "protocol": "UDP",
                    "buffered_messages": buffer_size,
                    "instructions": "In UniFi: Settings → System → Remote Logging → "
                    "Enter syslog server IP and port 5514",
                },
                latency_ms=0,
            )

        except Exception as e:
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
        """Fetch alerts from the syslog buffer."""
        try:
            import logging

            from app.services.syslog_receiver import get_syslog_receiver

            logger = logging.getLogger(__name__)

            # Register handler if not already registered
            self._register_syslog_handler()

            syslog_receiver = get_syslog_receiver()
            messages = syslog_receiver.get_buffered_messages(self.connector_id, limit)

            logger.info(f"UniFi syslog: fetching from buffer, got {len(messages)} messages")

            normalized_alerts = []
            for msg in messages:
                # Filter by timestamp
                if msg.timestamp < since:
                    continue

                # Parse and normalize the syslog message
                alert = self._normalize_syslog_message(msg)
                if alert:
                    normalized_alerts.append(alert)

            logger.info(
                f"UniFi syslog: processed {len(normalized_alerts)} alerts "
                f"from {len(messages)} messages"
            )

            return normalized_alerts, None

        except Exception as e:
            import logging

            logging.getLogger(__name__).exception(f"Failed to fetch UniFi syslog alerts: {e}")
            raise Exception(f"Failed to fetch UniFi syslog alerts: {str(e)}")

    def _normalize_syslog_message(self, msg) -> NormalizedAlert | None:
        """Normalize a syslog message to the unified alert schema."""
        # Parse CEF format: CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extensions
        cef_pattern = re.compile(
            r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
        )

        message = msg.message if hasattr(msg, "message") else str(msg)
        match = cef_pattern.search(message)

        if match:
            cef_version, vendor, product, version, event_id, name, severity, extensions = (
                match.groups()
            )
            title = f"[{product}] {name}"
            description = f"Event ID: {event_id}\nExtensions: {extensions}"
        else:
            # Non-CEF message
            title = f"UniFi Event: {message[:100]}"
            description = message
            severity = "1"
            event_id = "unknown"

        # Map CEF severity (0-10) to our severity
        try:
            sev_num = int(severity)
            if sev_num >= 7:
                norm_severity = "critical"
            elif sev_num >= 5:
                norm_severity = "high"
            elif sev_num >= 3:
                norm_severity = "medium"
            elif sev_num >= 1:
                norm_severity = "low"
            else:
                norm_severity = "info"
        except ValueError:
            norm_severity = "info"

        source_ip = msg.source_ip if hasattr(msg, "source_ip") else "unknown"
        timestamp = msg.timestamp if hasattr(msg, "timestamp") else utcnow()

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi_syslog",
            external_id=f"unifi-syslog-{timestamp.timestamp()}-{uuid.uuid4().hex[:8]}",
            title=title[:500],
            description=description[:2000] if description else None,
            severity=norm_severity,
            status="open",
            created_at_source=timestamp,
            updated_at_source=None,
            rule_id=event_id,
            rule_name="UniFi Syslog Event",
            tags=[f"source:{source_ip}", "connector:unifi_syslog"],
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data={"raw_message": message, "source_ip": source_ip},
            ingested_at=utcnow(),
        )

    def _normalize_api_event(self, event: dict[str, Any]) -> NormalizedAlert | None:
        """Normalize a UniFi API event to the unified schema."""
        event_key = event.get("key", "unknown")
        event_time = event.get("time", event.get("datetime"))

        # Parse timestamp
        timestamp = utcnow()
        if event_time:
            if isinstance(event_time, (int, float)):
                timestamp = datetime.fromtimestamp(event_time / 1000)
            elif isinstance(event_time, str):
                try:
                    timestamp = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                except ValueError:
                    pass

        # Map event key to our event types
        event_type = self._map_api_event_type(event_key)

        # Build title and description
        title = self._build_api_event_title(event_key, event)
        description = self._build_api_event_description(event)

        # Get severity
        severity = self._get_api_event_severity(event_key, event)

        # Get MITRE mappings
        mitre = self.MITRE_MAPPINGS.get(event_type, {})

        # Build tags
        tags = [f"event_key:{event_key}", f"event_type:{event_type}"]
        if event.get("user"):
            tags.append(f"user:{event.get('user')}")
        if event.get("ap"):
            tags.append(f"ap:{event.get('ap')}")
        if event.get("gw"):
            tags.append(f"gateway:{event.get('gw')}")
        if event.get("sw"):
            tags.append(f"switch:{event.get('sw')}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=event.get("_id", str(uuid.uuid4())),
            title=title,
            description=description,
            severity=severity,
            status="open",
            created_at_source=timestamp,
            updated_at_source=None,
            rule_id=event_key,
            rule_name=f"UniFi {event_key}",
            tags=tags,
            mitre_tactics=mitre.get("tactics", []),
            mitre_techniques=mitre.get("techniques", []),
            raw_data=event,
            ingested_at=utcnow(),
        )

    def _normalize_api_alarm(self, alarm: dict[str, Any]) -> NormalizedAlert | None:
        """Normalize a UniFi API alarm to the unified schema."""
        alarm_key = alarm.get("key", alarm.get("type", "unknown"))
        alarm_time = alarm.get("time", alarm.get("datetime"))

        # Parse timestamp
        timestamp = utcnow()
        if alarm_time:
            if isinstance(alarm_time, (int, float)):
                timestamp = datetime.fromtimestamp(alarm_time / 1000)
            elif isinstance(alarm_time, str):
                try:
                    timestamp = datetime.fromisoformat(alarm_time.replace("Z", "+00:00"))
                except ValueError:
                    pass

        # Alarms are generally higher severity
        severity = "high" if alarm.get("archived", False) is False else "medium"

        # Build title
        title = alarm.get("msg", f"UniFi Alarm: {alarm_key}")

        # Build description
        desc_parts = [f"Alarm Type: {alarm_key}"]
        if alarm.get("ap_name"):
            desc_parts.append(f"AP: {alarm.get('ap_name')}")
        if alarm.get("gw_name"):
            desc_parts.append(f"Gateway: {alarm.get('gw_name')}")
        if alarm.get("sw_name"):
            desc_parts.append(f"Switch: {alarm.get('sw_name')}")
        if alarm.get("dest_ip"):
            desc_parts.append(f"Destination: {alarm.get('dest_ip')}")
        if alarm.get("src_ip"):
            desc_parts.append(f"Source: {alarm.get('src_ip')}")
        description = "\n".join(desc_parts)

        tags = [f"alarm_type:{alarm_key}", "source:unifi_alarm"]
        if alarm.get("catname"):
            tags.append(f"category:{alarm.get('catname')}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=alarm.get("_id", str(uuid.uuid4())),
            title=title,
            description=description,
            severity=severity,
            status="open" if not alarm.get("archived") else "closed",
            created_at_source=timestamp,
            updated_at_source=None,
            rule_id=f"alarm_{alarm_key}",
            rule_name=f"UniFi Alarm: {alarm_key}",
            tags=tags,
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data=alarm,
            ingested_at=utcnow(),
        )

    def _map_api_event_type(self, event_key: str) -> str:
        """Map UniFi API event key to our event type."""
        mapping = {
            "EVT_IDS_IpReputation": "threat_detection",
            "EVT_IDS_Fingerprint": "ids_alert",
            "EVT_IDS": "ids_alert",
            "EVT_AD_LOGIN": "admin_login",
            "EVT_WU_Connected": "wireless_assoc",
            "EVT_WU_Disconnected": "wireless_assoc",
            "EVT_WU_Roam": "wireless_roam",
            "EVT_WU_RoamRadio": "wireless_roam",
            "EVT_LU_Connected": "switch_port",
            "EVT_LU_Disconnected": "switch_port",
            "EVT_GW_WANTransition": "system_event",
            "EVT_GW_PortForward": "config_change",
            "EVT_GW_VPN": "vpn_event",
            "EVT_SW_Connected": "switch_port",
            "EVT_SW_Disconnected": "switch_port",
            "EVT_AP_Connected": "system_event",
            "EVT_AP_Disconnected": "system_event",
            "EVT_AP_Upgraded": "system_event",
            "EVT_GW_Upgraded": "system_event",
            "EVT_SW_Upgraded": "system_event",
        }
        return mapping.get(event_key, "system_event")

    def _build_api_event_title(self, event_key: str, event: dict) -> str:
        """Build alert title from API event."""
        msg = event.get("msg", "")
        if msg:
            return msg[:200]

        # Fallback titles
        titles = {
            "EVT_WU_Connected": (
                f"Client connected: {event.get('user', event.get('guest', 'unknown'))}"
            ),
            "EVT_WU_Disconnected": (
                f"Client disconnected: {event.get('user', event.get('guest', 'unknown'))}"
            ),
            "EVT_WU_Roam": f"Client roamed: {event.get('user', 'unknown')}",
            "EVT_AD_LOGIN": f"Admin login: {event.get('admin', 'unknown')}",
            "EVT_IDS": f"IDS Alert: {event.get('catname', 'unknown')}",
            "EVT_GW_WANTransition": f"WAN transition: {event.get('wan_type', 'unknown')}",
        }
        return titles.get(event_key, f"UniFi Event: {event_key}")

    def _build_api_event_description(self, event: dict) -> str:
        """Build description from API event."""
        parts = []

        if event.get("msg"):
            parts.append(event["msg"])

        # Add relevant details
        if event.get("ap_name"):
            parts.append(f"Access Point: {event['ap_name']}")
        if event.get("gw_name"):
            parts.append(f"Gateway: {event['gw_name']}")
        if event.get("sw_name"):
            parts.append(f"Switch: {event['sw_name']}")
        if event.get("user"):
            parts.append(f"User/Client: {event['user']}")
        if event.get("admin"):
            parts.append(f"Admin: {event['admin']}")
        if event.get("ip"):
            parts.append(f"IP: {event['ip']}")
        if event.get("channel"):
            parts.append(f"Channel: {event['channel']}")
        if event.get("radio"):
            parts.append(f"Radio: {event['radio']}")
        if event.get("ssid"):
            parts.append(f"SSID: {event['ssid']}")

        return "\n".join(parts) if parts else "No details available"

    def _get_api_event_severity(self, event_key: str, event: dict) -> str:
        """Determine severity for API event."""
        # IDS events are high severity
        if event_key.startswith("EVT_IDS"):
            return "high"

        # Admin events are medium
        if event_key.startswith("EVT_AD"):
            return "medium"

        # Connection events are info
        if "Connected" in event_key or "Disconnected" in event_key:
            return "info"

        # WAN issues are medium
        if "WAN" in event_key:
            return "medium"

        return "info"

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a parsed UniFi event to the unified schema."""
        event_type = raw_alert.get("event_type", "system_event")
        syslog_data = raw_alert.get("syslog", {})

        # Build title based on event type
        title = self._build_title(event_type, raw_alert)

        # Build description
        description = self._build_description(event_type, raw_alert)

        # Get severity
        severity = self._get_alert_severity(event_type, raw_alert)

        # Get MITRE mappings
        mitre = self.MITRE_MAPPINGS.get(event_type, {})

        # Parse timestamp
        timestamp = utcnow()
        if syslog_data.get("timestamp"):
            try:
                timestamp = datetime.fromisoformat(syslog_data["timestamp"])
            except ValueError:
                pass

        # Build tags
        tags = [
            f"device:{syslog_data.get('hostname', 'unknown')}",
            f"event_type:{event_type}",
        ]
        if raw_alert.get("src_ip"):
            tags.append(f"src_ip:{raw_alert['src_ip']}")
        if raw_alert.get("dst_ip"):
            tags.append(f"dst_ip:{raw_alert['dst_ip']}")
        if raw_alert.get("client_mac"):
            tags.append(f"client_mac:{raw_alert['client_mac']}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi_syslog",
            external_id=f"unifi-{syslog_data.get('hostname', 'unknown')}-{timestamp.timestamp()}",
            title=title,
            description=description,
            severity=severity,
            status="open",
            created_at_source=timestamp,
            updated_at_source=None,
            rule_id=event_type,
            rule_name=f"UniFi {event_type.replace('_', ' ').title()}",
            tags=tags,
            mitre_tactics=mitre.get("tactics", []),
            mitre_techniques=mitre.get("techniques", []),
            raw_data=raw_alert,
            ingested_at=utcnow(),
        )

    def _build_title(self, event_type: str, data: dict) -> str:
        """Build alert title based on event type."""
        titles = {
            "firewall_block": lambda d: (
                f"Firewall Block: {d.get('src_ip', '?')} -> "
                f"{d.get('dst_ip', '?')}:{d.get('dst_port', '?')}"
            ),
            "ids_alert": lambda d: f"IDS Alert: {d.get('signature', 'Unknown threat')}",
            "wireless_assoc": lambda d: (
                f"Wireless {d.get('action', 'event').title()}: {d.get('client_mac', '?')}"
            ),
            "wireless_roam": lambda d: (
                f"Client Roam: {d.get('client_mac', '?')} to {d.get('to_ap', '?')}"
            ),
            "admin_login": lambda d: (
                f"Admin {d.get('action', 'event').title()} from {d.get('src_ip', 'unknown')}"
            ),
            "dhcp_event": lambda d: (
                f"DHCP: {d.get('action', '?')} {d.get('ip', '')} {d.get('mac', '')}"
            ),
            "vpn_event": lambda d: (
                f"VPN {d.get('action', 'event').title()}: {d.get('peer', 'unknown')}"
            ),
            "config_change": lambda d: (
                f"Config {d.get('action', 'changed')} by {d.get('user', 'unknown')}"
            ),
            "switch_port": lambda d: f"Port {d.get('port', '?')}: {d.get('action', '?')}",
            "dpi_event": lambda d: (
                f"DPI: {d.get('app_name', 'unknown')} detected for {d.get('client_mac', '?')}"
            ),
            "threat_detection": lambda d: (
                f"Threat Detected: {d.get('threat_type', 'unknown')} from {d.get('src_ip', '?')}"
            ),
            "honeypot": lambda d: (
                f"Honeypot Hit: {d.get('src_ip', '?')} on port {d.get('port', '?')}"
            ),
            "system_event": lambda d: f"System: {d.get('message', 'Event')[:100]}",
        }
        builder = titles.get(event_type, lambda d: f"UniFi Event: {event_type}")
        return builder(data)

    def _build_description(self, event_type: str, data: dict) -> str:
        """Build alert description based on event type."""
        syslog = data.get("syslog", {})
        base = f"Source: {syslog.get('hostname', 'unknown')} ({syslog.get('source_ip', '?')})\n"
        base += (
            f"Facility: {syslog.get('facility', '?')}, Severity: {syslog.get('severity', '?')}\n\n"
        )

        if event_type == "firewall_block":
            base += f"Rule: {data.get('rule_name', 'unknown')}\n"
            base += f"Protocol: {data.get('proto', '?')}\n"
            base += f"Source: {data.get('src_ip', '?')}:{data.get('src_port', '?')}\n"
            base += f"Destination: {data.get('dst_ip', '?')}:{data.get('dst_port', '?')}\n"
            base += f"Interface: {data.get('in_iface', '?')} -> {data.get('out_iface', '?')}"

        elif event_type == "ids_alert":
            base += f"Signature: {data.get('signature', '?')}\n"
            base += f"Classification: {data.get('classification', '?')}\n"
            base += f"Priority: {data.get('priority', '?')}\n"
            base += f"Source: {data.get('src_ip', '?')}:{data.get('src_port', '?')}\n"
            base += f"Destination: {data.get('dst_ip', '?')}:{data.get('dst_port', '?')}"

        elif event_type in ("wireless_assoc", "wireless_roam"):
            base += f"Client MAC: {data.get('client_mac', '?')}\n"
            base += f"AP: {data.get('ap_name', data.get('to_ap', '?'))}"

        elif event_type == "admin_login":
            base += f"Action: {data.get('action', '?')}\n"
            base += f"Source IP: {data.get('src_ip', 'N/A')}"

        else:
            base += f"Raw: {data.get('raw_message', '')[:500]}"

        return base

    def _get_alert_severity(self, event_type: str, data: dict) -> str:
        """Determine alert severity based on event type and content."""
        # IDS alerts use their own priority
        if event_type == "ids_alert":
            ids_priority = data.get("priority", "3")
            try:
                p = int(ids_priority)
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

        # Default severity by event type
        return self.SEVERITY_MAP.get(event_type, "info")

    def normalize_severity(self, source_severity: str) -> str:
        """Normalize syslog severity to standard values."""
        severity_map = {
            "emerg": "critical",
            "alert": "critical",
            "crit": "critical",
            "err": "high",
            "warning": "medium",
            "notice": "low",
            "info": "info",
            "debug": "info",
        }
        return severity_map.get(source_severity.lower(), "info")

    def normalize_status(self, source_status: str) -> str:
        """Normalize status to standard values."""
        return "open"
