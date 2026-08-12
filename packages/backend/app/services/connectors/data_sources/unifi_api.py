"""
UniFi Network API Data Source Connector

Integrates with UniFi Network Controllers to fetch and normalize security events,
admin activities, client events, and threat detections via the REST API.
"""

import logging
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

logger = logging.getLogger(__name__)


# Event type to severity mapping
SEVERITY_MAP = {
    # Threat/Security events - High priority
    "IPS": "high",
    "EVT_IPS_IpsAlert": "high",
    "EVT_AD_Login": "info",
    "EVT_AD_LoginFailed": "high",
    "EVT_AD_Logout": "info",
    # Admin events
    "EVT_ADMIN_LOGIN": "info",
    "EVT_ADMIN_LOGIN_FAILED": "high",
    "EVT_ADMIN_LOGOUT": "info",
    # Client events
    "EVT_WU_Connected": "info",
    "EVT_WU_Disconnected": "info",
    "EVT_LU_Connected": "info",
    "EVT_LU_Disconnected": "info",
    "EVT_WG_Connected": "info",
    "EVT_WG_Disconnected": "info",
    # Device events
    "EVT_AP_Connected": "info",
    "EVT_AP_Disconnected": "medium",
    "EVT_AP_Restarted": "low",
    "EVT_SW_Connected": "info",
    "EVT_SW_Disconnected": "medium",
    "EVT_GW_Connected": "info",
    "EVT_GW_Disconnected": "high",
    "EVT_GW_Restarted": "medium",
    # System events
    "EVT_SYSTEM_UPGRADE_SCHEDULED": "info",
    "EVT_SYSTEM_UPGRADE_STARTED": "info",
    "EVT_SYSTEM_UPGRADE_COMPLETED": "info",
    "EVT_SYSTEM_UPGRADE_FAILED": "medium",
    # Rogue AP detection
    "EVT_AP_DetectedRogueAP": "high",
    # DPI/Firewall
    "EVT_FW_BLOCK": "medium",
    "EVT_DPI_ALERT": "medium",
}

# MITRE ATT&CK mapping
MITRE_MAP = {
    "EVT_AD_LoginFailed": (["TA0006", "TA0001"], ["T1110", "T1078"]),
    "EVT_ADMIN_LOGIN_FAILED": (["TA0006", "TA0001"], ["T1110", "T1078"]),
    "IPS": (["TA0001", "TA0043"], ["T1190", "T1595"]),
    "EVT_IPS_IpsAlert": (["TA0001", "TA0043"], ["T1190", "T1595"]),
    "EVT_AP_DetectedRogueAP": (["TA0001", "TA0043"], ["T1200", "T1595"]),
    "EVT_FW_BLOCK": (["TA0011", "TA0010"], ["T1071", "T1041"]),
}


class UniFiAPIConnector(DataSourceConnector):
    """
    UniFi Network API data source connector.

    Fetches events from UniFi Network Controllers including:
    - Admin login/logout events
    - Client connect/disconnect events
    - Device status changes
    - IPS/IDS alerts
    - Rogue AP detections
    - Firewall blocks
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="unifi_api",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="UniFi Network (API)",
            description="Fetch security events from UniFi Network Controllers via REST API",
            icon="unifi",
            config_schema={
                "type": "object",
                "properties": {
                    "controller_url": {
                        "type": "string",
                        "title": "Controller URL",
                        "description": "UniFi Controller URL (e.g., https://192.168.1.1 or https://unifi.example.com)",
                        "format": "uri",
                    },
                    "site": {
                        "type": "string",
                        "title": "Site Name",
                        "description": "UniFi site name (default: 'default')",
                        "default": "default",
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "title": "Verify SSL",
                        "description": "Verify SSL certificate (disable for self-signed certs)",
                        "default": False,
                    },
                    "event_types": {
                        "type": "array",
                        "title": "Event Types",
                        "description": "Types of events to fetch (empty = all)",
                        "items": {
                            "type": "string",
                            "enum": [
                                "admin",
                                "client",
                                "device",
                                "ips",
                                "firewall",
                                "system",
                            ],
                        },
                        "default": ["admin", "ips", "firewall"],
                    },
                    "min_severity": {
                        "type": "string",
                        "title": "Minimum Severity",
                        "description": "Only create alerts at or above this severity",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "default": "info",
                    },
                },
                "required": ["controller_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "title": "API Key",
                        "description": (
                            "UniFi Network API key "
                            "(create in Settings → Integrations → API Keys)"
                        ),
                        "format": "password",
                    },
                },
                "required": ["api_key"],
            },
        )

    def _get_base_url(self) -> str:
        """Get the base URL for API requests."""
        url = self.config.get("controller_url", "").rstrip("/")
        return url

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "X-API-KEY": self.credentials.get("api_key", ""),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _get_verify_ssl(self) -> bool:
        """Get SSL verification setting."""
        return self.config.get("verify_ssl", False)

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to UniFi Controller API."""
        start_time = time.time()
        try:
            base_url = self._get_base_url()
            api_key = self.credentials.get("api_key", "")

            if not base_url:
                return ConnectionTestResult(
                    success=False,
                    message="Controller URL is required",
                )

            if not api_key:
                return ConnectionTestResult(
                    success=False,
                    message="API key is required",
                )

            # Test connection by fetching sites
            async with httpx.AsyncClient(
                timeout=30.0,
                verify=self._get_verify_ssl(),
            ) as client:
                response = await client.get(
                    f"{base_url}/proxy/network/integration/v1/sites",
                    headers=self._get_headers(),
                )

                latency_ms = int((time.time() - start_time) * 1000)

                if response.status_code == 200:
                    data = response.json()
                    sites = data.get("data", [])
                    site_names = [s.get("name", "unknown") for s in sites[:5]]

                    return ConnectionTestResult(
                        success=True,
                        message="Connected to UniFi Controller",
                        details={
                            "sites": site_names,
                            "site_count": len(sites),
                        },
                        latency_ms=latency_ms,
                    )

                if response.status_code == 401:
                    return ConnectionTestResult(
                        success=False,
                        message="Authentication failed - check API key",
                        latency_ms=latency_ms,
                    )
                elif response.status_code == 403:
                    return ConnectionTestResult(
                        success=False,
                        message="Access denied - API key lacks required permissions",
                        latency_ms=latency_ms,
                    )
                else:
                    return ConnectionTestResult(
                        success=False,
                        message=f"API error: HTTP {response.status_code}",
                        latency_ms=latency_ms,
                    )

        except httpx.ConnectError as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection failed - check controller URL: {str(e)}",
            )
        except httpx.SSLError as e:
            return ConnectionTestResult(
                success=False,
                message=f"SSL error - try disabling 'Verify SSL' for self-signed certs: {str(e)}",
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
        """Fetch events from UniFi Controller API."""
        try:
            base_url = self._get_base_url()
            site = self.config.get("site", "default")

            # Calculate time range
            # UniFi API uses Unix timestamps in milliseconds
            since_ts = int(since.timestamp() * 1000)
            now_ts = int(datetime.utcnow().timestamp() * 1000)

            events = []

            async with httpx.AsyncClient(
                timeout=60.0,
                verify=self._get_verify_ssl(),
            ) as client:
                # Fetch events from the stat/event endpoint
                # This endpoint returns recent events
                response = await client.get(
                    f"{base_url}/proxy/network/api/s/{site}/stat/event",
                    headers=self._get_headers(),
                    params={
                        "start": since_ts,
                        "end": now_ts,
                        "_limit": limit,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    events.extend(data.get("data", []))
                else:
                    logger.warning(
                        f"Failed to fetch UniFi events: {response.status_code} - "
                        f"{response.text[:200]}"
                    )

                # Also fetch alarms if available
                try:
                    alarm_response = await client.get(
                        f"{base_url}/proxy/network/api/s/{site}/stat/alarm",
                        headers=self._get_headers(),
                    )
                    if alarm_response.status_code == 200:
                        alarm_data = alarm_response.json()
                        for alarm in alarm_data.get("data", []):
                            alarm["_is_alarm"] = True
                            events.append(alarm)
                except Exception as e:
                    logger.debug(f"Could not fetch alarms: {e}")

            # Filter events by configured types
            event_types = self.config.get("event_types", [])
            if event_types:
                events = self._filter_by_type(events, event_types)

            # Normalize events
            normalized_alerts = []
            min_severity = self.config.get("min_severity", "info")
            severity_order = ["info", "low", "medium", "high", "critical"]
            min_severity_idx = severity_order.index(min_severity)

            for event in events:
                try:
                    normalized = self.normalize_alert(event)

                    # Apply severity filter
                    event_severity_idx = severity_order.index(normalized.severity)
                    if event_severity_idx >= min_severity_idx:
                        normalized_alerts.append(normalized)
                except Exception as e:
                    logger.warning(f"Failed to normalize UniFi event: {e}")
                    continue

            return normalized_alerts, None

        except Exception as e:
            logger.error(f"Failed to fetch events from UniFi: {e}")
            raise

    def _filter_by_type(self, events: list[dict], event_types: list[str]) -> list[dict]:
        """Filter events by configured event types."""
        type_prefixes = {
            "admin": ["EVT_AD", "EVT_ADMIN"],
            "client": ["EVT_WU", "EVT_LU", "EVT_WG", "EVT_GU"],
            "device": ["EVT_AP", "EVT_SW", "EVT_GW", "EVT_BB", "EVT_DM"],
            "ips": ["EVT_IPS", "IPS"],
            "firewall": ["EVT_FW", "EVT_DPI"],
            "system": ["EVT_SYSTEM", "EVT_UPGRADE"],
        }

        allowed_prefixes = []
        for et in event_types:
            allowed_prefixes.extend(type_prefixes.get(et, []))

        if not allowed_prefixes:
            return events

        filtered = []
        for event in events:
            event_key = event.get("key", "")
            for prefix in allowed_prefixes:
                if event_key.startswith(prefix):
                    filtered.append(event)
                    break

        return filtered

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a UniFi event to the unified schema."""
        event_key = raw_alert.get("key", "unknown")
        event_msg = raw_alert.get("msg", "")
        is_alarm = raw_alert.get("_is_alarm", False)

        # Parse timestamp
        timestamp = datetime.utcnow()
        if raw_alert.get("time"):
            try:
                # UniFi uses millisecond timestamps
                ts = raw_alert["time"]
                if ts > 1e12:  # milliseconds
                    ts = ts / 1000
                timestamp = datetime.utcfromtimestamp(ts)
            except (ValueError, TypeError):
                pass
        elif raw_alert.get("datetime"):
            try:
                timestamp = datetime.fromisoformat(raw_alert["datetime"].replace("Z", ""))
            except (ValueError, TypeError):
                pass

        # Build title
        title = self._build_title(event_key, raw_alert, event_msg, is_alarm)

        # Build description
        description = self._build_description(raw_alert, event_msg)

        # Determine severity
        severity = SEVERITY_MAP.get(event_key, "low" if is_alarm else "info")

        # Get MITRE mappings
        mitre_tactics, mitre_techniques = MITRE_MAP.get(event_key, ([], []))

        # Build tags
        tags = self._build_tags(raw_alert, event_key)

        # Generate external ID
        external_id = raw_alert.get("_id", f"unifi-{timestamp.timestamp()}-{uuid.uuid4().hex[:8]}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi_api",
            external_id=external_id,
            title=title[:500],
            description=description[:2000] if description else None,
            severity=severity,
            status="open",
            created_at_source=timestamp,
            updated_at_source=None,
            rule_id=event_key,
            rule_name=self._get_rule_name(event_key),
            tags=tags[:20],
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def _build_title(self, event_key: str, event: dict, msg: str, is_alarm: bool) -> str:
        """Build alert title from event data."""
        controller_url = self.config.get("controller_url", "UniFi")
        # Extract hostname from URL for cleaner titles
        try:
            from urllib.parse import urlparse

            hostname = urlparse(controller_url).hostname or "UniFi"
        except Exception:
            hostname = "UniFi"

        # Event-specific titles
        if "Login" in event_key and "Failed" in event_key:
            admin = event.get("admin", event.get("user", "unknown"))
            ip = event.get("ip", event.get("src_ip", "unknown"))
            return f"[{hostname}] Failed login attempt: {admin} from {ip}"

        if "Login" in event_key:
            admin = event.get("admin", event.get("user", "unknown"))
            return f"[{hostname}] Admin login: {admin}"

        if "Logout" in event_key:
            admin = event.get("admin", event.get("user", "unknown"))
            return f"[{hostname}] Admin logout: {admin}"

        if "IPS" in event_key or "Ips" in event_key:
            signature = event.get("inner_alert_signature", event.get("msg", "IPS Alert"))
            src = event.get("src_ip", "unknown")
            return f"[{hostname}] IPS Alert: {signature[:80]} from {src}"

        if "RogueAP" in event_key:
            ap_name = event.get("ap_name", event.get("ap", "unknown"))
            return f"[{hostname}] Rogue AP detected near {ap_name}"

        if "_Connected" in event_key or "_Disconnected" in event_key:
            device = event.get("hostname", event.get("name", event.get("mac", "unknown")))
            action = "connected" if "_Connected" in event_key else "disconnected"
            return f"[{hostname}] Device {action}: {device}"

        if "FW_BLOCK" in event_key:
            src = event.get("src_ip", "unknown")
            dst = event.get("dst_ip", "unknown")
            return f"[{hostname}] Firewall block: {src} -> {dst}"

        if is_alarm:
            return f"[{hostname}] Alarm: {msg[:100]}"

        # Default: use message or event key
        if msg:
            return f"[{hostname}] {msg[:100]}"
        return f"[{hostname}] {event_key}"

    def _build_description(self, event: dict, msg: str) -> str:
        """Build alert description from event data."""
        lines = [
            f"Event Type: {event.get('key', 'unknown')}",
            f"Message: {msg}" if msg else None,
            "",
            "Details:",
        ]

        # Add relevant fields
        detail_fields = [
            ("admin", "Admin"),
            ("user", "User"),
            ("hostname", "Hostname"),
            ("mac", "MAC Address"),
            ("ip", "IP Address"),
            ("src_ip", "Source IP"),
            ("dst_ip", "Destination IP"),
            ("src_port", "Source Port"),
            ("dst_port", "Destination Port"),
            ("ap_name", "Access Point"),
            ("ssid", "SSID"),
            ("network", "Network"),
            ("inner_alert_signature", "IPS Signature"),
            ("inner_alert_category", "IPS Category"),
            ("proto", "Protocol"),
        ]

        for field, label in detail_fields:
            if event.get(field):
                lines.append(f"  {label}: {event[field]}")

        # Add site info
        if event.get("site_id"):
            lines.append(f"  Site ID: {event['site_id']}")

        return "\n".join(line for line in lines if line is not None)

    def _build_tags(self, event: dict, event_key: str) -> list[str]:
        """Build tags from event data."""
        tags = [
            "source:unifi",
            f"event_type:{event_key}",
        ]

        if event.get("admin"):
            tags.append(f"admin:{event['admin']}")
        if event.get("user"):
            tags.append(f"user:{event['user']}")
        if event.get("src_ip"):
            tags.append(f"src_ip:{event['src_ip']}")
        if event.get("dst_ip"):
            tags.append(f"dst_ip:{event['dst_ip']}")
        if event.get("mac"):
            tags.append(f"mac:{event['mac']}")
        if event.get("hostname"):
            tags.append(f"hostname:{event['hostname']}")
        if event.get("ssid"):
            tags.append(f"ssid:{event['ssid']}")
        if event.get("ap_name"):
            tags.append(f"ap:{event['ap_name']}")
        if event.get("_is_alarm"):
            tags.append("alarm:true")

        return tags

    def _get_rule_name(self, event_key: str) -> str:
        """Get human-readable rule name from event key."""
        # Convert EVT_AD_LoginFailed -> "Admin Login Failed"
        name = event_key.replace("EVT_", "").replace("_", " ")

        # Common substitutions
        substitutions = {
            "AD ": "Admin ",
            "WU ": "Wireless User ",
            "LU ": "LAN User ",
            "WG ": "Wireless Guest ",
            "GU ": "Guest User ",
            "AP ": "Access Point ",
            "SW ": "Switch ",
            "GW ": "Gateway ",
            "FW ": "Firewall ",
            "DPI ": "Deep Packet Inspection ",
            "IPS ": "Intrusion Prevention ",
        }

        for old, new in substitutions.items():
            name = name.replace(old, new)

        return f"UniFi: {name}"
