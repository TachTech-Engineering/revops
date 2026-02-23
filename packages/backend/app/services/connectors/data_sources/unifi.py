"""
UniFi Network Data Source Connector

Fetches security events (IDS/IPS threats, alarms, and security-related system events)
from Ubiquiti UniFi Network controllers into the unified alerts dashboard.

Uses API key authentication (create in UniFi Settings > Integrations).
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


# Security-relevant event types to ingest
SECURITY_EVENT_TYPES = {
    "EVT_IPS_IpsAlert",
    "EVT_IPS_IpReputation",
    "EVT_IPS_Fingerprint",
    "EVT_AD_Login",
    "EVT_AD_LoginFailed",
    "EVT_AD_AdminLogin",
    "EVT_AD_AdminLoginFailed",
    "EVT_WG_Connected",
    "EVT_WG_Disconnected",
    "EVT_WG_Authorization",
    "EVT_WG_AuthorizationFailed",
    "EVT_LU_Blocked",
    "EVT_LU_Connected",
    "EVT_LU_Disconnected",
    "EVT_AP_DetectedRogueAP",
    "EVT_AP_PossibleInterference",
    "EVT_SW_StpBlockPortActive",
    "EVT_SW_AclDeny",
    "EVT_GW_VPN",
}

# MITRE ATT&CK mappings for IDS categories
MITRE_MAPPINGS: dict[str, tuple[list[str], list[str]]] = {
    # Reconnaissance
    "ET SCAN": (["TA0043"], ["T1595"]),
    "ET POLICY": (["TA0043"], ["T1592"]),
    "GPL SCAN": (["TA0043"], ["T1595"]),
    # Initial Access
    "ET EXPLOIT": (["TA0001"], ["T1190"]),
    "GPL EXPLOIT": (["TA0001"], ["T1190"]),
    "ET WEB_SERVER": (["TA0001"], ["T1190"]),
    "ET WEB_CLIENT": (["TA0001"], ["T1189"]),
    # Execution
    "ET MALWARE": (["TA0002"], ["T1059"]),
    "GPL MALWARE": (["TA0002"], ["T1059"]),
    "ET TROJAN": (["TA0002"], ["T1059"]),
    "GPL TROJAN": (["TA0002"], ["T1059"]),
    # Command and Control
    "ET CNC": (["TA0011"], ["T1071"]),
    "ET BOTNET": (["TA0011"], ["T1071"]),
    "GPL BOTNET": (["TA0011"], ["T1071"]),
    # Credential Access
    "ET ATTACK_RESPONSE": (["TA0006"], ["T1110"]),
    "GPL ATTACK_RESPONSE": (["TA0006"], ["T1110"]),
    # Lateral Movement
    "ET RPC": (["TA0008"], ["T1021"]),
    "GPL RPC": (["TA0008"], ["T1021"]),
    "ET NETBIOS": (["TA0008"], ["T1021"]),
    "GPL NETBIOS": (["TA0008"], ["T1021"]),
    # Exfiltration
    "ET DNS": (["TA0010"], ["T1048"]),
    "GPL DNS": (["TA0010"], ["T1048"]),
}


class UnifiConnector(DataSourceConnector):
    """
    UniFi Network data source connector.

    Fetches IDS/IPS events, alarms, and security-relevant system events
    from UniFi controllers using API key authentication.
    """

    def __init__(self, connector_id: uuid.UUID, config: dict[str, Any], credentials: dict[str, Any]):
        super().__init__(connector_id, config, credentials)
        self._http_client: Optional[httpx.AsyncClient] = None

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="unifi",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="UniFi Network",
            description="Ubiquiti UniFi Network - IDS/IPS events, alarms, and security events",
            icon="ubiquiti",
            config_schema={
                "type": "object",
                "properties": {
                    "site": {
                        "type": "string",
                        "title": "Site",
                        "description": "UniFi site name",
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
                        "description": "Which event types to fetch",
                        "items": {
                            "type": "string",
                            "enum": ["ids", "alarms", "events"],
                        },
                        "default": ["ids", "alarms", "events"],
                    },
                    "include_alarms": {
                        "type": "boolean",
                        "title": "Include Alarms",
                        "description": "Also fetch UniFi alarms/alerts",
                        "default": True,
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
                        "description": "UniFi controller URL (e.g., https://192.168.1.1)",
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

    def _get_controller_url(self) -> str:
        """Get the configured controller URL with trailing slash removed."""
        url = self.credentials.get("controller_url", "")
        return url.rstrip("/")

    def _get_site(self) -> str:
        """Get the configured site name."""
        return self.config.get("site", "default")

    def _get_verify_ssl(self) -> bool:
        """Get SSL verification setting."""
        return self.config.get("verify_ssl", False)

    def _get_event_types(self) -> list[str]:
        """Get configured event types to fetch."""
        return self.config.get("event_types", ["ids", "alarms", "events"])

    def _get_headers(self) -> dict[str, str]:
        """Get API request headers with API key."""
        return {
            "X-API-KEY": self.credentials.get("api_key", ""),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                verify=self._get_verify_ssl(),
                headers=self._get_headers(),
            )
        return self._http_client

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to UniFi controller."""
        import logging

        logger = logging.getLogger(__name__)
        start_time = time.time()

        try:
            base_url = self._get_controller_url()
            if not base_url:
                return ConnectionTestResult(
                    success=False,
                    message="Controller URL is required",
                )

            if not self.credentials.get("api_key"):
                return ConnectionTestResult(
                    success=False,
                    message="API Key is required",
                )

            client = await self._get_client()
            site = self._get_site()

            # Test API connection by listing sites
            response = await client.get(f"{base_url}/proxy/network/integration/v1/sites")
            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                sites = data if isinstance(data, list) else [data]

                # Try to get device count
                device_count = 0
                try:
                    devices_resp = await client.get(
                        f"{base_url}/proxy/network/api/s/{site}/stat/device"
                    )
                    if devices_resp.status_code == 200:
                        devices_data = devices_resp.json()
                        device_count = len(devices_data.get("data", []))
                except Exception:
                    pass

                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to UniFi Network API",
                    details={
                        "sites_count": len(sites),
                        "site_names": [s.get("name", s.get("desc", "unknown")) for s in sites[:5]],
                        "device_count": device_count,
                        "controller_url": base_url,
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check your API key",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Access forbidden - API key may lack permissions",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}: {response.text[:200]}",
                    latency_ms=latency_ms,
                )

        except httpx.TimeoutException:
            logger.error("UniFi connection timed out")
            return ConnectionTestResult(
                success=False,
                message="Connection timed out",
            )
        except httpx.ConnectError as e:
            logger.error(f"UniFi connection error: {e}")
            return ConnectionTestResult(
                success=False,
                message="Connection error: Unable to connect to controller",
            )
        except Exception as e:
            logger.exception(f"UniFi connection error: {e}")
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
        """
        Fetch security events from UniFi controller.

        Fetches IDS/IPS events, alarms, and security-relevant system events
        based on configuration.
        """
        import logging

        logger = logging.getLogger(__name__)
        normalized_alerts: list[NormalizedAlert] = []
        event_types = self._get_event_types()

        try:
            base_url = self._get_controller_url()
            site = self._get_site()
            client = await self._get_client()

            # Convert since to Unix timestamp (milliseconds)
            since_ts = int(since.timestamp() * 1000)
            now_ts = int(datetime.utcnow().timestamp() * 1000)

            # Fetch IDS/IPS events
            if "ids" in event_types:
                ids_alerts = await self._fetch_ids_events(
                    client, base_url, site, since_ts, now_ts, limit
                )
                normalized_alerts.extend(ids_alerts)

            # Fetch alarms
            if "alarms" in event_types or self.config.get("include_alarms", True):
                alarm_alerts = await self._fetch_alarms(
                    client, base_url, site, since_ts, limit
                )
                normalized_alerts.extend(alarm_alerts)

            # Fetch security-relevant system events
            if "events" in event_types:
                event_alerts = await self._fetch_security_events(
                    client, base_url, site, since_ts, now_ts, limit
                )
                normalized_alerts.extend(event_alerts)

            logger.info(f"UniFi fetched {len(normalized_alerts)} events")

            # Sort by timestamp and apply limit
            normalized_alerts.sort(key=lambda x: x.created_at_source)
            if len(normalized_alerts) > limit:
                normalized_alerts = normalized_alerts[:limit]

            # Generate cursor for pagination (timestamp of last event)
            next_cursor = None
            if normalized_alerts:
                last_ts = int(normalized_alerts[-1].created_at_source.timestamp() * 1000)
                next_cursor = str(last_ts)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch events from UniFi: {str(e)}")

    async def _fetch_ids_events(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        site: str,
        since_ts: int,
        now_ts: int,
        limit: int,
    ) -> list[NormalizedAlert]:
        """Fetch IDS/IPS events from UniFi controller."""
        try:
            response = await client.get(
                f"{base_url}/proxy/network/api/s/{site}/stat/ips/event",
                params={
                    "start": since_ts,
                    "end": now_ts,
                    "_limit": limit,
                },
            )

            if response.status_code != 200:
                return []

            data = response.json()
            if data.get("meta", {}).get("rc") != "ok":
                return []

            events = data.get("data", [])
            return [self._normalize_ids_event(event) for event in events]
        except Exception:
            return []

    async def _fetch_alarms(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        site: str,
        since_ts: int,
        limit: int,
    ) -> list[NormalizedAlert]:
        """Fetch alarms from UniFi controller."""
        try:
            response = await client.get(
                f"{base_url}/proxy/network/api/s/{site}/stat/alarm",
            )

            if response.status_code != 200:
                return []

            data = response.json()
            if data.get("meta", {}).get("rc") != "ok":
                return []

            alarms = data.get("data", [])

            # Filter by time
            filtered_alarms = []
            for alarm in alarms:
                alarm_time = alarm.get("time", alarm.get("datetime", 0))
                if isinstance(alarm_time, (int, float)) and alarm_time >= since_ts:
                    filtered_alarms.append(alarm)

            return [self._normalize_alarm(alarm) for alarm in filtered_alarms[:limit]]
        except Exception:
            return []

    async def _fetch_security_events(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        site: str,
        since_ts: int,
        now_ts: int,
        limit: int,
    ) -> list[NormalizedAlert]:
        """Fetch security-relevant system events from UniFi controller."""
        try:
            response = await client.get(
                f"{base_url}/proxy/network/api/s/{site}/stat/event",
                params={
                    "start": since_ts,
                    "end": now_ts,
                    "_limit": limit * 2,  # Fetch more since we'll filter
                },
            )

            if response.status_code != 200:
                return []

            data = response.json()
            if data.get("meta", {}).get("rc") != "ok":
                return []

            events = data.get("data", [])

            # Filter for security-relevant events only
            security_events = [
                event for event in events
                if self._is_security_event(event)
            ]

            return [self._normalize_security_event(event) for event in security_events[:limit]]
        except Exception:
            return []

    def _is_security_event(self, event: dict[str, Any]) -> bool:
        """Check if an event is security-relevant."""
        event_key = event.get("key", "")
        return event_key in SECURITY_EVENT_TYPES

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """
        Normalize a raw alert from UniFi.

        Dispatches to the appropriate normalizer based on event type.
        """
        # Determine event type and dispatch
        if "inner_alert_signature" in raw_alert:
            return self._normalize_ids_event(raw_alert)
        elif "archived" in raw_alert and "key" not in raw_alert:
            return self._normalize_alarm(raw_alert)
        else:
            return self._normalize_security_event(raw_alert)

    def _normalize_ids_event(self, event: dict[str, Any]) -> NormalizedAlert:
        """Normalize an IDS/IPS event to the unified alert schema."""
        # Extract action and signature
        action = event.get("inner_alert_action", "alert")
        signature = event.get("inner_alert_signature", "Unknown IDS Event")
        category = event.get("catname", "")

        # Build title
        title = f"[{action.upper()}] {signature}"

        # Build description with network details
        src_ip = event.get("src_ip", "unknown")
        dst_ip = event.get("dst_ip", "unknown")
        src_port = event.get("src_port", "")
        dst_port = event.get("dst_port", "")
        protocol = event.get("proto", "").upper()
        src_country = event.get("src_country_name", "")
        dst_country = event.get("dst_country_name", "")

        description_parts = [
            f"Category: {category}" if category else None,
            f"Source: {src_ip}:{src_port}" if src_port else f"Source: {src_ip}",
            f"Destination: {dst_ip}:{dst_port}" if dst_port else f"Destination: {dst_ip}",
            f"Protocol: {protocol}" if protocol else None,
            f"Source Country: {src_country}" if src_country else None,
            f"Destination Country: {dst_country}" if dst_country else None,
        ]
        description = " | ".join(filter(None, description_parts))

        # Map severity
        inner_severity = event.get("inner_alert_severity", 2)
        severity = self._map_ids_severity(inner_severity)

        # Build tags
        tags = []
        if action:
            tags.append(f"action:{action}")
        if category:
            tags.append(f"category:{category.split()[0] if category else ''}")
        if protocol:
            tags.append(f"protocol:{protocol.lower()}")
        if src_country:
            tags.append(f"src_country:{src_country}")
        if dst_country:
            tags.append(f"dst_country:{dst_country}")

        # Get MITRE mappings
        mitre_tactics, mitre_techniques = self._map_mitre(category)

        # Parse timestamp
        timestamp_ms = event.get("timestamp", event.get("time", 0))
        if timestamp_ms:
            created_at = datetime.utcfromtimestamp(timestamp_ms / 1000)
        else:
            created_at = datetime.utcnow()

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=event.get("_id", str(uuid.uuid4())),
            title=title,
            description=description,
            severity=severity,
            status="open",
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=str(event.get("inner_alert_signature_id", "")),
            rule_name=signature,
            tags=tags,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=event,
            ingested_at=datetime.utcnow(),
        )

    def _normalize_alarm(self, alarm: dict[str, Any]) -> NormalizedAlert:
        """Normalize an alarm to the unified alert schema."""
        # Get alarm details
        key = alarm.get("key", "")
        msg = alarm.get("msg", "UniFi Alarm")

        # Build title
        title = f"[ALARM] {msg}"

        # Build description
        description_parts = []
        if "ap_name" in alarm:
            description_parts.append(f"AP: {alarm['ap_name']}")
        if "client_name" in alarm or "guest" in alarm:
            client = alarm.get("client_name") or alarm.get("guest", {}).get("name", "Unknown")
            description_parts.append(f"Client: {client}")
        if "gw_name" in alarm:
            description_parts.append(f"Gateway: {alarm['gw_name']}")

        description = " | ".join(description_parts) if description_parts else msg

        # Determine severity based on alarm type
        severity = "medium"
        if "critical" in key.lower() or "intrusion" in key.lower():
            severity = "critical"
        elif "warning" in key.lower() or "failed" in key.lower():
            severity = "high"
        elif "info" in key.lower():
            severity = "info"

        # Determine status from archived flag
        status = "closed" if alarm.get("archived", False) else "open"

        # Parse timestamp
        timestamp_ms = alarm.get("time", alarm.get("datetime", 0))
        if timestamp_ms:
            created_at = datetime.utcfromtimestamp(timestamp_ms / 1000)
        else:
            created_at = datetime.utcnow()

        # Build tags
        tags = [f"alarm_type:{key}"]
        if "site_name" in alarm:
            tags.append(f"site:{alarm['site_name']}")

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=alarm.get("_id", str(uuid.uuid4())),
            title=title,
            description=description,
            severity=severity,
            status=status,
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=key,
            rule_name=key,
            tags=tags,
            mitre_tactics=[],
            mitre_techniques=[],
            raw_data=alarm,
            ingested_at=datetime.utcnow(),
        )

    def _normalize_security_event(self, event: dict[str, Any]) -> NormalizedAlert:
        """Normalize a security-relevant system event to the unified alert schema."""
        event_key = event.get("key", "Unknown Event")
        msg = event.get("msg", event_key)

        # Build title
        title = f"[EVENT] {msg}"

        # Build description with context
        description_parts = []
        if "user" in event:
            description_parts.append(f"User: {event['user']}")
        if "client" in event:
            description_parts.append(f"Client: {event['client']}")
        if "hostname" in event:
            description_parts.append(f"Hostname: {event['hostname']}")
        if "ip" in event:
            description_parts.append(f"IP: {event['ip']}")
        if "ap" in event:
            description_parts.append(f"AP: {event['ap']}")

        description = " | ".join(description_parts) if description_parts else msg

        # Map severity based on event type
        severity = self._map_event_severity(event_key)

        # Parse timestamp
        timestamp_ms = event.get("time", event.get("datetime", 0))
        if timestamp_ms:
            created_at = datetime.utcfromtimestamp(timestamp_ms / 1000)
        else:
            created_at = datetime.utcnow()

        # Build tags
        tags = [f"event_type:{event_key}"]
        if "site_name" in event:
            tags.append(f"site:{event['site_name']}")
        if "subsystem" in event:
            tags.append(f"subsystem:{event['subsystem']}")

        # Map MITRE for certain event types
        mitre_tactics: list[str] = []
        mitre_techniques: list[str] = []

        if "LoginFailed" in event_key or "AuthorizationFailed" in event_key:
            mitre_tactics = ["TA0006"]  # Credential Access
            mitre_techniques = ["T1110"]  # Brute Force
        elif "RogueAP" in event_key:
            mitre_tactics = ["TA0001"]  # Initial Access
            mitre_techniques = ["T1200"]  # Hardware Additions
        elif "Blocked" in event_key:
            mitre_tactics = ["TA0005"]  # Defense Evasion
            mitre_techniques = []

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="unifi",
            external_id=event.get("_id", str(uuid.uuid4())),
            title=title,
            description=description,
            severity=severity,
            status="open",
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=event_key,
            rule_name=event_key,
            tags=tags,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=event,
            ingested_at=datetime.utcnow(),
        )

    def _map_ids_severity(self, severity: int) -> str:
        """Map IDS severity (1-3) to standard values."""
        severity_map = {
            1: "critical",
            2: "high",
            3: "medium",
        }
        return severity_map.get(severity, "medium")

    def _map_event_severity(self, event_key: str) -> str:
        """Map event type to severity."""
        if "LoginFailed" in event_key or "AuthorizationFailed" in event_key:
            return "medium"
        elif "Blocked" in event_key:
            return "medium"
        elif "RogueAP" in event_key:
            return "high"
        elif "Interference" in event_key:
            return "low"
        elif "StpBlockPortActive" in event_key or "AclDeny" in event_key:
            return "medium"
        else:
            return "low"

    def _map_mitre(self, catname: str) -> tuple[list[str], list[str]]:
        """Map IDS category to MITRE ATT&CK tactics and techniques."""
        if not catname:
            return [], []

        # Check for matching category prefix
        for prefix, (tactics, techniques) in MITRE_MAPPINGS.items():
            if catname.startswith(prefix):
                return tactics, techniques

        return [], []
