"""
Okta Data Source Connector

Integrates with Okta to fetch and normalize security events and threat insights.
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


class OktaConnector(DataSourceConnector):
    """
    Okta data source connector.

    Fetches security events from Okta System Log and ThreatInsight,
    including:
    - Authentication failures
    - Suspicious activity
    - Policy violations
    - User behavior anomalies
    - ThreatInsight detections
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="okta",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Okta",
            description="Okta - Identity security events and threat insights",
            icon="okta",
            config_schema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "title": "Okta Domain",
                        "description": "Your Okta domain (e.g., company.okta.com)",
                    },
                    "event_types": {
                        "type": "array",
                        "title": "Event Types",
                        "description": (
                            "Security event types to fetch (empty = all security events)"
                        ),
                        "items": {
                            "type": "string",
                            "enum": [
                                "user.session.start",
                                "user.authentication.auth_via_mfa",
                                "user.authentication.sso",
                                "user.account.lock",
                                "user.account.privilege.grant",
                                "user.mfa.factor.deactivate",
                                "security.threat.detected",
                                "policy.evaluate_sign_on",
                                "system.api_token.create",
                                "application.lifecycle.update",
                            ],
                        },
                        "default": [],
                    },
                    "severity_filter": {
                        "type": "string",
                        "title": "Minimum Severity",
                        "description": "Minimum event severity to fetch",
                        "enum": ["DEBUG", "INFO", "WARN", "ERROR"],
                        "default": "WARN",
                    },
                    "include_threat_insight": {
                        "type": "boolean",
                        "title": "Include ThreatInsight",
                        "description": "Also fetch Okta ThreatInsight detections",
                        "default": True,
                    },
                },
                "required": ["domain"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "Okta API token with read:logs scope",
                        "format": "password",
                    },
                },
                "required": ["api_token"],
            },
        )

    def _get_base_url(self) -> str:
        """Get the Okta API base URL."""
        domain = self.config.get("domain", "").strip()
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return domain.rstrip("/")

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"SSWS {self.credentials.get('api_token', '')}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Okta API."""
        start_time = time.time()
        try:
            base_url = self._get_base_url()

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test by getting org info
                response = await client.get(
                    f"{base_url}/api/v1/org",
                    headers=self._get_headers(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                org_data = response.json()
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Okta",
                    details={
                        "org_name": org_data.get("name"),
                        "org_url": org_data.get("_links", {}).get("organization", {}).get("href"),
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check API token",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Access denied - ensure token has required scopes",
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
        """Fetch security events from Okta System Log."""
        try:
            base_url = self._get_base_url()

            # Build query parameters
            since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            # Build filter for security events
            filters = []

            # Event type filter
            event_types = self.config.get("event_types", [])
            if event_types:
                event_filter = " or ".join([f'eventType eq "{et}"' for et in event_types])
                filters.append(f"({event_filter})")
            else:
                # Default: fetch security-relevant events
                security_events = [
                    "user.account.lock",
                    "user.session.impersonation.initiate",
                    "user.mfa.factor.deactivate",
                    "security.threat.detected",
                    "user.account.privilege.grant",
                    "system.api_token.create",
                    "policy.evaluate_sign_on",
                ]
                event_filter = " or ".join([f'eventType eq "{et}"' for et in security_events])
                # Also include failed authentications
                event_filter += (
                    ' or (eventType eq "user.authentication.auth_via_mfa"'
                    ' and outcome.result eq "FAILURE")'
                )
                event_filter += (
                    ' or (eventType eq "user.session.start" and outcome.result eq "FAILURE")'
                )
                filters.append(f"({event_filter})")

            # Severity filter
            severity_map = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
            min_severity = self.config.get("severity_filter", "WARN")
            min_level = severity_map.get(min_severity, 2)
            if min_level >= 2:
                filters.append('(severity eq "WARN" or severity eq "ERROR")')

            filter_str = " and ".join(filters) if filters else None

            params = {
                "since": since_str,
                "limit": min(limit, 1000),  # Okta max is 1000
                "sortOrder": "ASCENDING",
            }
            if filter_str:
                params["filter"] = filter_str

            url = cursor if cursor else f"{base_url}/api/v1/logs"

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(),
                    params=params if not cursor else None,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"Failed to fetch logs: {response.status_code} - {response.text}"
                    )

                events = response.json()

                # Get next link from headers
                next_cursor = None
                link_header = response.headers.get("link", "")
                if 'rel="next"' in link_header:
                    # Parse the next URL from Link header
                    for link in link_header.split(","):
                        if 'rel="next"' in link:
                            next_cursor = link.split(";")[0].strip("<> ")
                            break

            # Normalize events to alerts (only security-relevant ones)
            normalized_alerts = []
            for event in events:
                # Only create alerts for security events
                if self._is_security_event(event):
                    normalized = self.normalize_alert(event)
                    normalized_alerts.append(normalized)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch events from Okta: {str(e)}")

    def _is_security_event(self, event: dict[str, Any]) -> bool:
        """Determine if an event should be treated as a security alert."""
        event_type = event.get("eventType", "")

        # Always alert on these event types
        security_event_types = [
            "user.account.lock",
            "user.session.impersonation",
            "user.mfa.factor.deactivate",
            "security.threat.detected",
            "user.account.privilege.grant",
            "system.api_token.create",
        ]
        if any(et in event_type for et in security_event_types):
            return True

        # Alert on authentication failures
        outcome = event.get("outcome", {})
        if outcome.get("result") == "FAILURE":
            return True

        # Alert on WARN or ERROR severity
        if event.get("severity") in ["WARN", "ERROR"]:
            return True

        return False

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize an Okta event to the unified schema."""
        # Parse timestamps
        created_at = datetime.utcnow()
        if raw_alert.get("published"):
            try:
                created_at = datetime.fromisoformat(raw_alert["published"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Build title based on event type
        event_type = raw_alert.get("eventType", "okta.event")
        display_message = raw_alert.get("displayMessage", "")
        title = display_message if display_message else event_type.replace(".", " ").title()

        # Add outcome to title if failed
        outcome = raw_alert.get("outcome", {})
        if outcome.get("result") == "FAILURE":
            title = f"[FAILED] {title}"
            if outcome.get("reason"):
                title += f" - {outcome['reason']}"

        # Build description
        description_parts = []
        if display_message:
            description_parts.append(display_message)

        # Add actor info
        actor = raw_alert.get("actor", {})
        if actor.get("displayName"):
            description_parts.append(
                f"Actor: {actor['displayName']} ({actor.get('alternateId', 'N/A')})"
            )

        # Add target info
        targets = raw_alert.get("target", [])
        for target in targets[:3]:
            target_type = target.get("type", "Unknown")
            target_name = target.get("displayName", target.get("alternateId", ""))
            if target_name:
                description_parts.append(f"Target ({target_type}): {target_name}")

        # Add client info
        client = raw_alert.get("client", {})
        if client.get("ipAddress"):
            geo = client.get("geographicalContext", {})
            location = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(", ")
            description_parts.append(f"Client IP: {client['ipAddress']} ({location})")

        description = "\n".join(description_parts)

        # Build tags
        tags = []
        tags.append(f"event:{event_type}")
        if outcome.get("result"):
            tags.append(f"outcome:{outcome['result'].lower()}")
        if actor.get("type"):
            tags.append(f"actor_type:{actor['type']}")
        if client.get("device"):
            tags.append(f"device:{client['device']}")
        if client.get("ipAddress"):
            tags.append(f"ip:{client['ipAddress']}")

        # Determine severity
        severity = self._determine_severity(raw_alert)

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="okta",
            external_id=raw_alert.get("uuid", str(uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=severity,
            status=self.normalize_status(outcome.get("result", "SUCCESS")),
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=event_type,
            rule_name=event_type.replace(".", " ").title(),
            tags=tags[:20],
            mitre_tactics=self._map_mitre_tactics(event_type),
            mitre_techniques=self._map_mitre_techniques(event_type),
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def _determine_severity(self, event: dict[str, Any]) -> str:
        """Determine alert severity based on event characteristics."""
        event_type = event.get("eventType", "")
        outcome = event.get("outcome", {}).get("result", "")
        okta_severity = event.get("severity", "INFO")

        # Critical events
        if "security.threat.detected" in event_type:
            return "critical"
        if "user.session.impersonation" in event_type:
            return "critical"

        # High severity events
        if "user.account.privilege.grant" in event_type:
            return "high"
        if "system.api_token.create" in event_type:
            return "high"
        if "user.mfa.factor.deactivate" in event_type:
            return "high"
        if "user.account.lock" in event_type:
            return "high"

        # Medium for failures
        if outcome == "FAILURE":
            return "medium"

        # Map Okta severity
        severity_map = {
            "ERROR": "high",
            "WARN": "medium",
            "INFO": "low",
            "DEBUG": "info",
        }
        return severity_map.get(okta_severity, "low")

    def normalize_status(self, outcome_result: str) -> str:
        """Normalize Okta outcome to standard status."""
        if outcome_result == "FAILURE":
            return "open"
        return "open"  # All Okta events start as open for review

    def _map_mitre_tactics(self, event_type: str) -> list[str]:
        """Map Okta event types to MITRE ATT&CK tactics."""
        tactic_map = {
            "user.session.start": ["TA0001"],  # Initial Access
            "user.authentication": ["TA0006"],  # Credential Access
            "user.account.lock": ["TA0006"],  # Credential Access
            "user.account.privilege": ["TA0004"],  # Privilege Escalation
            "user.mfa.factor": ["TA0005", "TA0006"],  # Defense Evasion, Credential Access
            "security.threat": ["TA0001", "TA0006"],  # Initial Access, Credential Access
            "system.api_token": ["TA0003"],  # Persistence
        }

        tactics = []
        for key, tacs in tactic_map.items():
            if key in event_type:
                tactics.extend(tacs)
        return list(set(tactics))

    def _map_mitre_techniques(self, event_type: str) -> list[str]:
        """Map Okta event types to MITRE ATT&CK techniques."""
        technique_map = {
            "user.session.start": ["T1078"],  # Valid Accounts
            "user.authentication.auth_via_mfa": [
                "T1111"
            ],  # Multi-Factor Authentication Interception
            "user.account.lock": ["T1110"],  # Brute Force
            "user.account.privilege.grant": ["T1098"],  # Account Manipulation
            "user.mfa.factor.deactivate": ["T1556"],  # Modify Authentication Process
            "system.api_token.create": ["T1098.001"],  # Additional Cloud Credentials
        }

        techniques = []
        for key, techs in technique_map.items():
            if key in event_type:
                techniques.extend(techs)
        return list(set(techniques))
