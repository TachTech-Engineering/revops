"""
Cloudflare Security Data Source Connector

Integrates with Cloudflare to fetch and normalize security events from
WAF, Bot Management, DDoS Protection, and Zero Trust.
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


class CloudflareConnector(DataSourceConnector):
    """
    Cloudflare data source connector.

    Fetches security events from Cloudflare including:
    - WAF events (firewall rules, managed rules, rate limiting)
    - Bot Management detections
    - DDoS attack events
    - Zero Trust Access logs
    - Security Center insights
    """

    BASE_URL = "https://api.cloudflare.com/client/v4"

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="cloudflare",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Cloudflare",
            description="Cloudflare - WAF, Bot Management, DDoS Protection, and Zero Trust security events",
            icon="cloudflare",
            config_schema={
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "string",
                        "title": "Account ID",
                        "description": "Cloudflare account ID",
                    },
                    "zone_ids": {
                        "type": "array",
                        "title": "Zone IDs",
                        "description": "Filter by specific zone IDs (empty = all zones)",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "event_types": {
                        "type": "array",
                        "title": "Event Types",
                        "description": "Types of security events to fetch",
                        "items": {
                            "type": "string",
                            "enum": [
                                "firewall_events",
                                "bot_management",
                                "ddos_events",
                                "access_requests",
                            ],
                        },
                        "default": ["firewall_events", "bot_management"],
                    },
                    "action_filter": {
                        "type": "array",
                        "title": "Action Filter",
                        "description": "Only fetch events with these actions",
                        "items": {
                            "type": "string",
                            "enum": ["block", "challenge", "js_challenge", "managed_challenge", "log", "bypass"],
                        },
                        "default": ["block", "challenge", "js_challenge", "managed_challenge"],
                    },
                },
                "required": ["account_id"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "Cloudflare API token with Analytics and Firewall read permissions",
                        "format": "password",
                    },
                },
                "required": ["api_token"],
            },
        )

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Bearer {self.credentials.get('api_token', '')}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Cloudflare API."""
        start_time = time.time()
        try:
            account_id = self.config.get("account_id")

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test by verifying token
                response = await client.get(
                    f"{self.BASE_URL}/user/tokens/verify",
                    headers=self._get_headers(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    return ConnectionTestResult(
                        success=True,
                        message="Successfully connected to Cloudflare",
                        details={
                            "account_id": account_id,
                            "token_status": data.get("result", {}).get("status"),
                        },
                        latency_ms=latency_ms,
                    )

            if response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check API token",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Access denied - ensure token has required permissions",
                    latency_ms=latency_ms,
                )
            else:
                error_msg = response.json().get("errors", [{}])[0].get("message", "Unknown error")
                return ConnectionTestResult(
                    success=False,
                    message=f"API error: {error_msg}",
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
        cursor: Optional[str] = None,
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        """Fetch security events from Cloudflare using GraphQL Analytics API."""
        try:
            account_id = self.config.get("account_id")
            zone_ids = self.config.get("zone_ids", [])
            action_filter = self.config.get("action_filter", ["block", "challenge", "js_challenge", "managed_challenge"])

            # Build GraphQL query for firewall events
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            until_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # Build filter
            filter_parts = [
                f'datetime_geq: "{since_str}"',
                f'datetime_leq: "{until_str}"',
            ]

            if action_filter:
                actions_str = ", ".join([f'"{a}"' for a in action_filter])
                filter_parts.append(f"action_in: [{actions_str}]")

            filter_str = ", ".join(filter_parts)

            query = f"""
            query {{
                viewer {{
                    accounts(filter: {{accountTag: "{account_id}"}}) {{
                        firewallEventsAdaptive(
                            filter: {{{filter_str}}}
                            limit: {min(limit, 10000)}
                            orderBy: [datetime_ASC]
                        ) {{
                            action
                            clientASNDescription
                            clientCountryName
                            clientIP
                            clientRequestHTTPHost
                            clientRequestHTTPMethodName
                            clientRequestPath
                            clientRequestQuery
                            datetime
                            rayName
                            ruleId
                            ruleName
                            source
                            userAgent
                            matchIndex
                            sampleInterval
                        }}
                    }}
                }}
            }}
            """

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.BASE_URL}/graphql",
                    headers=self._get_headers(),
                    json={"query": query},
                )

                if response.status_code != 200:
                    raise Exception(f"GraphQL request failed: {response.status_code} - {response.text}")

                data = response.json()

            if data.get("errors"):
                raise Exception(f"GraphQL errors: {data['errors']}")

            # Extract events
            events = []
            accounts = data.get("data", {}).get("viewer", {}).get("accounts", [])
            for account in accounts:
                events.extend(account.get("firewallEventsAdaptive", []))

            # Normalize events
            normalized_alerts = []
            for event in events:
                normalized = self.normalize_alert(event)
                normalized_alerts.append(normalized)

            # GraphQL doesn't have cursor pagination in the same way
            # Return None for next_cursor (implement offset-based if needed)
            return normalized_alerts, None

        except Exception as e:
            raise Exception(f"Failed to fetch security events from Cloudflare: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Cloudflare security event to the unified schema."""
        # Parse timestamp
        created_at = datetime.utcnow()
        if raw_alert.get("datetime"):
            try:
                created_at = datetime.fromisoformat(raw_alert["datetime"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Build title
        action = raw_alert.get("action", "unknown")
        source = raw_alert.get("source", "firewall")
        host = raw_alert.get("clientRequestHTTPHost", "unknown")
        client_ip = raw_alert.get("clientIP", "unknown")
        title = f"[{action.upper()}] {source} event on {host} from {client_ip}"

        # Build description
        description_parts = []
        description_parts.append(f"Action: {action}")
        description_parts.append(f"Source: {source}")

        if raw_alert.get("ruleName"):
            description_parts.append(f"Rule: {raw_alert['ruleName']} ({raw_alert.get('ruleId', 'N/A')})")

        description_parts.append(f"\nRequest: {raw_alert.get('clientRequestHTTPMethodName', 'GET')} {raw_alert.get('clientRequestPath', '/')}")
        if raw_alert.get("clientRequestQuery"):
            description_parts.append(f"Query: {raw_alert['clientRequestQuery'][:200]}")

        description_parts.append(f"\nClient IP: {client_ip}")
        if raw_alert.get("clientCountryName"):
            description_parts.append(f"Country: {raw_alert['clientCountryName']}")
        if raw_alert.get("clientASNDescription"):
            description_parts.append(f"ASN: {raw_alert['clientASNDescription']}")
        if raw_alert.get("userAgent"):
            description_parts.append(f"User-Agent: {raw_alert['userAgent'][:200]}")

        description = "\n".join(description_parts)

        # Build tags
        tags = []
        tags.append(f"action:{action}")
        tags.append(f"source:{source}")
        if raw_alert.get("clientCountryName"):
            tags.append(f"country:{raw_alert['clientCountryName']}")
        if raw_alert.get("clientIP"):
            tags.append(f"ip:{raw_alert['clientIP']}")
        if raw_alert.get("clientRequestHTTPHost"):
            tags.append(f"host:{raw_alert['clientRequestHTTPHost']}")
        if raw_alert.get("ruleId"):
            tags.append(f"rule:{raw_alert['ruleId']}")

        # Map MITRE based on source/action
        mitre_tactics, mitre_techniques = self._map_mitre(source, action)

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="cloudflare",
            external_id=raw_alert.get("rayName", str(uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=self._determine_severity(raw_alert),
            status="open",  # Cloudflare events are informational
            created_at_source=created_at,
            updated_at_source=None,
            rule_id=raw_alert.get("ruleId"),
            rule_name=raw_alert.get("ruleName") or raw_alert.get("source", "Cloudflare Rule"),
            tags=tags[:20],
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def _determine_severity(self, event: dict[str, Any]) -> str:
        """Determine severity based on event characteristics."""
        action = event.get("action", "").lower()
        source = event.get("source", "").lower()

        # High severity for blocks
        if action == "block":
            return "high"

        # Medium for challenges
        if action in ["challenge", "js_challenge", "managed_challenge"]:
            return "medium"

        # Check source for severity hints
        if "ddos" in source.lower():
            return "high"
        if "bot" in source.lower():
            return "medium"

        # Default
        return "low"

    def _map_mitre(self, source: str, action: str) -> tuple[list[str], list[str]]:
        """Map Cloudflare events to MITRE ATT&CK."""
        source_lower = source.lower()

        if "waf" in source_lower or "firewall" in source_lower:
            return (["TA0001", "TA0043"], ["T1190", "T1595"])  # Initial Access, Recon; Exploit Public-Facing, Active Scanning

        if "bot" in source_lower:
            return (["TA0043"], ["T1595.002"])  # Reconnaissance, Vulnerability Scanning

        if "ddos" in source_lower:
            return (["TA0040"], ["T1498", "T1499"])  # Impact, Network DoS, Endpoint DoS

        if "rate" in source_lower:
            return (["TA0006", "TA0040"], ["T1110"])  # Credential Access, Impact; Brute Force

        # Default for other sources
        return (["TA0043"], ["T1595"])  # Reconnaissance, Active Scanning
