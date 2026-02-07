"""
Microsoft Entra ID Data Source Connector

Integrates with Microsoft Entra ID (formerly Azure AD) to fetch identity
protection alerts and risky user/sign-in detections.
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


class EntraIDConnector(DataSourceConnector):
    """
    Microsoft Entra ID data source connector.

    Fetches identity protection signals from Microsoft Entra ID including:
    - Risky users
    - Risky sign-ins
    - Risk detections
    - Identity protection alerts

    Uses Microsoft Graph Identity Protection API.
    """

    _access_token: Optional[str] = None
    _token_expires_at: float = 0

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="entra_id",
            category=ConnectorCategory.DATA_SOURCE,
            display_name="Microsoft Entra ID",
            description="Microsoft Entra ID - Identity protection and risky sign-in detection",
            icon="microsoft",
            config_schema={
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "title": "Tenant ID",
                        "description": "Azure AD tenant ID (directory ID)",
                    },
                    "fetch_risky_users": {
                        "type": "boolean",
                        "title": "Fetch Risky Users",
                        "description": "Fetch users flagged as risky",
                        "default": True,
                    },
                    "fetch_risky_signins": {
                        "type": "boolean",
                        "title": "Fetch Risky Sign-ins",
                        "description": "Fetch risky sign-in events",
                        "default": True,
                    },
                    "risk_level_filter": {
                        "type": "array",
                        "title": "Risk Level Filter",
                        "description": "Only fetch detections with these risk levels",
                        "items": {
                            "type": "string",
                            "enum": ["high", "medium", "low", "hidden", "none"],
                        },
                        "default": ["high", "medium"],
                    },
                },
                "required": ["tenant_id"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "title": "Client ID",
                        "description": "Azure AD application (client) ID",
                    },
                    "client_secret": {
                        "type": "string",
                        "title": "Client Secret",
                        "description": "Azure AD application client secret",
                        "format": "password",
                    },
                },
                "required": ["client_id", "client_secret"],
            },
        )

    async def _get_access_token(self) -> str:
        """Get OAuth2 access token from Azure AD (with caching)."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        tenant_id = self.config.get("tenant_id")
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                token_url,
                data={
                    "client_id": self.credentials.get("client_id", ""),
                    "client_secret": self.credentials.get("client_secret", ""),
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )

        if response.status_code != 200:
            raise Exception(f"Failed to get access token: {response.status_code} - {response.text}")

        data = response.json()
        self._access_token = data.get("access_token", "")
        self._token_expires_at = time.time() + data.get("expires_in", 3600)

        return self._access_token

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Microsoft Graph Identity Protection API."""
        start_time = time.time()
        try:
            token = await self._get_access_token()

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Test by querying risk detections (top 1)
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/identityProtection/riskDetections",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"$top": 1},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Microsoft Entra ID",
                    details={"tenant_id": self.config.get("tenant_id")},
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check client ID and secret",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 403:
                return ConnectionTestResult(
                    success=False,
                    message="Access denied - ensure app has IdentityRiskEvent.Read.All permission",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}: {response.text}",
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
        """Fetch risk detections from Microsoft Entra ID."""
        try:
            token = await self._get_access_token()

            # Build OData filter
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_parts = [f"detectedDateTime ge {since_str}"]

            # Add risk level filter
            risk_levels = self.config.get("risk_level_filter", ["high", "medium"])
            if risk_levels:
                level_conditions = " or ".join([f"riskLevel eq '{level}'" for level in risk_levels])
                filter_parts.append(f"({level_conditions})")

            odata_filter = " and ".join(filter_parts)

            params = {
                "$filter": odata_filter,
                "$top": min(limit, 100),
                "$orderby": "detectedDateTime asc",
            }

            url = cursor if cursor else "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    params=params if not cursor else None,
                )

                if response.status_code != 200:
                    raise Exception(f"Failed to fetch risk detections: {response.status_code} - {response.text}")

                data = response.json()

            detections = data.get("value", [])
            next_cursor = data.get("@odata.nextLink")

            # Normalize detections
            normalized_alerts = []
            for detection in detections:
                normalized = self.normalize_alert(detection)
                normalized_alerts.append(normalized)

            return normalized_alerts, next_cursor

        except Exception as e:
            raise Exception(f"Failed to fetch risk detections from Entra ID: {str(e)}")

    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """Normalize a Microsoft Entra ID risk detection to the unified schema."""
        # Parse timestamps
        created_at = datetime.utcnow()
        if raw_alert.get("detectedDateTime"):
            try:
                created_at = datetime.fromisoformat(raw_alert["detectedDateTime"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        last_updated = None
        if raw_alert.get("lastUpdatedDateTime"):
            try:
                last_updated = datetime.fromisoformat(raw_alert["lastUpdatedDateTime"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Build title
        risk_type = raw_alert.get("riskEventType", "Unknown Risk")
        risk_type_display = risk_type.replace("_", " ").title()
        user_principal = raw_alert.get("userPrincipalName", "Unknown User")
        title = f"{risk_type_display}: {user_principal}"

        # Build description
        description_parts = []
        description_parts.append(f"Risk Type: {risk_type_display}")
        description_parts.append(f"User: {user_principal}")
        description_parts.append(f"Risk Level: {raw_alert.get('riskLevel', 'Unknown')}")
        description_parts.append(f"Risk State: {raw_alert.get('riskState', 'Unknown')}")

        if raw_alert.get("ipAddress"):
            description_parts.append(f"IP Address: {raw_alert['ipAddress']}")

        location = raw_alert.get("location", {})
        if location:
            loc_str = f"{location.get('city', '')}, {location.get('state', '')}, {location.get('countryOrRegion', '')}".strip(", ")
            if loc_str:
                description_parts.append(f"Location: {loc_str}")

        if raw_alert.get("additionalInfo"):
            description_parts.append(f"Additional Info: {raw_alert['additionalInfo']}")

        description = "\n".join(description_parts)

        # Build tags
        tags = []
        tags.append(f"risk_type:{risk_type}")
        tags.append(f"risk_level:{raw_alert.get('riskLevel', 'unknown')}")
        tags.append(f"risk_state:{raw_alert.get('riskState', 'unknown')}")
        if raw_alert.get("source"):
            tags.append(f"source:{raw_alert['source']}")
        if raw_alert.get("ipAddress"):
            tags.append(f"ip:{raw_alert['ipAddress']}")
        if raw_alert.get("userPrincipalName"):
            tags.append(f"user:{raw_alert['userPrincipalName']}")

        # Map MITRE tactics/techniques
        mitre_tactics, mitre_techniques = self._map_mitre(risk_type)

        return NormalizedAlert(
            id=uuid.uuid4(),
            connector_id=self.connector_id,
            source_type="entra_id",
            external_id=raw_alert.get("id", str(uuid.uuid4())),
            title=title[:500],
            description=description[:2000] if description else None,
            severity=self.normalize_severity(raw_alert.get("riskLevel", "medium")),
            status=self.normalize_status(raw_alert.get("riskState", "atRisk")),
            created_at_source=created_at,
            updated_at_source=last_updated,
            rule_id=risk_type,
            rule_name=risk_type_display,
            tags=tags[:20],
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            raw_data=raw_alert,
            ingested_at=datetime.utcnow(),
        )

    def normalize_severity(self, risk_level: str) -> str:
        """Normalize Entra ID risk level to standard severity."""
        severity_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "hidden": "info",
            "none": "info",
        }
        return severity_map.get(risk_level.lower(), "medium")

    def normalize_status(self, risk_state: str) -> str:
        """Normalize Entra ID risk state to standard status."""
        status_map = {
            "atRisk": "open",
            "confirmedCompromised": "open",
            "remediated": "resolved",
            "dismissed": "closed",
            "confirmedSafe": "closed",
        }
        return status_map.get(risk_state, "open")

    def _map_mitre(self, risk_type: str) -> tuple[list[str], list[str]]:
        """Map Entra ID risk types to MITRE ATT&CK."""
        mitre_map = {
            "anonymizedIPAddress": (["TA0005"], ["T1090"]),  # Defense Evasion, Proxy
            "maliciousIPAddress": (["TA0001"], ["T1078"]),  # Initial Access, Valid Accounts
            "unfamiliarFeatures": (["TA0001"], ["T1078"]),  # Initial Access, Valid Accounts
            "malwareInfectedIPAddress": (["TA0001"], ["T1078"]),
            "suspiciousIPAddress": (["TA0001"], ["T1078"]),
            "leakedCredentials": (["TA0006"], ["T1552"]),  # Credential Access, Unsecured Credentials
            "passwordSpray": (["TA0006"], ["T1110.003"]),  # Credential Access, Password Spraying
            "impossibleTravel": (["TA0001"], ["T1078"]),  # Initial Access, Valid Accounts
            "newCountry": (["TA0001"], ["T1078"]),
            "anomalousToken": (["TA0006"], ["T1528"]),  # Credential Access, Steal Application Access Token
            "tokenIssuerAnomaly": (["TA0006"], ["T1606"]),  # Forge Web Credentials
            "suspiciousBrowser": (["TA0005"], ["T1036"]),  # Defense Evasion, Masquerading
            "riskyIPAddress": (["TA0001"], ["T1078"]),
            "mcasImpossibleTravel": (["TA0001"], ["T1078"]),
            "mcasSuspiciousInboxManipulationRules": (["TA0003"], ["T1137"]),  # Persistence, Office Application Startup
        }

        return mitre_map.get(risk_type, ([], []))
