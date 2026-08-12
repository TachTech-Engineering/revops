"""
AlienVault OTX (Open Threat Exchange) integration.
Free tier with API key registration.
"""

import httpx

from app.config import settings


class OTXConnector:
    """Connector for AlienVault OTX threat intelligence API."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    # Mapping of IOC types to OTX indicator types
    IOC_TYPE_MAP = {
        "ip_address": "IPv4",
        "domain": "domain",
        "url": "url",
        "file_hash_md5": "file",
        "file_hash_sha1": "file",
        "file_hash_sha256": "file",
        "email": "email",
    }

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or settings.otx_api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def get_indicator(self, indicator: str, indicator_type: str) -> dict:
        """
        Get threat intelligence for an indicator.

        Args:
            indicator: The indicator value (IP, domain, hash, etc.)
            indicator_type: Type of indicator (from IOC types)

        Returns:
            Dictionary with threat intel data
        """
        if not self.is_configured:
            raise ValueError("OTX API key not configured")

        otx_type = self.IOC_TYPE_MAP.get(indicator_type, indicator_type)

        # Determine the correct endpoint based on type
        if otx_type == "IPv4":
            section = "general"
            endpoint = f"/indicators/IPv4/{indicator}/{section}"
        elif otx_type == "domain":
            section = "general"
            endpoint = f"/indicators/domain/{indicator}/{section}"
        elif otx_type == "url":
            section = "general"
            endpoint = f"/indicators/url/{indicator}/{section}"
        elif otx_type == "file":
            section = "general"
            endpoint = f"/indicators/file/{indicator}/{section}"
        else:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}{endpoint}",
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )

            if response.status_code == 400:
                raise ValueError(f"Invalid indicator: {indicator}")
            elif response.status_code == 403:
                raise ValueError("Invalid OTX API key")

            response.raise_for_status()
            data = response.json()

            # Get pulses (threat intel reports)
            pulses = await self.get_pulses(indicator, otx_type)

            return self._format_response(data, pulses, indicator_type)

    async def get_pulses(self, indicator: str, otx_type: str) -> list[dict]:
        """
        Get OTX pulses (threat intel reports) containing this indicator.

        Args:
            indicator: The indicator value
            otx_type: OTX indicator type

        Returns:
            List of pulse summaries
        """
        if not self.is_configured:
            return []

        if otx_type == "IPv4":
            endpoint = f"/indicators/IPv4/{indicator}/general"
        elif otx_type == "domain":
            endpoint = f"/indicators/domain/{indicator}/general"
        elif otx_type == "url":
            endpoint = f"/indicators/url/{indicator}/general"
        elif otx_type == "file":
            endpoint = f"/indicators/file/{indicator}/general"
        else:
            return []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.BASE_URL}{endpoint}",
                    headers={
                        "X-OTX-API-KEY": self.api_key,
                        "Accept": "application/json",
                    },
                    timeout=30.0,
                )

                if response.status_code != 200:
                    return []

                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])

                return [
                    {
                        "id": p.get("id"),
                        "name": p.get("name"),
                        "description": p.get("description", "")[:200],
                        "author_name": p.get("author", {}).get("username"),
                        "created": p.get("created"),
                        "modified": p.get("modified"),
                        "tags": p.get("tags", [])[:5],
                        "targeted_countries": p.get("targeted_countries", []),
                        "malware_families": p.get("malware_families", []),
                        "attack_ids": [a.get("id") for a in p.get("attack_ids", [])][:5],
                        "references": p.get("references", [])[:3],
                    }
                    for p in pulses[:10]  # Limit to 10 pulses
                ]
        except Exception:
            return []

    def _format_response(self, data: dict, pulses: list[dict], indicator_type: str) -> dict:
        """Format the OTX response for consistent output."""
        pulse_info = data.get("pulse_info", {})

        # Calculate risk based on pulse count and recency
        pulse_count = pulse_info.get("count", 0)
        risk_level = self._calculate_risk_level(pulse_count)

        result = {
            "indicator": data.get("indicator"),
            "indicator_type": indicator_type,
            "pulse_count": pulse_count,
            "risk_level": risk_level,
            "pulses": pulses,
            "first_seen": None,
            "last_seen": None,
            "tags": [],
            "malware_families": [],
            "attack_techniques": [],
        }

        # Extract additional data based on type
        if indicator_type == "ip_address":
            result.update(
                {
                    "asn": data.get("asn"),
                    "country_code": data.get("country_code"),
                    "country_name": data.get("country_name"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                }
            )
        elif indicator_type == "domain":
            result.update(
                {
                    "alexa": data.get("alexa"),
                    "whois": data.get("whois"),
                }
            )
        elif indicator_type.startswith("file_hash"):
            result.update(
                {
                    "file_type": data.get("type_title"),
                    "file_class": data.get("file_class"),
                    "file_size": data.get("filesize"),
                }
            )

        # Aggregate tags and malware families from pulses
        all_tags = set()
        all_malware = set()
        all_attacks = set()

        for pulse in pulses:
            all_tags.update(pulse.get("tags", []))
            all_malware.update(pulse.get("malware_families", []))
            all_attacks.update(pulse.get("attack_ids", []))

        result["tags"] = list(all_tags)[:10]
        result["malware_families"] = list(all_malware)[:5]
        result["attack_techniques"] = list(all_attacks)[:10]

        return result

    def _calculate_risk_level(self, pulse_count: int) -> str:
        """Calculate risk level from pulse count."""
        if pulse_count >= 10:
            return "critical"
        elif pulse_count >= 5:
            return "high"
        elif pulse_count >= 2:
            return "medium"
        elif pulse_count >= 1:
            return "low"
        return "clean"


# Singleton instance
otx_connector = OTXConnector()
