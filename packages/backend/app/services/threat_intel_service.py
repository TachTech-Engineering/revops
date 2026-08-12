"""
Unified Threat Intelligence Service.
Aggregates results from multiple free-tier providers:
- AbuseIPDB (IP reputation)
- AlienVault OTX (multi-indicator)
- Abuse.ch (malware/URL)
"""

import asyncio

from app.services.integrations.abusech import abusech_connector
from app.services.integrations.abuseipdb import abuseipdb_connector
from app.services.integrations.otx import otx_connector


class ThreatIntelService:
    """Unified threat intelligence lookup service."""

    # IOC type mappings for each provider
    PROVIDER_SUPPORT = {
        "abuseipdb": ["ip_address"],
        "otx": [
            "ip_address",
            "domain",
            "url",
            "file_hash_md5",
            "file_hash_sha1",
            "file_hash_sha256",
        ],
        "abusech": ["url", "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "ip_address"],
    }

    async def lookup(self, indicator: str, indicator_type: str) -> dict:
        """
        Perform unified threat intelligence lookup across all providers.

        Args:
            indicator: The indicator value (IP, domain, hash, etc.)
            indicator_type: Type of indicator

        Returns:
            Dictionary with aggregated results from all providers
        """
        results = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "providers": {},
            "aggregate_risk_level": "unknown",
            "aggregate_score": 0,
            "total_providers_checked": 0,
            "providers_with_data": 0,
        }

        # Run lookups in parallel
        tasks = []
        provider_names = []

        # AbuseIPDB (IP only)
        if indicator_type in self.PROVIDER_SUPPORT["abuseipdb"]:
            if abuseipdb_connector.is_configured:
                tasks.append(self._lookup_abuseipdb(indicator))
                provider_names.append("abuseipdb")

        # OTX (multiple types)
        if indicator_type in self.PROVIDER_SUPPORT["otx"]:
            if otx_connector.is_configured:
                tasks.append(self._lookup_otx(indicator, indicator_type))
                provider_names.append("otx")

        # Abuse.ch (hashes and URLs, IPs for Feodo)
        if indicator_type in self.PROVIDER_SUPPORT["abusech"]:
            tasks.append(self._lookup_abusech(indicator, indicator_type))
            provider_names.append("abusech")

        # Execute all lookups
        if tasks:
            lookup_results = await asyncio.gather(*tasks, return_exceptions=True)

            for name, result in zip(provider_names, lookup_results):
                if isinstance(result, Exception):
                    results["providers"][name] = {
                        "error": str(result),
                        "available": False,
                    }
                else:
                    results["providers"][name] = {
                        "data": result,
                        "available": True,
                    }
                    results["providers_with_data"] += 1

            results["total_providers_checked"] = len(tasks)

        # Calculate aggregate risk
        results["aggregate_risk_level"], results["aggregate_score"] = (
            self._calculate_aggregate_risk(results["providers"])
        )

        return results

    async def _lookup_abuseipdb(self, ip: str) -> dict:
        """Lookup IP in AbuseIPDB."""
        return await abuseipdb_connector.check_ip(ip)

    async def _lookup_otx(self, indicator: str, indicator_type: str) -> dict:
        """Lookup indicator in OTX."""
        return await otx_connector.get_indicator(indicator, indicator_type)

    async def _lookup_abusech(self, indicator: str, indicator_type: str) -> dict:
        """Lookup indicator in Abuse.ch services."""
        if indicator_type.startswith("file_hash"):
            return await abusech_connector.check_hash(indicator)
        elif indicator_type == "url":
            return await abusech_connector.check_url(indicator)
        elif indicator_type == "ip_address":
            return await abusech_connector.check_ip_feodo(indicator)
        else:
            raise ValueError(f"Unsupported indicator type for Abuse.ch: {indicator_type}")

    def _calculate_aggregate_risk(self, providers: dict) -> tuple[str, int]:
        """
        Calculate aggregate risk level from all provider results.

        Returns:
            Tuple of (risk_level, score)
        """
        risk_scores = []

        for provider_name, provider_data in providers.items():
            if not provider_data.get("available"):
                continue

            data = provider_data.get("data", {})
            risk_level = data.get("risk_level", "unknown")

            # Convert risk level to numeric score
            score = self._risk_level_to_score(risk_level)
            if score is not None:
                risk_scores.append(score)

            # Check for specific indicators
            if provider_name == "abuseipdb":
                confidence = data.get("abuse_confidence_score", 0)
                if confidence > 0:
                    risk_scores.append(confidence)

            elif provider_name == "otx":
                pulse_count = data.get("pulse_count", 0)
                if pulse_count > 0:
                    # Scale pulse count to 0-100
                    pulse_score = min(pulse_count * 10, 100)
                    risk_scores.append(pulse_score)

            elif provider_name == "abusech":
                if data.get("found"):
                    risk_scores.append(90)  # If found in abuse.ch, high risk

        if not risk_scores:
            return "unknown", 0

        # Calculate average score
        avg_score = sum(risk_scores) / len(risk_scores)

        # Determine risk level from score
        if avg_score >= 80:
            risk_level = "critical"
        elif avg_score >= 60:
            risk_level = "high"
        elif avg_score >= 40:
            risk_level = "medium"
        elif avg_score >= 20:
            risk_level = "low"
        else:
            risk_level = "clean"

        return risk_level, int(avg_score)

    def _risk_level_to_score(self, risk_level: str) -> int | None:
        """Convert risk level string to numeric score."""
        mapping = {
            "critical": 95,
            "high": 75,
            "medium": 50,
            "low": 25,
            "clean": 5,
            "unknown": None,
        }
        return mapping.get(risk_level.lower())

    async def get_sources_status(self) -> dict:
        """Get status of all threat intel sources."""
        return {
            "abuseipdb": {
                "configured": abuseipdb_connector.is_configured,
                "supported_types": self.PROVIDER_SUPPORT["abuseipdb"],
                "description": "IP reputation and abuse reports",
            },
            "otx": {
                "configured": otx_connector.is_configured,
                "supported_types": self.PROVIDER_SUPPORT["otx"],
                "description": "AlienVault Open Threat Exchange",
            },
            "abusech": {
                "configured": True,  # No API key required
                "supported_types": self.PROVIDER_SUPPORT["abusech"],
                "description": "MalwareBazaar, URLhaus, Feodo Tracker",
            },
        }


# Singleton instance
threat_intel_service = ThreatIntelService()
