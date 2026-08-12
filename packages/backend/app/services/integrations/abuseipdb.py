"""
AbuseIPDB integration for IP reputation lookups.
Free tier: 1000 checks/day
"""

import httpx

from app.config import settings


class AbuseIPDBConnector:
    """Connector for AbuseIPDB threat intelligence API."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or settings.abuseipdb_api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """
        Check an IP address against AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports to consider (1-365)

        Returns:
            Dictionary with abuse data including:
            - abuseConfidenceScore: 0-100 score
            - countryCode: Country of origin
            - usageType: ISP, hosting, etc.
            - isp: Internet service provider
            - domain: Associated domain
            - totalReports: Number of abuse reports
            - lastReportedAt: Last report timestamp
        """
        if not self.is_configured:
            raise ValueError("AbuseIPDB API key not configured")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                },
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )

            if response.status_code == 401:
                raise ValueError("Invalid AbuseIPDB API key")
            elif response.status_code == 422:
                raise ValueError(f"Invalid IP address: {ip}")
            elif response.status_code == 429:
                raise ValueError("AbuseIPDB rate limit exceeded")

            response.raise_for_status()
            data = response.json()

            return self._format_response(data.get("data", {}))

    async def get_reports(self, ip: str, max_age_days: int = 90, page: int = 1) -> list[dict]:
        """
        Get detailed reports for an IP address.

        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports
            page: Page number for pagination

        Returns:
            List of report dictionaries
        """
        if not self.is_configured:
            raise ValueError("AbuseIPDB API key not configured")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/reports",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "page": page,
                    "perPage": 25,
                },
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )

            response.raise_for_status()
            data = response.json()

            return data.get("data", {}).get("results", [])

    def _format_response(self, data: dict) -> dict:
        """Format the AbuseIPDB response for consistent output."""
        # Map category IDs to names
        categories = data.get("reports", [])
        category_names = []
        for report in categories[:10]:  # Only process first 10 reports
            for cat in report.get("categories", []):
                cat_name = self._get_category_name(cat)
                if cat_name and cat_name not in category_names:
                    category_names.append(cat_name)

        return {
            "ip_address": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames", []),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted"),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "categories": category_names[:5],  # Top 5 categories
            "risk_level": self._calculate_risk_level(data.get("abuseConfidenceScore", 0)),
        }

    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from abuse confidence score."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "clean"

    def _get_category_name(self, category_id: int) -> str | None:
        """Map AbuseIPDB category ID to name."""
        categories = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted",
        }
        return categories.get(category_id)


# Singleton instance
abuseipdb_connector = AbuseIPDBConnector()
