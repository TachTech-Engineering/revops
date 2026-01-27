"""
Abuse.ch integration for malware and URL threat intelligence.
Free tier - no API key required for basic lookups.

Supports:
- MalwareBazaar (file hashes)
- URLhaus (malicious URLs)
- Feodo Tracker (botnet C2)
"""
import hashlib
import httpx
from typing import Optional


class AbuseCHConnector:
    """Connector for Abuse.ch threat intelligence APIs."""

    MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1"
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1"
    FEODO_URL = "https://feodotracker.abuse.ch/downloads"

    async def check_hash(self, file_hash: str) -> dict:
        """
        Check a file hash against MalwareBazaar.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dictionary with malware data
        """
        # Determine hash type
        hash_length = len(file_hash)
        if hash_length == 32:
            hash_type = "md5"
        elif hash_length == 40:
            hash_type = "sha1"
        elif hash_length == 64:
            hash_type = "sha256"
        else:
            raise ValueError(f"Invalid hash length: {hash_length}")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.MALWARE_BAZAAR_URL}/",
                data={
                    "query": "get_info",
                    f"hash": file_hash,
                },
                headers={"Accept": "application/json"},
                timeout=30.0,
            )

            response.raise_for_status()
            data = response.json()

            return self._format_hash_response(data, file_hash, hash_type)

    async def check_url(self, url: str) -> dict:
        """
        Check a URL against URLhaus.

        Args:
            url: URL to check

        Returns:
            Dictionary with URL threat data
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.URLHAUS_URL}/url/",
                data={"url": url},
                headers={"Accept": "application/json"},
                timeout=30.0,
            )

            response.raise_for_status()
            data = response.json()

            return self._format_url_response(data, url)

    async def check_ip_feodo(self, ip: str) -> dict:
        """
        Check an IP against Feodo Tracker (botnet C2 IPs).

        Args:
            ip: IP address to check

        Returns:
            Dictionary with botnet C2 data
        """
        # Feodo provides a JSON feed we can check against
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
                timeout=30.0,
            )

            if response.status_code != 200:
                return {
                    "ip": ip,
                    "found": False,
                    "risk_level": "unknown",
                    "error": "Failed to fetch Feodo blocklist",
                }

            data = response.json()

            # Search for the IP in the blocklist
            for entry in data:
                if entry.get("ip_address") == ip:
                    return self._format_feodo_response(entry, ip)

            return {
                "ip": ip,
                "found": False,
                "risk_level": "clean",
                "message": "IP not found in Feodo Tracker blocklist",
            }

    async def search_tag(self, tag: str) -> list[dict]:
        """
        Search MalwareBazaar by tag (e.g., malware family).

        Args:
            tag: Tag to search for

        Returns:
            List of matching samples
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.MALWARE_BAZAAR_URL}/",
                data={
                    "query": "get_taginfo",
                    "tag": tag,
                    "limit": 50,
                },
                headers={"Accept": "application/json"},
                timeout=30.0,
            )

            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "ok":
                return []

            samples = data.get("data", [])
            return [
                {
                    "sha256": s.get("sha256_hash"),
                    "sha1": s.get("sha1_hash"),
                    "md5": s.get("md5_hash"),
                    "file_type": s.get("file_type"),
                    "file_name": s.get("file_name"),
                    "signature": s.get("signature"),
                    "first_seen": s.get("first_seen"),
                    "tags": s.get("tags", []),
                }
                for s in samples[:20]
            ]

    def _format_hash_response(self, data: dict, file_hash: str, hash_type: str) -> dict:
        """Format MalwareBazaar response."""
        if data.get("query_status") == "hash_not_found":
            return {
                "hash": file_hash,
                "hash_type": hash_type,
                "found": False,
                "risk_level": "clean",
                "message": "Hash not found in MalwareBazaar",
            }

        if data.get("query_status") != "ok":
            return {
                "hash": file_hash,
                "hash_type": hash_type,
                "found": False,
                "risk_level": "unknown",
                "error": data.get("query_status"),
            }

        sample = data.get("data", [{}])[0]

        return {
            "hash": file_hash,
            "hash_type": hash_type,
            "found": True,
            "risk_level": "critical",  # If in MalwareBazaar, it's malware
            "sha256": sample.get("sha256_hash"),
            "sha1": sample.get("sha1_hash"),
            "md5": sample.get("md5_hash"),
            "file_type": sample.get("file_type"),
            "file_type_mime": sample.get("file_type_mime"),
            "file_size": sample.get("file_size"),
            "file_name": sample.get("file_name"),
            "signature": sample.get("signature"),  # Malware family
            "first_seen": sample.get("first_seen"),
            "last_seen": sample.get("last_seen"),
            "tags": sample.get("tags", []),
            "intelligence": {
                "downloads": sample.get("intelligence", {}).get("downloads"),
                "uploads": sample.get("intelligence", {}).get("uploads"),
                "mail_intelligence": sample.get("intelligence", {}).get("mail"),
            },
            "vendor_intel": self._format_vendor_intel(sample.get("vendor_intel", {})),
            "delivery_method": sample.get("delivery_method"),
            "origin_country": sample.get("origin_country"),
        }

    def _format_vendor_intel(self, vendor_intel: dict) -> dict:
        """Format vendor intelligence from MalwareBazaar."""
        formatted = {}
        for vendor, intel in vendor_intel.items():
            if intel:
                formatted[vendor] = {
                    "verdict": intel.get("verdict"),
                    "malware_family": intel.get("malware_family"),
                    "detection": intel.get("detection"),
                }
        return formatted

    def _format_url_response(self, data: dict, url: str) -> dict:
        """Format URLhaus response."""
        if data.get("query_status") == "no_results":
            return {
                "url": url,
                "found": False,
                "risk_level": "clean",
                "message": "URL not found in URLhaus",
            }

        if data.get("query_status") != "ok":
            return {
                "url": url,
                "found": False,
                "risk_level": "unknown",
                "error": data.get("query_status"),
            }

        return {
            "url": url,
            "found": True,
            "risk_level": "critical" if data.get("url_status") == "online" else "high",
            "id": data.get("id"),
            "url_status": data.get("url_status"),  # online, offline
            "host": data.get("host"),
            "date_added": data.get("date_added"),
            "last_online": data.get("last_online"),
            "threat": data.get("threat"),  # malware_download, etc.
            "blacklists": data.get("blacklists", {}),
            "reporter": data.get("reporter"),
            "larted": data.get("larted"),  # Reported to hosting provider
            "takedown_time_seconds": data.get("takedown_time_seconds"),
            "tags": data.get("tags", []),
            "payloads": [
                {
                    "sha256": p.get("sha256_hash"),
                    "file_type": p.get("file_type"),
                    "file_size": p.get("file_size"),
                    "signature": p.get("signature"),
                    "first_seen": p.get("firstseen"),
                }
                for p in data.get("payloads", [])[:5]
            ],
        }

    def _format_feodo_response(self, entry: dict, ip: str) -> dict:
        """Format Feodo Tracker response."""
        return {
            "ip": ip,
            "found": True,
            "risk_level": "critical",  # Botnet C2 is critical
            "port": entry.get("port"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_online"),
            "malware": entry.get("malware"),  # e.g., Dridex, Emotet, TrickBot
            "status": entry.get("status"),  # online, offline
            "as_number": entry.get("as_number"),
            "as_name": entry.get("as_name"),
            "country": entry.get("country"),
        }


# Singleton instance
abusech_connector = AbuseCHConnector()
