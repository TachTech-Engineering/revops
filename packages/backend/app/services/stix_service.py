"""
STIX 2.1 Service for parsing and creating STIX bundles.
"""

import re
import uuid
from datetime import datetime

from app.db.models import IOCSeverity, IOCType

# STIX 2.1 pattern mappings
IOC_TYPE_TO_STIX_PATTERN = {
    IOCType.IP_ADDRESS: "[ipv4-addr:value = '{value}']",
    IOCType.DOMAIN: "[domain-name:value = '{value}']",
    IOCType.URL: "[url:value = '{value}']",
    IOCType.FILE_HASH_MD5: "[file:hashes.'MD5' = '{value}']",
    IOCType.FILE_HASH_SHA1: "[file:hashes.'SHA-1' = '{value}']",
    IOCType.FILE_HASH_SHA256: "[file:hashes.'SHA-256' = '{value}']",
    IOCType.EMAIL: "[email-addr:value = '{value}']",
}

# Reverse mapping for parsing STIX patterns
STIX_PATTERN_TO_IOC_TYPE = {
    "ipv4-addr:value": IOCType.IP_ADDRESS,
    "ipv6-addr:value": IOCType.IP_ADDRESS,
    "domain-name:value": IOCType.DOMAIN,
    "url:value": IOCType.URL,
    "file:hashes.'MD5'": IOCType.FILE_HASH_MD5,
    "file:hashes.MD5": IOCType.FILE_HASH_MD5,
    "file:hashes.'SHA-1'": IOCType.FILE_HASH_SHA1,
    "file:hashes.SHA-1": IOCType.FILE_HASH_SHA1,
    "file:hashes.'SHA-256'": IOCType.FILE_HASH_SHA256,
    "file:hashes.SHA-256": IOCType.FILE_HASH_SHA256,
    "email-addr:value": IOCType.EMAIL,
}


class STIXService:
    """Service for STIX 2.1 bundle parsing and creation."""

    def parse_bundle(self, json_data: dict) -> list[dict]:
        """
        Parse a STIX 2.1 bundle and extract IOCs.

        Args:
            json_data: STIX bundle JSON

        Returns:
            List of IOC dictionaries ready for database insertion
        """
        iocs = []

        if json_data.get("type") != "bundle":
            raise ValueError("Invalid STIX bundle: missing type 'bundle'")

        objects = json_data.get("objects", [])

        for obj in objects:
            if obj.get("type") == "indicator":
                ioc = self.parse_indicator(obj)
                if ioc:
                    iocs.append(ioc)

        return iocs

    def parse_indicator(self, indicator: dict) -> dict | None:
        """
        Parse a single STIX indicator object into an IOC.

        Args:
            indicator: STIX indicator object

        Returns:
            IOC dictionary or None if parsing fails
        """
        pattern = indicator.get("pattern", "")

        # Extract IOC type and value from pattern
        ioc_type, value = self._parse_pattern(pattern)
        if not ioc_type or not value:
            return None

        # Map STIX confidence to severity
        confidence = indicator.get("confidence", 50)
        severity = self._confidence_to_severity(confidence)

        # Parse timestamps
        valid_from = indicator.get("valid_from")
        valid_until = indicator.get("valid_until")
        created = indicator.get("created")

        first_seen = self._parse_timestamp(valid_from or created)
        expires_at = self._parse_timestamp(valid_until) if valid_until else None

        # Extract labels as tags
        tags = indicator.get("labels", [])

        return {
            "ioc_type": ioc_type,
            "value": value,
            "severity": severity,
            "description": indicator.get("description") or indicator.get("name"),
            "tags": tags,
            "first_seen": first_seen or datetime.utcnow(),
            "expires_at": expires_at,
            "stix_id": indicator.get("id"),
        }

    def _parse_pattern(self, pattern: str) -> tuple[IOCType | None, str | None]:
        """Extract IOC type and value from a STIX pattern."""
        # Simple pattern: [type:property = 'value']
        match = re.search(r"\[([^\]]+)\]", pattern)
        if not match:
            return None, None

        inner = match.group(1)

        # Try to match known patterns
        for pattern_prefix, ioc_type in STIX_PATTERN_TO_IOC_TYPE.items():
            if pattern_prefix in inner:
                # Extract the value
                value_match = re.search(r"=\s*['\"]([^'\"]+)['\"]", inner)
                if value_match:
                    return ioc_type, value_match.group(1)

        return None, None

    def _confidence_to_severity(self, confidence: int) -> IOCSeverity:
        """Map STIX confidence (0-100) to IOC severity."""
        if confidence >= 90:
            return IOCSeverity.CRITICAL
        elif confidence >= 70:
            return IOCSeverity.HIGH
        elif confidence >= 50:
            return IOCSeverity.MEDIUM
        elif confidence >= 30:
            return IOCSeverity.LOW
        return IOCSeverity.INFO

    def _severity_to_confidence(self, severity: IOCSeverity) -> int:
        """Map IOC severity to STIX confidence (0-100)."""
        mapping = {
            IOCSeverity.CRITICAL: 95,
            IOCSeverity.HIGH: 80,
            IOCSeverity.MEDIUM: 60,
            IOCSeverity.LOW: 40,
            IOCSeverity.INFO: 20,
        }
        return mapping.get(severity, 50)

    def _parse_timestamp(self, ts_str: str | None) -> datetime | None:
        """Parse a STIX timestamp string."""
        if not ts_str:
            return None
        try:
            # Handle ISO format with Z or +00:00
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            return datetime.fromisoformat(ts_str).replace(tzinfo=None)
        except ValueError:
            return None

    def create_bundle(self, iocs: list[dict]) -> dict:
        """
        Create a STIX 2.1 bundle from IOCs.

        Args:
            iocs: List of IOC dictionaries (from database)

        Returns:
            STIX 2.1 bundle dictionary
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []

        for ioc in iocs:
            indicator = self.create_indicator(ioc)
            if indicator:
                objects.append(indicator)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    def create_indicator(self, ioc: dict) -> dict | None:
        """
        Create a STIX indicator object from an IOC.

        Args:
            ioc: IOC dictionary from database

        Returns:
            STIX indicator object or None
        """
        ioc_type = ioc.get("ioc_type")
        value = ioc.get("value")

        if isinstance(ioc_type, str):
            ioc_type = IOCType(ioc_type)

        pattern_template = IOC_TYPE_TO_STIX_PATTERN.get(ioc_type)
        if not pattern_template:
            return None

        pattern = pattern_template.format(value=value)

        # Generate STIX ID
        indicator_id = f"indicator--{ioc.get('id', uuid.uuid4())}"

        # Get timestamps
        created = ioc.get("created_at") or datetime.utcnow()
        first_seen = ioc.get("first_seen") or created

        if isinstance(created, datetime):
            created_str = created.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        else:
            created_str = str(created)

        if isinstance(first_seen, datetime):
            valid_from = first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        else:
            valid_from = str(first_seen)

        # Map severity to confidence
        severity = ioc.get("severity", IOCSeverity.MEDIUM)
        if isinstance(severity, str):
            severity = IOCSeverity(severity)
        confidence = self._severity_to_confidence(severity)

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": created_str,
            "modified": created_str,
            "name": f"{ioc_type.value}: {value}",
            "description": ioc.get("description")
            or f"IOC imported from {ioc.get('source', 'unknown')}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": valid_from,
            "confidence": confidence,
            "labels": ioc.get("tags", []),
        }

        # Add valid_until if expires_at is set
        expires_at = ioc.get("expires_at")
        if expires_at:
            if isinstance(expires_at, datetime):
                indicator["valid_until"] = expires_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            else:
                indicator["valid_until"] = str(expires_at)

        return indicator


# Singleton instance
stix_service = STIXService()
