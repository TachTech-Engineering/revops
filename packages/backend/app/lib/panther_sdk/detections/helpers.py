"""Common helper functions for detection rules."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


def deep_get(obj: dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Safely get a nested value from a dictionary using dot notation.

    Args:
        obj: The dictionary to search
        path: Dot-separated path (e.g., "user.email")
        default: Default value if path not found

    Returns:
        The value at the path or the default

    Example:
        event = {"user": {"email": "test@example.com"}}
        deep_get(event, "user.email")  # Returns "test@example.com"
        deep_get(event, "user.name", "unknown")  # Returns "unknown"
    """
    keys = path.split(".")
    result = obj

    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        elif isinstance(result, list) and key.isdigit():
            try:
                result = result[int(key)]
            except (IndexError, ValueError):
                return default
        else:
            return default

        if result is None:
            return default

    return result


def is_ip_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP address is within a given network.

    Args:
        ip: IP address to check
        network: CIDR network (e.g., "10.0.0.0/8")

    Returns:
        True if IP is in the network

    Example:
        is_ip_in_network("10.1.2.3", "10.0.0.0/8")  # Returns True
        is_ip_in_network("192.168.1.1", "10.0.0.0/8")  # Returns False
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private (RFC 1918).

    Args:
        ip: IP address to check

    Returns:
        True if IP is private
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """
    Check if an IP address is public (not private, loopback, etc.).

    Args:
        ip: IP address to check

    Returns:
        True if IP is public
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def pattern_match(value: str, pattern: str) -> bool:
    """
    Check if a value matches a pattern (supports * and ? wildcards).

    Args:
        value: String to check
        pattern: Pattern with wildcards (* matches any, ? matches single char)

    Returns:
        True if value matches pattern

    Example:
        pattern_match("admin@example.com", "*@example.com")  # Returns True
        pattern_match("test.txt", "*.txt")  # Returns True
    """
    regex_pattern = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
    return bool(re.match(f"^{regex_pattern}$", value, re.IGNORECASE))


def pattern_match_list(value: str, patterns: list[str]) -> bool:
    """
    Check if a value matches any pattern in a list.

    Args:
        value: String to check
        patterns: List of patterns to match against

    Returns:
        True if value matches any pattern
    """
    return any(pattern_match(value, pattern) for pattern in patterns)


def extract_domain(url_or_email: str) -> str | None:
    """
    Extract the domain from a URL or email address.

    Args:
        url_or_email: URL or email address

    Returns:
        Domain string or None if extraction fails

    Example:
        extract_domain("https://example.com/path")  # Returns "example.com"
        extract_domain("user@example.com")  # Returns "example.com"
    """
    if "@" in url_or_email:
        # Email address
        parts = url_or_email.split("@")
        if len(parts) == 2:
            return parts[1].lower()
        return None

    # URL
    try:
        if not url_or_email.startswith(("http://", "https://")):
            url_or_email = f"https://{url_or_email}"
        parsed = urlparse(url_or_email)
        return parsed.netloc.lower() if parsed.netloc else None
    except Exception:
        return None


def is_aws_account_id(value: str) -> bool:
    """
    Check if a value looks like an AWS account ID.

    Args:
        value: String to check

    Returns:
        True if it's a 12-digit number
    """
    return bool(re.match(r"^\d{12}$", str(value)))


def is_aws_arn(value: str) -> bool:
    """
    Check if a value is a valid AWS ARN.

    Args:
        value: String to check

    Returns:
        True if it matches ARN format
    """
    return bool(re.match(r"^arn:aws[a-z\-]*:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:.+$", str(value)))


def get_val(event: dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Alias for deep_get with simpler name.

    Args:
        event: Event dictionary
        key: Dot-separated key path
        default: Default value if not found

    Returns:
        Value at key or default
    """
    return deep_get(event, key, default)


def aws_cloudtrail_success(event: dict[str, Any]) -> bool:
    """
    Check if a CloudTrail event was successful.

    Args:
        event: CloudTrail event

    Returns:
        True if the API call was successful
    """
    error_code = event.get("errorCode")
    error_message = event.get("errorMessage")
    return error_code is None and error_message is None


def aws_guardduty_context(event: dict[str, Any]) -> dict[str, Any]:
    """
    Extract useful context from a GuardDuty finding.

    Args:
        event: GuardDuty finding event

    Returns:
        Dictionary with extracted context
    """
    return {
        "finding_type": event.get("type"),
        "severity": event.get("severity"),
        "region": event.get("region"),
        "account_id": event.get("accountId"),
        "resource_type": deep_get(event, "resource.resourceType"),
        "description": event.get("description"),
    }


def okta_event_outcome(event: dict[str, Any]) -> str | None:
    """
    Get the outcome of an Okta event.

    Args:
        event: Okta System Log event

    Returns:
        Outcome result (SUCCESS, FAILURE, etc.) or None
    """
    return deep_get(event, "outcome.result")


def okta_actor(event: dict[str, Any]) -> dict[str, Any]:
    """
    Extract actor information from an Okta event.

    Args:
        event: Okta System Log event

    Returns:
        Dictionary with actor information
    """
    actor = event.get("actor", {})
    return {
        "id": actor.get("id"),
        "type": actor.get("type"),
        "email": actor.get("alternateId"),
        "display_name": actor.get("displayName"),
    }


def box_event_type_match(event: dict[str, Any], event_types: list[str]) -> bool:
    """
    Check if a Box event matches any of the given event types.

    Args:
        event: Box event
        event_types: List of event types to match

    Returns:
        True if event type matches
    """
    return event.get("event_type") in event_types
