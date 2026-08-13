import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep, PantherServiceDep

logger = logging.getLogger(__name__)

router = APIRouter()


class IOCSearchRequest(BaseModel):
    indicator: str
    indicator_type: str | None = (
        None  # ip, domain, hash, email, username - auto-detect if not provided
    )
    time_range_days: int = 7


class IOCSearchResult(BaseModel):
    indicator: str
    indicator_type: str
    total_matches: int
    sources: list[dict[str, Any]]
    first_seen: str | None = None
    last_seen: str | None = None


def detect_indicator_type(indicator: str) -> str:
    """Auto-detect the type of indicator."""
    import re

    # IP address (v4)
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", indicator):
        return "ip"

    # IP address (v6)
    if re.match(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", indicator):
        return "ip"

    # MD5 hash
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "hash_md5"

    # SHA1 hash
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "hash_sha1"

    # SHA256 hash
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "hash_sha256"

    # Email
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", indicator):
        return "email"

    # Domain (simple check)
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}", indicator) and "/" not in indicator:
        return "domain"

    # URL
    if indicator.startswith(("http://", "https://")):
        return "url"

    # Default to username
    return "username"


# Indicators are interpolated into Snowflake SQL sent to Panther (there is no
# bind-parameter channel through that API), so the value must be constrained
# rather than trusted. Real IOCs -- IPs, domains, hashes, emails, usernames,
# URLs -- never need quotes, semicolons, backslashes or comment markers, which
# is exactly what a break-out payload requires.
_SAFE_INDICATOR = re.compile(r"^[A-Za-z0-9._:@/%?=&+~\[\]-]{1,255}$")


class UnsafeIndicatorError(ValueError):
    """Raised when an indicator cannot be safely embedded in a query."""


def _validate_indicator(indicator: str) -> str:
    value = (indicator or "").strip()
    if not _SAFE_INDICATOR.match(value):
        raise UnsafeIndicatorError(
            "Indicator contains unsupported characters. Provide a plain IP, "
            "domain, hash, email, username, or URL."
        )
    return value


def build_search_query(indicator: str, indicator_type: str, days: int) -> str:
    """Build SQL query based on indicator type.

    ``indicator`` is validated against a strict character allowlist and
    ``days`` is coerced to a bounded int before either is interpolated.
    """
    indicator = _validate_indicator(indicator)
    days = max(1, min(int(days), 365))
    base_query = f"""
SELECT
    p_log_type as source,
    p_event_time,
    p_source_label,
    p_any_ip_addresses,
    p_any_domain_names,
    p_any_sha256_hashes,
    p_any_usernames,
    p_any_emails
FROM panther_logs.public.all_logs
WHERE p_event_time > current_timestamp - interval '{days}' day
"""

    if indicator_type == "ip":
        return (
            base_query
            + f"  AND ARRAY_CONTAINS('{indicator}'::variant, p_any_ip_addresses)\nLIMIT 500"
        )
    elif indicator_type == "domain":
        return (
            base_query
            + f"  AND ARRAY_CONTAINS('{indicator}'::variant, p_any_domain_names)\nLIMIT 500"
        )
    elif indicator_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        return (
            base_query + f"  AND (ARRAY_CONTAINS('{indicator}'::variant, p_any_md5_hashes)"
            f" OR ARRAY_CONTAINS('{indicator}'::variant, p_any_sha1_hashes)"
            f" OR ARRAY_CONTAINS('{indicator}'::variant, p_any_sha256_hashes))"
            "\nLIMIT 500"
        )
    elif indicator_type == "email":
        return base_query + f"  AND ARRAY_CONTAINS('{indicator}'::variant, p_any_emails)\nLIMIT 500"
    elif indicator_type == "username":
        return (
            base_query + f"  AND ARRAY_CONTAINS('{indicator}'::variant, p_any_usernames)\nLIMIT 500"
        )
    elif indicator_type == "url":
        return base_query + f"  AND ARRAY_CONTAINS('{indicator}'::variant, p_any_urls)\nLIMIT 500"
    else:
        # Generic search across all fields
        return (
            base_query
            + f"""  AND (
    ARRAY_CONTAINS('{indicator}'::variant, p_any_ip_addresses)
    OR ARRAY_CONTAINS('{indicator}'::variant, p_any_domain_names)
    OR ARRAY_CONTAINS('{indicator}'::variant, p_any_usernames)
    OR ARRAY_CONTAINS('{indicator}'::variant, p_any_emails)
  )
LIMIT 500"""
        )


@router.post("/search")
async def search_ioc(
    request: IOCSearchRequest,
    panther: PantherServiceDep,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
) -> IOCSearchResult:
    """Search for an IOC across all log sources."""
    indicator_type = request.indicator_type or detect_indicator_type(request.indicator)

    # A rejected indicator is a client error, not a 500 -- and must not fall
    # into the generic handler below, which would mask it as a search failure.
    try:
        request.indicator = _validate_indicator(request.indicator)
    except UnsafeIndicatorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        sql = build_search_query(request.indicator, indicator_type, request.time_range_days)
        result = await panther.execute_query(sql)

        results = result.get("results", [])

        # Aggregate by source
        sources_map: dict[str, dict] = {}
        first_seen = None
        last_seen = None

        for row in results:
            source = row.get("source", "unknown")
            event_time = row.get("p_event_time")

            if source not in sources_map:
                sources_map[source] = {
                    "source": source,
                    "count": 0,
                    "first_seen": event_time,
                    "last_seen": event_time,
                }

            sources_map[source]["count"] += 1

            if event_time:
                if (
                    not sources_map[source]["first_seen"]
                    or event_time < sources_map[source]["first_seen"]
                ):
                    sources_map[source]["first_seen"] = event_time
                if (
                    not sources_map[source]["last_seen"]
                    or event_time > sources_map[source]["last_seen"]
                ):
                    sources_map[source]["last_seen"] = event_time

                if not first_seen or event_time < first_seen:
                    first_seen = event_time
                if not last_seen or event_time > last_seen:
                    last_seen = event_time

        return IOCSearchResult(
            indicator=request.indicator,
            indicator_type=indicator_type,
            total_matches=len(results),
            sources=list(sources_map.values()),
            first_seen=first_seen,
            last_seen=last_seen,
        )
    except Exception:
        logger.exception("IOC search failed")
        raise HTTPException(status_code=500, detail="IOC search failed")


@router.get("/types")
async def get_indicator_types(
    user: OrgUserDep,
    org_id: OrgIdDep,
) -> list[dict[str, str]]:
    """Get list of supported indicator types."""
    return [
        {"value": "ip", "label": "IP Address"},
        {"value": "domain", "label": "Domain"},
        {"value": "hash_md5", "label": "MD5 Hash"},
        {"value": "hash_sha1", "label": "SHA1 Hash"},
        {"value": "hash_sha256", "label": "SHA256 Hash"},
        {"value": "email", "label": "Email"},
        {"value": "username", "label": "Username"},
        {"value": "url", "label": "URL"},
    ]
