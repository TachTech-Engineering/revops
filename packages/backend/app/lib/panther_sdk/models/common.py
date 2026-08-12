"""Common models and enums used across the SDK."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Alert/Rule severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(StrEnum):
    """Alert status values."""

    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    CLOSED = "CLOSED"
    RESOLVED = "RESOLVED"


class LogType(StrEnum):
    """Common log types supported by Panther."""

    # AWS
    AWS_CLOUDTRAIL = "AWS.CloudTrail"
    AWS_S3_SERVER_ACCESS = "AWS.S3ServerAccess"
    AWS_VPC_FLOW = "AWS.VPCFlow"
    AWS_GUARDDUTY = "AWS.GuardDuty"
    AWS_ALB = "AWS.ALB"

    # Identity Providers
    OKTA_SYSTEM_LOG = "Okta.SystemLog"
    ONELOGIN_EVENTS = "OneLogin.Events"
    GSUITE_REPORTS = "GSuite.Reports"

    # SaaS
    GITHUB_AUDIT = "GitHub.Audit"
    SLACK_AUDIT_LOGS = "Slack.AuditLogs"
    ZOOM_ACTIVITY = "Zoom.Activity"
    BOX_EVENT = "Box.Event"

    # Security Tools
    CROWDSTRIKE_FDR = "CrowdStrike.FDREvent"
    CARBON_BLACK = "CarbonBlack.Audit"
    SENTINEL_ONE = "SentinelOne.Activity"

    # Network
    ZEEK_DNS = "Zeek.DNS"
    SURICATA_ALERT = "Suricata.Alert"

    # Custom
    CUSTOM_LOGS = "Custom.Logs"


class DetectionType(StrEnum):
    """Detection type values."""

    RULE = "RULE"
    POLICY = "POLICY"
    SCHEDULED_RULE = "SCHEDULED_RULE"
    SCHEDULED_QUERY = "SCHEDULED_QUERY"


class BaseModelConfig(BaseModel):
    """Base model with common configuration."""

    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        extra="allow",
    )


class Pagination(BaseModelConfig):
    """Pagination information for list responses."""

    cursor: str | None = None
    has_more: bool = Field(default=False, alias="hasMore")
    total_count: int | None = Field(default=None, alias="totalCount")


class ListResponse(BaseModelConfig):
    """Generic list response with pagination."""

    results: list[dict[str, Any]] = Field(default_factory=list)
    cursor: str | None = None


class Timestamps(BaseModelConfig):
    """Common timestamp fields."""

    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    updated_by: str | None = Field(default=None, alias="updatedBy")
