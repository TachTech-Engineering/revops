"""Rule-related models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import BaseModelConfig, DetectionType, LogType, Severity


class RuleTest(BaseModelConfig):
    """A unit test for a rule."""

    name: str
    expected_result: bool = Field(alias="expectedResult")
    log: dict[str, Any]
    mocks: dict[str, Any] | None = None


class RuleReport(BaseModelConfig):
    """Rule reporting configuration."""

    enabled: bool = True
    schedule: str | None = None


class Rule(BaseModelConfig):
    """Represents a Panther detection rule."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool = True
    severity: Severity
    detection_type: DetectionType = Field(default=DetectionType.RULE, alias="detectionType")

    # Logic
    body: str | None = None
    log_types: list[str] = Field(default_factory=list, alias="logTypes")

    # Deduplication
    dedup_period_minutes: int = Field(default=60, alias="dedupPeriodMinutes")
    threshold: int = 1

    # Metadata
    tags: list[str] = Field(default_factory=list)
    runbook: str | None = None
    reference: str | None = None
    reports: dict[str, list[str]] = Field(default_factory=dict)

    # Alert settings
    destination_override: list[str] | None = Field(default=None, alias="destinationOverride")
    summary_attributes: list[str] = Field(default_factory=list, alias="summaryAttributes")

    # Testing
    tests: list[RuleTest] = Field(default_factory=list)

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    updated_by: str | None = Field(default=None, alias="updatedBy")


class RuleSummary(BaseModelConfig):
    """Summary view of a rule for list operations."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    enabled: bool = True
    severity: Severity
    log_types: list[str] = Field(default_factory=list, alias="logTypes")
    tags: list[str] = Field(default_factory=list)
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class RuleCreate(BaseModelConfig):
    """Model for creating a rule."""

    id: str
    body: str
    severity: Severity
    log_types: list[str | LogType] = Field(alias="logTypes")
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool = True
    dedup_period_minutes: int = Field(default=60, alias="dedupPeriodMinutes")
    threshold: int = 1
    tags: list[str] = Field(default_factory=list)
    runbook: str | None = None
    reference: str | None = None
    tests: list[RuleTest] = Field(default_factory=list)
    reports: dict[str, list[str]] = Field(default_factory=dict)


class RuleUpdate(BaseModelConfig):
    """Model for updating a rule."""

    body: str | None = None
    severity: Severity | None = None
    log_types: list[str | LogType] | None = Field(default=None, alias="logTypes")
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool | None = None
    dedup_period_minutes: int | None = Field(default=None, alias="dedupPeriodMinutes")
    threshold: int | None = None
    tags: list[str] | None = None
    runbook: str | None = None
    reference: str | None = None
    tests: list[RuleTest] | None = None
    reports: dict[str, list[str]] | None = None


class RuleListParams(BaseModelConfig):
    """Parameters for listing rules."""

    enabled: bool | None = None
    severity: Severity | str | None = None
    log_types: list[str] | None = Field(default=None, alias="logTypes")
    tags: list[str] | None = None
    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None
