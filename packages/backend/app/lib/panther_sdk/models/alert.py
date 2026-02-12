"""Alert-related models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import AlertStatus, BaseModelConfig, Severity


class AlertEvent(BaseModelConfig):
    """An event associated with an alert."""

    event_id: str | None = Field(default=None, alias="eventId")
    log_type: str | None = Field(default=None, alias="logType")
    event_time: datetime | None = Field(default=None, alias="eventTime")
    data: dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"  # Allow extra fields from Panther


class AlertComment(BaseModelConfig):
    """A comment on an alert."""

    id: str
    body: str
    author: str
    created_at: datetime = Field(alias="createdAt")


class AlertDelivery(BaseModelConfig):
    """Alert delivery information."""

    output_id: str = Field(alias="outputId")
    output_type: str = Field(alias="outputType")
    dispatched_at: datetime | None = Field(default=None, alias="dispatchedAt")
    success: bool = True
    error_message: str | None = Field(default=None, alias="errorMessage")


class Alert(BaseModelConfig):
    """Represents a Panther alert."""

    id: str
    title: str | None = None
    description: str | None = None
    severity: Severity | str | None = None
    status: AlertStatus | str | None = None
    detection_id: str | None = Field(default=None, alias="detectionId")
    detection_type: str | None = Field(default=None, alias="detectionType")
    type: str | None = None  # RULE, POLICY, etc.
    log_types: list[str] = Field(default_factory=list, alias="logTypes")

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    first_event_at: datetime | None = Field(default=None, alias="firstEventAt")
    last_event_at: datetime | None = Field(default=None, alias="lastEventAt")

    # Assignment
    assignee_id: str | None = Field(default=None, alias="assigneeId")
    assignee_name: str | None = Field(default=None, alias="assigneeName")

    # Counts
    event_count: int = Field(default=0, alias="eventCount")

    # Related data
    runbook: str | None = None
    reference: str | None = None
    tags: list[str] = Field(default_factory=list)
    context: dict | None = None  # Panther includes context data

    # Destinations
    delivery_responses: list[AlertDelivery] = Field(
        default_factory=list, alias="deliveryResponses"
    )

    class Config:
        extra = "allow"  # Allow extra fields


class AlertSummary(BaseModelConfig):
    """Summary view of an alert for list operations."""

    id: str
    title: str | None = None
    severity: Severity | str | None = None
    status: AlertStatus | str | None = None
    detection_id: str | None = Field(default=None, alias="detectionId")
    detection: dict | None = None  # Panther might nest detection info here
    created_at: datetime | None = Field(default=None, alias="createdAt")
    event_count: int = Field(default=0, alias="eventCount")
    type: str | None = None  # RULE, POLICY, etc.

    class Config:
        extra = "allow"  # Allow extra fields we don't know about


class AlertUpdate(BaseModelConfig):
    """Model for updating an alert."""

    status: AlertStatus | None = None
    assignee_id: str | None = Field(default=None, alias="assigneeId")


class AlertListParams(BaseModelConfig):
    """Parameters for listing alerts."""

    status: AlertStatus | str | None = None
    severity: Severity | str | None = None
    detection_id: str | None = Field(default=None, alias="detectionId")
    assignee_id: str | None = Field(default=None, alias="assigneeId")
    log_types: list[str] | None = Field(default=None, alias="logTypes")
    created_after: datetime | None = Field(default=None, alias="createdAfter")
    created_before: datetime | None = Field(default=None, alias="createdBefore")
    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None
