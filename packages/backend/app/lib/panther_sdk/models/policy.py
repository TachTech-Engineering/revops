"""Policy-related models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import BaseModelConfig, Severity


class PolicyTest(BaseModelConfig):
    """A unit test for a policy."""

    name: str
    expected_result: bool = Field(alias="expectedResult")
    resource: dict[str, Any]
    mocks: dict[str, Any] | None = None


class Policy(BaseModelConfig):
    """Represents a Panther policy."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool = True
    severity: Severity

    # Logic
    body: str | None = None
    resource_types: list[str] = Field(default_factory=list, alias="resourceTypes")

    # Auto-remediation
    auto_remediation_id: str | None = Field(default=None, alias="autoRemediationId")
    auto_remediation_parameters: dict[str, Any] | None = Field(
        default=None, alias="autoRemediationParameters"
    )

    # Suppressions
    suppressions: list[str] = Field(default_factory=list)

    # Metadata
    tags: list[str] = Field(default_factory=list)
    runbook: str | None = None
    reference: str | None = None
    reports: dict[str, list[str]] = Field(default_factory=dict)

    # Testing
    tests: list[PolicyTest] = Field(default_factory=list)

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    updated_by: str | None = Field(default=None, alias="updatedBy")


class PolicySummary(BaseModelConfig):
    """Summary view of a policy for list operations."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    enabled: bool = True
    severity: Severity
    resource_types: list[str] = Field(default_factory=list, alias="resourceTypes")
    tags: list[str] = Field(default_factory=list)
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class PolicyCreate(BaseModelConfig):
    """Model for creating a policy."""

    id: str
    body: str
    severity: Severity
    resource_types: list[str] = Field(alias="resourceTypes")
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool = True
    auto_remediation_id: str | None = Field(default=None, alias="autoRemediationId")
    auto_remediation_parameters: dict[str, Any] | None = Field(
        default=None, alias="autoRemediationParameters"
    )
    suppressions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    runbook: str | None = None
    reference: str | None = None
    tests: list[PolicyTest] = Field(default_factory=list)
    reports: dict[str, list[str]] = Field(default_factory=dict)


class PolicyUpdate(BaseModelConfig):
    """Model for updating a policy."""

    body: str | None = None
    severity: Severity | None = None
    resource_types: list[str] | None = Field(default=None, alias="resourceTypes")
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool | None = None
    auto_remediation_id: str | None = Field(default=None, alias="autoRemediationId")
    auto_remediation_parameters: dict[str, Any] | None = Field(
        default=None, alias="autoRemediationParameters"
    )
    suppressions: list[str] | None = None
    tags: list[str] | None = None
    runbook: str | None = None
    reference: str | None = None
    tests: list[PolicyTest] | None = None
    reports: dict[str, list[str]] | None = None


class PolicyListParams(BaseModelConfig):
    """Parameters for listing policies."""

    enabled: bool | None = None
    severity: Severity | str | None = None
    resource_types: list[str] | None = Field(default=None, alias="resourceTypes")
    tags: list[str] | None = None
    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None
