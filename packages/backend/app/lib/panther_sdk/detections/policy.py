"""Base Policy class for cloud security policies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from ..models.common import Severity


class Policy(ABC):
    """
    Base class for Panther cloud security policies.

    Policies evaluate the configuration of cloud resources to identify
    misconfigurations and compliance violations.

    Example:
        ```python
        from panther_sdk.detections import Policy, Severity

        class S3BucketEncryption(Policy):
            id = "AWS.S3.BucketEncryption"
            resource_types = ["AWS.S3.Bucket"]
            severity = Severity.HIGH

            def policy(self, resource):
                # Check if bucket has server-side encryption enabled
                encryption = resource.get("ServerSideEncryptionConfiguration")
                return encryption is not None

            def title(self, resource):
                return f"S3 bucket {resource.get('Name')} lacks encryption"
        ```
    """

    # Required class attributes
    id: ClassVar[str]
    resource_types: ClassVar[list[str]]
    severity: ClassVar[Severity | str]

    # Optional class attributes with defaults
    enabled: ClassVar[bool] = True
    display_name: ClassVar[str | None] = None
    description: ClassVar[str | None] = None
    tags: ClassVar[list[str]] = []
    runbook: ClassVar[str | None] = None
    reference: ClassVar[str | None] = None
    reports: ClassVar[dict[str, list[str]]] = {}
    suppressions: ClassVar[list[str]] = []
    auto_remediation_id: ClassVar[str | None] = None
    auto_remediation_parameters: ClassVar[dict[str, Any] | None] = None
    unit_tests: ClassVar[list[dict[str, Any]]] = []

    def __init__(self) -> None:
        """Initialize the policy and validate required attributes."""
        self._validate()

    def _validate(self) -> None:
        """Validate that required class attributes are defined."""
        if not hasattr(self, "id") or not self.id:
            raise ValueError(f"{self.__class__.__name__} must define 'id' class attribute")
        if not hasattr(self, "resource_types") or not self.resource_types:
            raise ValueError(
                f"{self.__class__.__name__} must define 'resource_types' class attribute"
            )
        if not hasattr(self, "severity"):
            raise ValueError(f"{self.__class__.__name__} must define 'severity' class attribute")

    @abstractmethod
    def policy(self, resource: dict[str, Any]) -> bool:
        """
        The main policy evaluation logic.

        Args:
            resource: The cloud resource configuration to evaluate

        Returns:
            True if the resource is compliant, False if it's a violation
        """
        pass

    def title(self, resource: dict[str, Any]) -> str:
        """
        Generate a dynamic title for the policy finding.

        Override this method to create context-aware titles.

        Args:
            resource: The resource that failed the policy

        Returns:
            Finding title string
        """
        return self.display_name or self.id

    def dedup(self, resource: dict[str, Any]) -> str:
        """
        Generate a deduplication key for the finding.

        Args:
            resource: The resource

        Returns:
            Deduplication key string
        """
        return resource.get("ResourceId", self.id)

    def alert_context(self, resource: dict[str, Any]) -> dict[str, Any]:
        """
        Add additional context to the finding.

        Override this to include relevant information.

        Args:
            resource: The resource

        Returns:
            Dictionary of additional context
        """
        return {}

    def severity_override(self, resource: dict[str, Any]) -> Severity | str | None:
        """
        Dynamically override the severity based on the resource.

        Args:
            resource: The resource

        Returns:
            New severity or None to use the default
        """
        return None

    def destinations(self, resource: dict[str, Any]) -> list[str] | None:
        """
        Override alert destinations based on the resource.

        Args:
            resource: The resource

        Returns:
            List of destination IDs or None to use defaults
        """
        return None

    def remediation(self, resource: dict[str, Any]) -> dict[str, Any] | None:
        """
        Return remediation parameters for auto-remediation.

        Override to provide dynamic remediation parameters.

        Args:
            resource: The resource to remediate

        Returns:
            Remediation parameters or None
        """
        return self.auto_remediation_parameters

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the policy to a dictionary for API submission.

        Returns:
            Dictionary representation of the policy
        """
        return {
            "id": self.id,
            "displayName": self.display_name,
            "description": self.description,
            "enabled": self.enabled,
            "severity": self.severity if isinstance(self.severity, str) else self.severity.value,
            "resourceTypes": self.resource_types,
            "tags": self.tags,
            "runbook": self.runbook,
            "reference": self.reference,
            "reports": self.reports,
            "suppressions": self.suppressions,
            "autoRemediationId": self.auto_remediation_id,
            "autoRemediationParameters": self.auto_remediation_parameters,
            "tests": self.unit_tests,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id}>"
