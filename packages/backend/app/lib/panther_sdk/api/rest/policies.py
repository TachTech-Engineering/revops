"""Policies REST API resource."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

from ...exceptions import NotFoundError
from ...models import (
    Policy,
    PolicyCreate,
    PolicyListParams,
    PolicySummary,
    PolicyTest,
    PolicyUpdate,
    Severity,
)
from ..base import BaseClient, PaginatedResource


class PoliciesResource(PaginatedResource):
    """REST API resource for managing policies."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/policies"

    def list(
        self,
        enabled: bool | None = None,
        severity: Severity | str | None = None,
        resource_types: list[str] | None = None,
        tags: list[str] | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[PolicySummary]:
        """
        List policies with optional filtering.

        Args:
            enabled: Filter by enabled status
            severity: Filter by severity
            resource_types: Filter by resource types
            tags: Filter by tags
            name_contains: Filter by name substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            PolicySummary objects
        """
        params = PolicyListParams(
            enabled=enabled,
            severity=severity,
            resourceTypes=resource_types,
            tags=tags,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(self._client, self._path, params, page_size, max_items):
            yield PolicySummary.model_validate(item)

    async def alist(
        self,
        enabled: bool | None = None,
        severity: Severity | str | None = None,
        resource_types: list[str] | None = None,
        tags: list[str] | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[PolicySummary]:
        """Async version of list()."""
        params = PolicyListParams(
            enabled=enabled,
            severity=severity,
            resourceTypes=resource_types,
            tags=tags,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(self._client, self._path, params, page_size, max_items):
            yield PolicySummary.model_validate(item)

    def get(self, policy_id: str) -> Policy:
        """
        Get a single policy by ID.

        Args:
            policy_id: The policy ID

        Returns:
            Policy object

        Raises:
            NotFoundError: If the policy is not found
        """
        try:
            data = self._client.get(f"{self._path}/{policy_id}")
            return Policy.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Policy", policy_id)

    async def aget(self, policy_id: str) -> Policy:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{policy_id}")
            return Policy.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Policy", policy_id)

    def create(
        self,
        id: str,
        body: str,
        severity: Severity,
        resource_types: list[str],
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        auto_remediation_id: str | None = None,
        auto_remediation_parameters: dict[str, Any] | None = None,
        suppressions: list[str] | None = None,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[PolicyTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Policy:
        """
        Create a new policy.

        Args:
            id: Unique policy ID
            body: Python code for the policy
            severity: Policy severity
            resource_types: Resource types this policy applies to
            display_name: Human-readable name
            description: Policy description
            enabled: Whether the policy is enabled
            auto_remediation_id: Auto-remediation Lambda ID
            auto_remediation_parameters: Parameters for auto-remediation
            suppressions: Resource patterns to suppress
            tags: Policy tags
            runbook: Runbook URL or text
            reference: Reference URL or text
            tests: Unit tests for the policy
            reports: Report mappings

        Returns:
            Created Policy object
        """
        create = PolicyCreate(
            id=id,
            body=body,
            severity=severity,
            resourceTypes=resource_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            autoRemediationId=auto_remediation_id,
            autoRemediationParameters=auto_remediation_parameters,
            suppressions=suppressions or [],
            tags=tags or [],
            runbook=runbook,
            reference=reference,
            tests=tests or [],
            reports=reports or {},
        )
        data = self._client.post(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return Policy.model_validate(data)

    async def acreate(
        self,
        id: str,
        body: str,
        severity: Severity,
        resource_types: list[str],
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        auto_remediation_id: str | None = None,
        auto_remediation_parameters: dict[str, Any] | None = None,
        suppressions: list[str] | None = None,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[PolicyTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Policy:
        """Async version of create()."""
        create = PolicyCreate(
            id=id,
            body=body,
            severity=severity,
            resourceTypes=resource_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            autoRemediationId=auto_remediation_id,
            autoRemediationParameters=auto_remediation_parameters,
            suppressions=suppressions or [],
            tags=tags or [],
            runbook=runbook,
            reference=reference,
            tests=tests or [],
            reports=reports or {},
        )
        data = await self._client.apost(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return Policy.model_validate(data)

    def update(
        self,
        policy_id: str,
        body: str | None = None,
        severity: Severity | None = None,
        resource_types: list[str] | None = None,
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        auto_remediation_id: str | None = None,
        auto_remediation_parameters: dict[str, Any] | None = None,
        suppressions: list[str] | None = None,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[PolicyTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Policy:
        """
        Update an existing policy.

        Args:
            policy_id: The policy ID to update
            body: Python code for the policy
            severity: Policy severity
            resource_types: Resource types this policy applies to
            display_name: Human-readable name
            description: Policy description
            enabled: Whether the policy is enabled
            auto_remediation_id: Auto-remediation Lambda ID
            auto_remediation_parameters: Parameters for auto-remediation
            suppressions: Resource patterns to suppress
            tags: Policy tags
            runbook: Runbook URL or text
            reference: Reference URL or text
            tests: Unit tests for the policy
            reports: Report mappings

        Returns:
            Updated Policy object
        """
        update = PolicyUpdate(
            body=body,
            severity=severity,
            resourceTypes=resource_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            autoRemediationId=auto_remediation_id,
            autoRemediationParameters=auto_remediation_parameters,
            suppressions=suppressions,
            tags=tags,
            runbook=runbook,
            reference=reference,
            tests=tests,
            reports=reports,
        )
        data = self._client.patch(
            f"{self._path}/{policy_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Policy.model_validate(data)

    async def aupdate(
        self,
        policy_id: str,
        body: str | None = None,
        severity: Severity | None = None,
        resource_types: list[str] | None = None,
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        auto_remediation_id: str | None = None,
        auto_remediation_parameters: dict[str, Any] | None = None,
        suppressions: list[str] | None = None,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[PolicyTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Policy:
        """Async version of update()."""
        update = PolicyUpdate(
            body=body,
            severity=severity,
            resourceTypes=resource_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            autoRemediationId=auto_remediation_id,
            autoRemediationParameters=auto_remediation_parameters,
            suppressions=suppressions,
            tags=tags,
            runbook=runbook,
            reference=reference,
            tests=tests,
            reports=reports,
        )
        data = await self._client.apatch(
            f"{self._path}/{policy_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Policy.model_validate(data)

    def delete(self, policy_id: str) -> None:
        """
        Delete a policy.

        Args:
            policy_id: The policy ID to delete
        """
        self._client.delete(f"{self._path}/{policy_id}")

    async def adelete(self, policy_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{policy_id}")

    def test(self, policy_id: str) -> dict[str, Any]:
        """
        Run tests for a policy.

        Args:
            policy_id: The policy ID to test

        Returns:
            Test results
        """
        return self._client.post(f"{self._path}/{policy_id}/test")

    async def atest(self, policy_id: str) -> dict[str, Any]:
        """Async version of test()."""
        return await self._client.apost(f"{self._path}/{policy_id}/test")
