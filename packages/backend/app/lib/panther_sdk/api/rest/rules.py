"""Rules REST API resource."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

from ...exceptions import NotFoundError
from ...models import (
    Rule,
    RuleCreate,
    RuleListParams,
    RuleSummary,
    RuleTest,
    RuleUpdate,
    Severity,
)
from ..base import BaseClient, PaginatedResource


class RulesResource(PaginatedResource):
    """REST API resource for managing detection rules."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/rules"

    def list(
        self,
        enabled: bool | None = None,
        severity: Severity | str | None = None,
        log_types: list[str] | None = None,
        tags: list[str] | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[RuleSummary]:
        """
        List rules with optional filtering.

        Args:
            enabled: Filter by enabled status
            severity: Filter by severity
            log_types: Filter by log types
            tags: Filter by tags
            name_contains: Filter by name substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            RuleSummary objects
        """
        params = RuleListParams(
            enabled=enabled,
            severity=severity,
            logTypes=log_types,
            tags=tags,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(self._client, self._path, params, page_size, max_items):
            yield RuleSummary.model_validate(item)

    async def alist(
        self,
        enabled: bool | None = None,
        severity: Severity | str | None = None,
        log_types: list[str] | None = None,
        tags: list[str] | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[RuleSummary]:
        """Async version of list()."""
        params = RuleListParams(
            enabled=enabled,
            severity=severity,
            logTypes=log_types,
            tags=tags,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(self._client, self._path, params, page_size, max_items):
            yield RuleSummary.model_validate(item)

    def get(self, rule_id: str) -> Rule:
        """
        Get a single rule by ID.

        Args:
            rule_id: The rule ID

        Returns:
            Rule object

        Raises:
            NotFoundError: If the rule is not found
        """
        try:
            data = self._client.get(f"{self._path}/{rule_id}")
            return Rule.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Rule", rule_id)

    async def aget(self, rule_id: str) -> Rule:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{rule_id}")
            return Rule.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Rule", rule_id)

    def create(
        self,
        id: str,
        body: str,
        severity: Severity,
        log_types: list[str],
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        dedup_period_minutes: int = 60,
        threshold: int = 1,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[RuleTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Rule:
        """
        Create a new rule.

        Args:
            id: Unique rule ID
            body: Python code for the rule
            severity: Rule severity
            log_types: Log types this rule applies to
            display_name: Human-readable name
            description: Rule description
            enabled: Whether the rule is enabled
            dedup_period_minutes: Deduplication window
            threshold: Alert threshold
            tags: Rule tags
            runbook: Runbook URL or text
            reference: Reference URL or text
            tests: Unit tests for the rule
            reports: Report mappings

        Returns:
            Created Rule object
        """
        create = RuleCreate(
            id=id,
            body=body,
            severity=severity,
            logTypes=log_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            dedupPeriodMinutes=dedup_period_minutes,
            threshold=threshold,
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
        return Rule.model_validate(data)

    async def acreate(
        self,
        id: str,
        body: str,
        severity: Severity,
        log_types: list[str],
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        dedup_period_minutes: int = 60,
        threshold: int = 1,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[RuleTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Rule:
        """Async version of create()."""
        create = RuleCreate(
            id=id,
            body=body,
            severity=severity,
            logTypes=log_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            dedupPeriodMinutes=dedup_period_minutes,
            threshold=threshold,
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
        return Rule.model_validate(data)

    def update(
        self,
        rule_id: str,
        body: str | None = None,
        severity: Severity | None = None,
        log_types: list[str] | None = None,
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        dedup_period_minutes: int | None = None,
        threshold: int | None = None,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[RuleTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Rule:
        """
        Update an existing rule.

        Args:
            rule_id: The rule ID to update
            body: Python code for the rule
            severity: Rule severity
            log_types: Log types this rule applies to
            display_name: Human-readable name
            description: Rule description
            enabled: Whether the rule is enabled
            dedup_period_minutes: Deduplication window
            threshold: Alert threshold
            tags: Rule tags
            runbook: Runbook URL or text
            reference: Reference URL or text
            tests: Unit tests for the rule
            reports: Report mappings

        Returns:
            Updated Rule object
        """
        update = RuleUpdate(
            body=body,
            severity=severity,
            logTypes=log_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            dedupPeriodMinutes=dedup_period_minutes,
            threshold=threshold,
            tags=tags,
            runbook=runbook,
            reference=reference,
            tests=tests,
            reports=reports,
        )
        data = self._client.patch(
            f"{self._path}/{rule_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Rule.model_validate(data)

    async def aupdate(
        self,
        rule_id: str,
        body: str | None = None,
        severity: Severity | None = None,
        log_types: list[str] | None = None,
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        dedup_period_minutes: int | None = None,
        threshold: int | None = None,
        tags: list[str] | None = None,
        runbook: str | None = None,
        reference: str | None = None,
        tests: list[RuleTest] | None = None,
        reports: dict[str, list[str]] | None = None,
    ) -> Rule:
        """Async version of update()."""
        update = RuleUpdate(
            body=body,
            severity=severity,
            logTypes=log_types,
            displayName=display_name,
            description=description,
            enabled=enabled,
            dedupPeriodMinutes=dedup_period_minutes,
            threshold=threshold,
            tags=tags,
            runbook=runbook,
            reference=reference,
            tests=tests,
            reports=reports,
        )
        data = await self._client.apatch(
            f"{self._path}/{rule_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Rule.model_validate(data)

    def delete(self, rule_id: str) -> None:
        """
        Delete a rule.

        Args:
            rule_id: The rule ID to delete
        """
        self._client.delete(f"{self._path}/{rule_id}")

    async def adelete(self, rule_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{rule_id}")

    def test(self, rule_id: str) -> dict[str, Any]:
        """
        Run tests for a rule.

        Args:
            rule_id: The rule ID to test

        Returns:
            Test results
        """
        return self._client.post(f"{self._path}/{rule_id}/test")

    async def atest(self, rule_id: str) -> dict[str, Any]:
        """Async version of test()."""
        return await self._client.apost(f"{self._path}/{rule_id}/test")
