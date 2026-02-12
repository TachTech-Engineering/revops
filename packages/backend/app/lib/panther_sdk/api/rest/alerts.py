"""Alerts REST API resource."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Iterator

from ...exceptions import NotFoundError
from ...models import (
    Alert,
    AlertComment,
    AlertEvent,
    AlertListParams,
    AlertStatus,
    AlertSummary,
    AlertUpdate,
    Severity,
)
from ..base import BaseClient, PaginatedResource


class AlertsResource(PaginatedResource):
    """REST API resource for managing alerts."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/alerts"

    def list(
        self,
        status: AlertStatus | str | None = None,
        severity: Severity | str | None = None,
        detection_id: str | None = None,
        assignee_id: str | None = None,
        log_types: list[str] | None = None,
        name_contains: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[AlertSummary]:
        """
        List alerts with optional filtering.

        Args:
            status: Filter by alert status
            severity: Filter by severity
            detection_id: Filter by detection ID
            assignee_id: Filter by assignee
            log_types: Filter by log types
            name_contains: Filter by name substring
            created_after: Filter alerts created after this datetime
            created_before: Filter alerts created before this datetime
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            AlertSummary objects
        """
        # Default to last 30 days if no date range specified
        if created_after is None and created_before is None:
            created_after = datetime.now() - timedelta(days=30)

        params = AlertListParams(
            status=status,
            severity=severity,
            detectionId=detection_id,
            assigneeId=assignee_id,
            logTypes=log_types,
            nameContains=name_contains,
            createdAfter=created_after,
            createdBefore=created_before,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield AlertSummary.model_validate(item)

    async def alist(
        self,
        status: AlertStatus | str | None = None,
        severity: Severity | str | None = None,
        detection_id: str | None = None,
        assignee_id: str | None = None,
        log_types: list[str] | None = None,
        name_contains: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[AlertSummary]:
        """Async version of list()."""
        # Default to last 30 days if no date range specified
        if created_after is None and created_before is None:
            created_after = datetime.now() - timedelta(days=30)

        params = AlertListParams(
            status=status,
            severity=severity,
            detectionId=detection_id,
            assigneeId=assignee_id,
            logTypes=log_types,
            nameContains=name_contains,
            createdAfter=created_after,
            createdBefore=created_before,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield AlertSummary.model_validate(item)

    def get(self, alert_id: str) -> Alert:
        """
        Get a single alert by ID.

        Args:
            alert_id: The alert ID

        Returns:
            Alert object

        Raises:
            NotFoundError: If the alert is not found
        """
        try:
            data = self._client.get(f"{self._path}/{alert_id}")
            return Alert.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Alert", alert_id)

    async def aget(self, alert_id: str) -> Alert:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{alert_id}")
            return Alert.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Alert", alert_id)

    def update(
        self,
        alert_id: str,
        status: AlertStatus | None = None,
        assignee_id: str | None = None,
    ) -> Alert:
        """
        Update an alert.

        Args:
            alert_id: The alert ID
            status: New status
            assignee_id: New assignee ID

        Returns:
            Updated Alert object
        """
        update = AlertUpdate(status=status, assigneeId=assignee_id)
        data = self._client.patch(
            f"{self._path}/{alert_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Alert.model_validate(data)

    async def aupdate(
        self,
        alert_id: str,
        status: AlertStatus | None = None,
        assignee_id: str | None = None,
    ) -> Alert:
        """Async version of update()."""
        update = AlertUpdate(status=status, assigneeId=assignee_id)
        data = await self._client.apatch(
            f"{self._path}/{alert_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Alert.model_validate(data)

    def batch_update(
        self,
        alert_ids: list[str],
        status: AlertStatus | None = None,
        assignee_id: str | None = None,
    ) -> list[Alert]:
        """
        Update multiple alerts at once.

        Args:
            alert_ids: List of alert IDs to update
            status: New status for all alerts
            assignee_id: New assignee ID for all alerts

        Returns:
            List of updated Alert objects
        """
        update = AlertUpdate(status=status, assigneeId=assignee_id)
        data = self._client.patch(
            f"{self._path}/batch",
            json={
                "alertIds": alert_ids,
                **update.model_dump(by_alias=True, exclude_none=True),
            },
        )
        return [Alert.model_validate(item) for item in data.get("results", [])]

    async def abatch_update(
        self,
        alert_ids: list[str],
        status: AlertStatus | None = None,
        assignee_id: str | None = None,
    ) -> list[Alert]:
        """Async version of batch_update()."""
        update = AlertUpdate(status=status, assigneeId=assignee_id)
        data = await self._client.apatch(
            f"{self._path}/batch",
            json={
                "alertIds": alert_ids,
                **update.model_dump(by_alias=True, exclude_none=True),
            },
        )
        return [Alert.model_validate(item) for item in data.get("results", [])]

    def get_events(
        self,
        alert_id: str,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[AlertEvent]:
        """
        Get events associated with an alert.

        Args:
            alert_id: The alert ID
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            AlertEvent objects
        """
        for item in self._paginate(
            self._client,
            f"{self._path}/{alert_id}/events",
            page_size=page_size,
            max_items=max_items,
            results_key="events",
        ):
            yield AlertEvent.model_validate(item)

    async def aget_events(
        self,
        alert_id: str,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[AlertEvent]:
        """Async version of get_events()."""
        async for item in self._apaginate(
            self._client,
            f"{self._path}/{alert_id}/events",
            page_size=page_size,
            max_items=max_items,
            results_key="events",
        ):
            yield AlertEvent.model_validate(item)

    def add_comment(self, alert_id: str, body: str) -> AlertComment:
        """
        Add a comment to an alert.

        Args:
            alert_id: The alert ID
            body: Comment text

        Returns:
            AlertComment object
        """
        data = self._client.post(
            f"{self._path}/{alert_id}/comments",
            json={"body": body},
        )
        return AlertComment.model_validate(data)

    async def aadd_comment(self, alert_id: str, body: str) -> AlertComment:
        """Async version of add_comment()."""
        data = await self._client.apost(
            f"{self._path}/{alert_id}/comments",
            json={"body": body},
        )
        return AlertComment.model_validate(data)

    def list_comments(self, alert_id: str) -> list[AlertComment]:
        """
        List comments on an alert.

        Args:
            alert_id: The alert ID

        Returns:
            List of AlertComment objects
        """
        data = self._client.get(f"{self._path}/{alert_id}/comments")
        return [AlertComment.model_validate(item) for item in data.get("results", [])]

    async def alist_comments(self, alert_id: str) -> list[AlertComment]:
        """Async version of list_comments()."""
        data = await self._client.aget(f"{self._path}/{alert_id}/comments")
        return [AlertComment.model_validate(item) for item in data.get("results", [])]
