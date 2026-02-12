"""Log Sources REST API resource."""

from __future__ import annotations

from datetime import datetime
from typing import Any, AsyncIterator, Iterator

from pydantic import Field

from ...exceptions import NotFoundError
from ...models.common import BaseModelConfig
from ..base import BaseClient, PaginatedResource


class LogSourceHealth(BaseModelConfig):
    """Health status of a log source."""

    status: str
    last_event_at: datetime | None = Field(default=None, alias="lastEventAt")
    error_message: str | None = Field(default=None, alias="errorMessage")


class LogSource(BaseModelConfig):
    """Represents a Panther log source."""

    id: str
    name: str
    description: str | None = None
    integration_type: str = Field(alias="integrationType")
    log_types: list[str] = Field(default_factory=list, alias="logTypes")
    enabled: bool = True

    # Health
    health: LogSourceHealth | None = None

    # Configuration
    s3_bucket: str | None = Field(default=None, alias="s3Bucket")
    s3_prefix: str | None = Field(default=None, alias="s3Prefix")
    kms_key: str | None = Field(default=None, alias="kmsKey")
    log_stream_type: str | None = Field(default=None, alias="logStreamType")

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    updated_by: str | None = Field(default=None, alias="updatedBy")


class LogSourceSummary(BaseModelConfig):
    """Summary view of a log source for list operations."""

    id: str
    name: str
    integration_type: str = Field(alias="integrationType")
    log_types: list[str] = Field(default_factory=list, alias="logTypes")
    enabled: bool = True
    health: LogSourceHealth | None = None
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class LogSourceCreate(BaseModelConfig):
    """Model for creating a log source."""

    name: str
    integration_type: str = Field(alias="integrationType")
    log_types: list[str] = Field(alias="logTypes")
    description: str | None = None
    enabled: bool = True
    s3_bucket: str | None = Field(default=None, alias="s3Bucket")
    s3_prefix: str | None = Field(default=None, alias="s3Prefix")
    kms_key: str | None = Field(default=None, alias="kmsKey")
    log_stream_type: str | None = Field(default=None, alias="logStreamType")


class LogSourceUpdate(BaseModelConfig):
    """Model for updating a log source."""

    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    log_types: list[str] | None = Field(default=None, alias="logTypes")
    s3_bucket: str | None = Field(default=None, alias="s3Bucket")
    s3_prefix: str | None = Field(default=None, alias="s3Prefix")
    kms_key: str | None = Field(default=None, alias="kmsKey")


class LogSourceListParams(BaseModelConfig):
    """Parameters for listing log sources."""

    enabled: bool | None = None
    integration_type: str | None = Field(default=None, alias="integrationType")
    log_types: list[str] | None = Field(default=None, alias="logTypes")
    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None


class LogSourcesResource(PaginatedResource):
    """REST API resource for managing log sources."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/log-sources"

    def list(
        self,
        enabled: bool | None = None,
        integration_type: str | None = None,
        log_types: list[str] | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[LogSourceSummary]:
        """
        List log sources with optional filtering.

        Args:
            enabled: Filter by enabled status
            integration_type: Filter by integration type
            log_types: Filter by log types
            name_contains: Filter by name substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            LogSourceSummary objects
        """
        params = LogSourceListParams(
            enabled=enabled,
            integrationType=integration_type,
            logTypes=log_types,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield LogSourceSummary.model_validate(item)

    async def alist(
        self,
        enabled: bool | None = None,
        integration_type: str | None = None,
        log_types: list[str] | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[LogSourceSummary]:
        """Async version of list()."""
        params = LogSourceListParams(
            enabled=enabled,
            integrationType=integration_type,
            logTypes=log_types,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield LogSourceSummary.model_validate(item)

    def get(self, log_source_id: str) -> LogSource:
        """
        Get a single log source by ID.

        Args:
            log_source_id: The log source ID

        Returns:
            LogSource object

        Raises:
            NotFoundError: If the log source is not found
        """
        try:
            data = self._client.get(f"{self._path}/{log_source_id}")
            return LogSource.model_validate(data)
        except NotFoundError:
            raise NotFoundError("LogSource", log_source_id)

    async def aget(self, log_source_id: str) -> LogSource:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{log_source_id}")
            return LogSource.model_validate(data)
        except NotFoundError:
            raise NotFoundError("LogSource", log_source_id)

    def create(
        self,
        name: str,
        integration_type: str,
        log_types: list[str],
        description: str | None = None,
        enabled: bool = True,
        s3_bucket: str | None = None,
        s3_prefix: str | None = None,
        kms_key: str | None = None,
        log_stream_type: str | None = None,
    ) -> LogSource:
        """
        Create a new log source.

        Args:
            name: Log source name
            integration_type: Type of integration (e.g., "aws-s3")
            log_types: Log types this source provides
            description: Log source description
            enabled: Whether the log source is enabled
            s3_bucket: S3 bucket name (for S3 integrations)
            s3_prefix: S3 prefix (for S3 integrations)
            kms_key: KMS key ARN (for encrypted sources)
            log_stream_type: Log stream type

        Returns:
            Created LogSource object
        """
        create = LogSourceCreate(
            name=name,
            integrationType=integration_type,
            logTypes=log_types,
            description=description,
            enabled=enabled,
            s3Bucket=s3_bucket,
            s3Prefix=s3_prefix,
            kmsKey=kms_key,
            logStreamType=log_stream_type,
        )
        data = self._client.post(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return LogSource.model_validate(data)

    async def acreate(
        self,
        name: str,
        integration_type: str,
        log_types: list[str],
        description: str | None = None,
        enabled: bool = True,
        s3_bucket: str | None = None,
        s3_prefix: str | None = None,
        kms_key: str | None = None,
        log_stream_type: str | None = None,
    ) -> LogSource:
        """Async version of create()."""
        create = LogSourceCreate(
            name=name,
            integrationType=integration_type,
            logTypes=log_types,
            description=description,
            enabled=enabled,
            s3Bucket=s3_bucket,
            s3Prefix=s3_prefix,
            kmsKey=kms_key,
            logStreamType=log_stream_type,
        )
        data = await self._client.apost(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return LogSource.model_validate(data)

    def update(
        self,
        log_source_id: str,
        name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        log_types: list[str] | None = None,
        s3_bucket: str | None = None,
        s3_prefix: str | None = None,
        kms_key: str | None = None,
    ) -> LogSource:
        """
        Update a log source.

        Args:
            log_source_id: The log source ID to update
            name: Log source name
            description: Log source description
            enabled: Whether the log source is enabled
            log_types: Log types this source provides
            s3_bucket: S3 bucket name (for S3 integrations)
            s3_prefix: S3 prefix (for S3 integrations)
            kms_key: KMS key ARN (for encrypted sources)

        Returns:
            Updated LogSource object
        """
        update = LogSourceUpdate(
            name=name,
            description=description,
            enabled=enabled,
            logTypes=log_types,
            s3Bucket=s3_bucket,
            s3Prefix=s3_prefix,
            kmsKey=kms_key,
        )
        data = self._client.patch(
            f"{self._path}/{log_source_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return LogSource.model_validate(data)

    async def aupdate(
        self,
        log_source_id: str,
        name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        log_types: list[str] | None = None,
        s3_bucket: str | None = None,
        s3_prefix: str | None = None,
        kms_key: str | None = None,
    ) -> LogSource:
        """Async version of update()."""
        update = LogSourceUpdate(
            name=name,
            description=description,
            enabled=enabled,
            logTypes=log_types,
            s3Bucket=s3_bucket,
            s3Prefix=s3_prefix,
            kmsKey=kms_key,
        )
        data = await self._client.apatch(
            f"{self._path}/{log_source_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return LogSource.model_validate(data)

    def delete(self, log_source_id: str) -> None:
        """
        Delete a log source.

        Args:
            log_source_id: The log source ID to delete
        """
        self._client.delete(f"{self._path}/{log_source_id}")

    async def adelete(self, log_source_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{log_source_id}")
