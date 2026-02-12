"""Data Models REST API resource."""

from __future__ import annotations

from datetime import datetime
from typing import Any, AsyncIterator, Iterator

from pydantic import Field

from ...exceptions import NotFoundError
from ...models.common import BaseModelConfig
from ..base import BaseClient, PaginatedResource


class DataModelMapping(BaseModelConfig):
    """A field mapping in a data model."""

    name: str
    path: str
    method: str | None = None


class DataModel(BaseModelConfig):
    """Represents a Panther data model."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool = True
    log_type: str = Field(alias="logType")
    mappings: list[DataModelMapping] = Field(default_factory=list)
    body: str | None = None

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    updated_by: str | None = Field(default=None, alias="updatedBy")


class DataModelSummary(BaseModelConfig):
    """Summary view of a data model for list operations."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    enabled: bool = True
    log_type: str = Field(alias="logType")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class DataModelCreate(BaseModelConfig):
    """Model for creating a data model."""

    id: str
    log_type: str = Field(alias="logType")
    mappings: list[DataModelMapping]
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool = True
    body: str | None = None


class DataModelUpdate(BaseModelConfig):
    """Model for updating a data model."""

    mappings: list[DataModelMapping] | None = None
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    enabled: bool | None = None
    body: str | None = None


class DataModelListParams(BaseModelConfig):
    """Parameters for listing data models."""

    enabled: bool | None = None
    log_type: str | None = Field(default=None, alias="logType")
    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None


class DataModelsResource(PaginatedResource):
    """REST API resource for managing data models."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/data-models"

    def list(
        self,
        enabled: bool | None = None,
        log_type: str | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[DataModelSummary]:
        """
        List data models with optional filtering.

        Args:
            enabled: Filter by enabled status
            log_type: Filter by log type
            name_contains: Filter by name substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            DataModelSummary objects
        """
        params = DataModelListParams(
            enabled=enabled,
            logType=log_type,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield DataModelSummary.model_validate(item)

    async def alist(
        self,
        enabled: bool | None = None,
        log_type: str | None = None,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[DataModelSummary]:
        """Async version of list()."""
        params = DataModelListParams(
            enabled=enabled,
            logType=log_type,
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield DataModelSummary.model_validate(item)

    def get(self, data_model_id: str) -> DataModel:
        """
        Get a single data model by ID.

        Args:
            data_model_id: The data model ID

        Returns:
            DataModel object

        Raises:
            NotFoundError: If the data model is not found
        """
        try:
            data = self._client.get(f"{self._path}/{data_model_id}")
            return DataModel.model_validate(data)
        except NotFoundError:
            raise NotFoundError("DataModel", data_model_id)

    async def aget(self, data_model_id: str) -> DataModel:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{data_model_id}")
            return DataModel.model_validate(data)
        except NotFoundError:
            raise NotFoundError("DataModel", data_model_id)

    def create(
        self,
        id: str,
        log_type: str,
        mappings: list[DataModelMapping],
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        body: str | None = None,
    ) -> DataModel:
        """
        Create a new data model.

        Args:
            id: Unique data model ID
            log_type: Log type this model applies to
            mappings: Field mappings
            display_name: Human-readable name
            description: Data model description
            enabled: Whether the data model is enabled
            body: Python code for custom methods

        Returns:
            Created DataModel object
        """
        create = DataModelCreate(
            id=id,
            logType=log_type,
            mappings=mappings,
            displayName=display_name,
            description=description,
            enabled=enabled,
            body=body,
        )
        data = self._client.post(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return DataModel.model_validate(data)

    async def acreate(
        self,
        id: str,
        log_type: str,
        mappings: list[DataModelMapping],
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool = True,
        body: str | None = None,
    ) -> DataModel:
        """Async version of create()."""
        create = DataModelCreate(
            id=id,
            logType=log_type,
            mappings=mappings,
            displayName=display_name,
            description=description,
            enabled=enabled,
            body=body,
        )
        data = await self._client.apost(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return DataModel.model_validate(data)

    def update(
        self,
        data_model_id: str,
        mappings: list[DataModelMapping] | None = None,
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        body: str | None = None,
    ) -> DataModel:
        """
        Update a data model.

        Args:
            data_model_id: The data model ID to update
            mappings: Field mappings
            display_name: Human-readable name
            description: Data model description
            enabled: Whether the data model is enabled
            body: Python code for custom methods

        Returns:
            Updated DataModel object
        """
        update = DataModelUpdate(
            mappings=mappings,
            displayName=display_name,
            description=description,
            enabled=enabled,
            body=body,
        )
        data = self._client.patch(
            f"{self._path}/{data_model_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return DataModel.model_validate(data)

    async def aupdate(
        self,
        data_model_id: str,
        mappings: list[DataModelMapping] | None = None,
        display_name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        body: str | None = None,
    ) -> DataModel:
        """Async version of update()."""
        update = DataModelUpdate(
            mappings=mappings,
            displayName=display_name,
            description=description,
            enabled=enabled,
            body=body,
        )
        data = await self._client.apatch(
            f"{self._path}/{data_model_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return DataModel.model_validate(data)

    def delete(self, data_model_id: str) -> None:
        """
        Delete a data model.

        Args:
            data_model_id: The data model ID to delete
        """
        self._client.delete(f"{self._path}/{data_model_id}")

    async def adelete(self, data_model_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{data_model_id}")
