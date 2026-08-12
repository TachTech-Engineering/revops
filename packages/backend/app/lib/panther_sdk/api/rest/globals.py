"""Globals REST API resource."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import datetime

from pydantic import Field

from ...exceptions import NotFoundError
from ...models.common import BaseModelConfig
from ..base import BaseClient, PaginatedResource


class Global(BaseModelConfig):
    """Represents a Panther global helper module."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    body: str

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    updated_by: str | None = Field(default=None, alias="updatedBy")


class GlobalSummary(BaseModelConfig):
    """Summary view of a global for list operations."""

    id: str
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class GlobalCreate(BaseModelConfig):
    """Model for creating a global."""

    id: str
    body: str
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None


class GlobalUpdate(BaseModelConfig):
    """Model for updating a global."""

    body: str | None = None
    display_name: str | None = Field(default=None, alias="displayName")
    description: str | None = None


class GlobalListParams(BaseModelConfig):
    """Parameters for listing globals."""

    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None


class GlobalsResource(PaginatedResource):
    """REST API resource for managing global helper modules."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/globals"

    def list(
        self,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[GlobalSummary]:
        """
        List globals with optional filtering.

        Args:
            name_contains: Filter by name substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            GlobalSummary objects
        """
        params = GlobalListParams(
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(self._client, self._path, params, page_size, max_items):
            yield GlobalSummary.model_validate(item)

    async def alist(
        self,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[GlobalSummary]:
        """Async version of list()."""
        params = GlobalListParams(
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(self._client, self._path, params, page_size, max_items):
            yield GlobalSummary.model_validate(item)

    def get(self, global_id: str) -> Global:
        """
        Get a single global by ID.

        Args:
            global_id: The global ID

        Returns:
            Global object

        Raises:
            NotFoundError: If the global is not found
        """
        try:
            data = self._client.get(f"{self._path}/{global_id}")
            return Global.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Global", global_id)

    async def aget(self, global_id: str) -> Global:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{global_id}")
            return Global.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Global", global_id)

    def create(
        self,
        id: str,
        body: str,
        display_name: str | None = None,
        description: str | None = None,
    ) -> Global:
        """
        Create a new global helper module.

        Args:
            id: Unique global ID (used as module name)
            body: Python code for the global module
            display_name: Human-readable name
            description: Global description

        Returns:
            Created Global object
        """
        create = GlobalCreate(
            id=id,
            body=body,
            displayName=display_name,
            description=description,
        )
        data = self._client.post(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return Global.model_validate(data)

    async def acreate(
        self,
        id: str,
        body: str,
        display_name: str | None = None,
        description: str | None = None,
    ) -> Global:
        """Async version of create()."""
        create = GlobalCreate(
            id=id,
            body=body,
            displayName=display_name,
            description=description,
        )
        data = await self._client.apost(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return Global.model_validate(data)

    def update(
        self,
        global_id: str,
        body: str | None = None,
        display_name: str | None = None,
        description: str | None = None,
    ) -> Global:
        """
        Update a global helper module.

        Args:
            global_id: The global ID to update
            body: Python code for the global module
            display_name: Human-readable name
            description: Global description

        Returns:
            Updated Global object
        """
        update = GlobalUpdate(
            body=body,
            displayName=display_name,
            description=description,
        )
        data = self._client.patch(
            f"{self._path}/{global_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Global.model_validate(data)

    async def aupdate(
        self,
        global_id: str,
        body: str | None = None,
        display_name: str | None = None,
        description: str | None = None,
    ) -> Global:
        """Async version of update()."""
        update = GlobalUpdate(
            body=body,
            displayName=display_name,
            description=description,
        )
        data = await self._client.apatch(
            f"{self._path}/{global_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Global.model_validate(data)

    def delete(self, global_id: str) -> None:
        """
        Delete a global helper module.

        Args:
            global_id: The global ID to delete
        """
        self._client.delete(f"{self._path}/{global_id}")

    async def adelete(self, global_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{global_id}")
