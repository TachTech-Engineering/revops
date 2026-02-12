"""Roles REST API resource."""

from __future__ import annotations

from typing import AsyncIterator, Iterator

from ...exceptions import NotFoundError
from ...models import Role, RoleCreate, RoleListParams, RoleUpdate
from ..base import BaseClient, PaginatedResource


class RolesResource(PaginatedResource):
    """REST API resource for managing roles."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/roles"

    def list(
        self,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[Role]:
        """
        List roles with optional filtering.

        Args:
            name_contains: Filter by name substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            Role objects
        """
        params = RoleListParams(
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield Role.model_validate(item)

    async def alist(
        self,
        name_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[Role]:
        """Async version of list()."""
        params = RoleListParams(
            nameContains=name_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(
            self._client, self._path, params, page_size, max_items
        ):
            yield Role.model_validate(item)

    def get(self, role_id: str) -> Role:
        """
        Get a single role by ID.

        Args:
            role_id: The role ID

        Returns:
            Role object

        Raises:
            NotFoundError: If the role is not found
        """
        try:
            data = self._client.get(f"{self._path}/{role_id}")
            return Role.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Role", role_id)

    async def aget(self, role_id: str) -> Role:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{role_id}")
            return Role.model_validate(data)
        except NotFoundError:
            raise NotFoundError("Role", role_id)

    def create(
        self,
        name: str,
        permissions: list[str],
        description: str | None = None,
    ) -> Role:
        """
        Create a new role.

        Args:
            name: Role name
            permissions: List of permission strings
            description: Role description

        Returns:
            Created Role object
        """
        create = RoleCreate(
            name=name,
            permissions=permissions,
            description=description,
        )
        data = self._client.post(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return Role.model_validate(data)

    async def acreate(
        self,
        name: str,
        permissions: list[str],
        description: str | None = None,
    ) -> Role:
        """Async version of create()."""
        create = RoleCreate(
            name=name,
            permissions=permissions,
            description=description,
        )
        data = await self._client.apost(
            self._path,
            json=create.model_dump(by_alias=True, exclude_none=True),
        )
        return Role.model_validate(data)

    def update(
        self,
        role_id: str,
        name: str | None = None,
        permissions: list[str] | None = None,
        description: str | None = None,
    ) -> Role:
        """
        Update a role.

        Args:
            role_id: The role ID to update
            name: Role name
            permissions: List of permission strings
            description: Role description

        Returns:
            Updated Role object
        """
        update = RoleUpdate(
            name=name,
            permissions=permissions,
            description=description,
        )
        data = self._client.patch(
            f"{self._path}/{role_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Role.model_validate(data)

    async def aupdate(
        self,
        role_id: str,
        name: str | None = None,
        permissions: list[str] | None = None,
        description: str | None = None,
    ) -> Role:
        """Async version of update()."""
        update = RoleUpdate(
            name=name,
            permissions=permissions,
            description=description,
        )
        data = await self._client.apatch(
            f"{self._path}/{role_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return Role.model_validate(data)

    def delete(self, role_id: str) -> None:
        """
        Delete a role.

        Args:
            role_id: The role ID to delete
        """
        self._client.delete(f"{self._path}/{role_id}")

    async def adelete(self, role_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{role_id}")
