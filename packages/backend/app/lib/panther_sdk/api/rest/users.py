"""Users REST API resource."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

from ...exceptions import NotFoundError
from ...models import User, UserInvite, UserListParams, UserSummary, UserUpdate
from ..base import BaseClient, PaginatedResource


class UsersResource(PaginatedResource):
    """REST API resource for managing users."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/users"

    def list(
        self,
        status: str | None = None,
        role_id: str | None = None,
        email_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> Iterator[UserSummary]:
        """
        List users with optional filtering.

        Args:
            status: Filter by user status
            role_id: Filter by role ID
            email_contains: Filter by email substring
            page_size: Number of results per page
            max_items: Maximum total items to return

        Yields:
            UserSummary objects
        """
        params = UserListParams(
            status=status,
            roleId=role_id,
            emailContains=email_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        for item in self._paginate(self._client, self._path, params, page_size, max_items):
            yield UserSummary.model_validate(item)

    async def alist(
        self,
        status: str | None = None,
        role_id: str | None = None,
        email_contains: str | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> AsyncIterator[UserSummary]:
        """Async version of list()."""
        params = UserListParams(
            status=status,
            roleId=role_id,
            emailContains=email_contains,
            pageSize=page_size,
        ).model_dump(by_alias=True, exclude_none=True)

        async for item in self._apaginate(self._client, self._path, params, page_size, max_items):
            yield UserSummary.model_validate(item)

    def get(self, user_id: str) -> User:
        """
        Get a single user by ID.

        Args:
            user_id: The user ID

        Returns:
            User object

        Raises:
            NotFoundError: If the user is not found
        """
        try:
            data = self._client.get(f"{self._path}/{user_id}")
            return User.model_validate(data)
        except NotFoundError:
            raise NotFoundError("User", user_id)

    async def aget(self, user_id: str) -> User:
        """Async version of get()."""
        try:
            data = await self._client.aget(f"{self._path}/{user_id}")
            return User.model_validate(data)
        except NotFoundError:
            raise NotFoundError("User", user_id)

    def invite(
        self,
        email: str,
        role_id: str,
        given_name: str | None = None,
        family_name: str | None = None,
    ) -> User:
        """
        Invite a new user.

        Args:
            email: User's email address
            role_id: Role ID to assign
            given_name: User's first name
            family_name: User's last name

        Returns:
            Created User object
        """
        invite = UserInvite(
            email=email,
            roleId=role_id,
            givenName=given_name,
            familyName=family_name,
        )
        data = self._client.post(
            self._path,
            json=invite.model_dump(by_alias=True, exclude_none=True),
        )
        return User.model_validate(data)

    async def ainvite(
        self,
        email: str,
        role_id: str,
        given_name: str | None = None,
        family_name: str | None = None,
    ) -> User:
        """Async version of invite()."""
        invite = UserInvite(
            email=email,
            roleId=role_id,
            givenName=given_name,
            familyName=family_name,
        )
        data = await self._client.apost(
            self._path,
            json=invite.model_dump(by_alias=True, exclude_none=True),
        )
        return User.model_validate(data)

    def update(
        self,
        user_id: str,
        given_name: str | None = None,
        family_name: str | None = None,
        role_id: str | None = None,
    ) -> User:
        """
        Update a user.

        Args:
            user_id: The user ID to update
            given_name: User's first name
            family_name: User's last name
            role_id: Role ID to assign

        Returns:
            Updated User object
        """
        update = UserUpdate(
            givenName=given_name,
            familyName=family_name,
            roleId=role_id,
        )
        data = self._client.patch(
            f"{self._path}/{user_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return User.model_validate(data)

    async def aupdate(
        self,
        user_id: str,
        given_name: str | None = None,
        family_name: str | None = None,
        role_id: str | None = None,
    ) -> User:
        """Async version of update()."""
        update = UserUpdate(
            givenName=given_name,
            familyName=family_name,
            roleId=role_id,
        )
        data = await self._client.apatch(
            f"{self._path}/{user_id}",
            json=update.model_dump(by_alias=True, exclude_none=True),
        )
        return User.model_validate(data)

    def delete(self, user_id: str) -> None:
        """
        Delete a user.

        Args:
            user_id: The user ID to delete
        """
        self._client.delete(f"{self._path}/{user_id}")

    async def adelete(self, user_id: str) -> None:
        """Async version of delete()."""
        await self._client.adelete(f"{self._path}/{user_id}")
