"""User and role-related models."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .common import BaseModelConfig


class Role(BaseModelConfig):
    """Represents a Panther role."""

    id: str
    name: str
    description: str | None = None
    permissions: list[str] = Field(default_factory=list)
    is_system: bool = Field(default=False, alias="isSystem")

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class RoleCreate(BaseModelConfig):
    """Model for creating a role."""

    name: str
    description: str | None = None
    permissions: list[str]


class RoleUpdate(BaseModelConfig):
    """Model for updating a role."""

    name: str | None = None
    description: str | None = None
    permissions: list[str] | None = None


class User(BaseModelConfig):
    """Represents a Panther user."""

    id: str
    email: str
    given_name: str | None = Field(default=None, alias="givenName")
    family_name: str | None = Field(default=None, alias="familyName")
    status: str
    role_id: str = Field(alias="roleId")
    role_name: str | None = Field(default=None, alias="roleName")

    # Timestamps
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    last_login: datetime | None = Field(default=None, alias="lastLogin")


class UserSummary(BaseModelConfig):
    """Summary view of a user for list operations."""

    id: str
    email: str
    given_name: str | None = Field(default=None, alias="givenName")
    family_name: str | None = Field(default=None, alias="familyName")
    status: str
    role_name: str | None = Field(default=None, alias="roleName")


class UserInvite(BaseModelConfig):
    """Model for inviting a user."""

    email: str
    given_name: str | None = Field(default=None, alias="givenName")
    family_name: str | None = Field(default=None, alias="familyName")
    role_id: str = Field(alias="roleId")


class UserUpdate(BaseModelConfig):
    """Model for updating a user."""

    given_name: str | None = Field(default=None, alias="givenName")
    family_name: str | None = Field(default=None, alias="familyName")
    role_id: str | None = Field(default=None, alias="roleId")


class UserListParams(BaseModelConfig):
    """Parameters for listing users."""

    status: str | None = None
    role_id: str | None = Field(default=None, alias="roleId")
    email_contains: str | None = Field(default=None, alias="emailContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None


class RoleListParams(BaseModelConfig):
    """Parameters for listing roles."""

    name_contains: str | None = Field(default=None, alias="nameContains")
    page_size: int = Field(default=50, alias="pageSize")
    cursor: str | None = None
