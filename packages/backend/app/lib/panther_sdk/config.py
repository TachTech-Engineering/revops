"""Configuration handling for the Panther SDK."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .exceptions import ConfigurationError


@dataclass
class PantherConfig:
    """Configuration for the Panther SDK client."""

    api_host: str
    api_token: str
    api_version: str = "v1"
    timeout: float = 30.0
    max_retries: int = 3
    verify_ssl: bool = True
    debug: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize the API host
        self.api_host = self.api_host.rstrip("/")
        if not self.api_host.startswith(("http://", "https://")):
            self.api_host = f"https://{self.api_host}"

    @property
    def base_url(self) -> str:
        """Get the base URL for API requests."""
        return self.api_host

    @property
    def rest_url(self) -> str:
        """Get the REST API base URL."""
        return f"{self.base_url}/{self.api_version}"

    @property
    def graphql_url(self) -> str:
        """Get the GraphQL API URL."""
        return f"{self.base_url}/public/graphql"

    def validate(self) -> None:
        """Validate the configuration."""
        if not self.api_host:
            raise ConfigurationError("api_host is required")
        if not self.api_token:
            raise ConfigurationError("api_token is required")


def load_config(
    api_host: str | None = None,
    api_token: str | None = None,
    env_file: str | Path | None = None,
    **kwargs: Any,
) -> PantherConfig:
    """
    Load configuration from various sources.

    Priority (highest to lowest):
    1. Explicit parameters
    2. Environment variables
    3. .env file

    Args:
        api_host: The Panther instance hostname
        api_token: The API token for authentication
        env_file: Path to a .env file to load
        **kwargs: Additional configuration options

    Returns:
        PantherConfig instance

    Raises:
        ConfigurationError: If required configuration is missing
    """
    # Load .env file if specified or look for default
    if env_file:
        load_dotenv(env_file)
    else:
        load_dotenv()

    # Get values with fallback to environment variables
    resolved_host = api_host or os.getenv("PANTHER_API_HOST") or os.getenv("PANTHER_HOST")
    resolved_token = api_token or os.getenv("PANTHER_API_TOKEN") or os.getenv("PANTHER_TOKEN")

    if not resolved_host:
        raise ConfigurationError(
            "api_host is required. Set it directly or via PANTHER_API_HOST environment variable."
        )
    if not resolved_token:
        raise ConfigurationError(
            "api_token is required. Set it directly or via PANTHER_API_TOKEN environment variable."
        )

    # Build config with environment variable fallbacks for optional settings
    config = PantherConfig(
        api_host=resolved_host,
        api_token=resolved_token,
        api_version=kwargs.get("api_version") or os.getenv("PANTHER_API_VERSION") or "v1",
        timeout=float(kwargs.get("timeout") or os.getenv("PANTHER_TIMEOUT") or 30.0),
        max_retries=int(kwargs.get("max_retries") or os.getenv("PANTHER_MAX_RETRIES") or 3),
        verify_ssl=kwargs.get(
            "verify_ssl", os.getenv("PANTHER_VERIFY_SSL", "true").lower() == "true"
        ),
        debug=kwargs.get("debug", os.getenv("PANTHER_DEBUG", "false").lower() == "true"),
        extra=kwargs.get("extra", {}),
    )

    config.validate()
    return config
