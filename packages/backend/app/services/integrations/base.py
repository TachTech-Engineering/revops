from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ActionResult:
    success: bool
    message: str
    data: dict | None = None
    error: str | None = None


class ActionConnector(ABC):
    """Base class for action connectors."""

    @abstractmethod
    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        """Execute the action with the given configuration and alert data."""
        pass

    @abstractmethod
    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        """Validate the action configuration. Returns (is_valid, error_message)."""
        pass
