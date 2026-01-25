from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ActionResult:
    success: bool
    message: str
    data: Optional[dict] = None
    error: Optional[str] = None


class ActionConnector(ABC):
    """Base class for action connectors."""

    @abstractmethod
    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        """Execute the action with the given configuration and alert data."""
        pass

    @abstractmethod
    def validate_config(self, config: dict) -> tuple[bool, Optional[str]]:
        """Validate the action configuration. Returns (is_valid, error_message)."""
        pass
