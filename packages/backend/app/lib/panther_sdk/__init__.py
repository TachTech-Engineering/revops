"""
Panther SDK - Python SDK for Panther Security.

This SDK provides:
1. API Client - Clean wrapper for REST and GraphQL APIs
2. Detection Framework - Tools for writing and testing detection rules

Quick Start:
    ```python
    from panther_sdk import PantherClient

    # Initialize client (uses PANTHER_API_HOST and PANTHER_API_TOKEN env vars)
    client = PantherClient()

    # Or with explicit credentials
    client = PantherClient(
        api_host="your-instance.runpanther.net",
        api_token="your-api-token"
    )

    # List open alerts
    for alert in client.alerts.list(status="OPEN"):
        print(f"{alert.severity}: {alert.title}")

    # Execute a data lake query
    result = client.queries.execute("SELECT * FROM panther_logs.public.aws_cloudtrail LIMIT 10")

    # Close the client
    client.close()
    ```

Detection Framework:
    ```python
    from panther_sdk.detections import Rule, Severity, LogType

    class SuspiciousAPICall(Rule):
        id = "Custom.SuspiciousAPICall"
        log_types = [LogType.AWS_CLOUDTRAIL]
        severity = Severity.HIGH

        def rule(self, event):
            return event.get("eventName") == "DeleteTrail"

        def title(self, event):
            return f"CloudTrail deleted by {event.get('userIdentity', {}).get('arn')}"
    ```
"""

from .client import PantherClient
from .config import PantherConfig, load_config
from .exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    DetectionError,
    DetectionTestError,
    GraphQLError,
    NotFoundError,
    PantherError,
    RateLimitError,
    ValidationError,
)
from .models import (
    Alert,
    AlertComment,
    AlertDelivery,
    AlertEvent,
    AlertListParams,
    AlertStatus,
    AlertSummary,
    AlertUpdate,
    DetectionType,
    ListResponse,
    LogType,
    Pagination,
    Policy,
    PolicyCreate,
    PolicyListParams,
    PolicySummary,
    PolicyTest,
    PolicyUpdate,
    Role,
    RoleCreate,
    RoleListParams,
    RoleUpdate,
    Rule,
    RuleCreate,
    RuleListParams,
    RuleReport,
    RuleSummary,
    RuleTest,
    RuleUpdate,
    Severity,
    Timestamps,
    User,
    UserInvite,
    UserListParams,
    UserSummary,
    UserUpdate,
)

__version__ = "0.1.0"
__all__ = [
    # Main client
    "PantherClient",
    # Configuration
    "PantherConfig",
    "load_config",
    # Exceptions
    "PantherError",
    "ConfigurationError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "APIError",
    "GraphQLError",
    "DetectionError",
    "DetectionTestError",
    # Enums
    "Severity",
    "AlertStatus",
    "LogType",
    "DetectionType",
    # Alert models
    "Alert",
    "AlertComment",
    "AlertDelivery",
    "AlertEvent",
    "AlertListParams",
    "AlertSummary",
    "AlertUpdate",
    # Rule models
    "Rule",
    "RuleCreate",
    "RuleListParams",
    "RuleReport",
    "RuleSummary",
    "RuleTest",
    "RuleUpdate",
    # Policy models
    "Policy",
    "PolicyCreate",
    "PolicyListParams",
    "PolicySummary",
    "PolicyTest",
    "PolicyUpdate",
    # User models
    "User",
    "UserInvite",
    "UserListParams",
    "UserSummary",
    "UserUpdate",
    # Role models
    "Role",
    "RoleCreate",
    "RoleListParams",
    "RoleUpdate",
    # Common models
    "ListResponse",
    "Pagination",
    "Timestamps",
]
