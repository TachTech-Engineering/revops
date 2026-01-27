"""
Action Connectors

Integrations for executing response actions like creating tickets,
sending notifications, or triggering EDR commands.
"""

from app.services.connectors.actions.jira import JiraActionConnector
from app.services.connectors.actions.slack import SlackActionConnector
from app.services.connectors.actions.pagerduty import PagerDutyActionConnector
from app.services.connectors.actions.teams import TeamsActionConnector
from app.services.connectors.actions.crowdstrike import CrowdStrikeActionConnector
from app.services.connectors.actions.sentinelone import SentinelOneActionConnector
from app.services.connectors.actions.servicenow import ServiceNowActionConnector
from app.services.connectors.actions.webhook import WebhookActionConnector
from app.services.connectors.actions.http import HTTPActionConnector

__all__ = [
    "JiraActionConnector",
    "SlackActionConnector",
    "PagerDutyActionConnector",
    "TeamsActionConnector",
    "CrowdStrikeActionConnector",
    "SentinelOneActionConnector",
    "ServiceNowActionConnector",
    "WebhookActionConnector",
    "HTTPActionConnector",
]
