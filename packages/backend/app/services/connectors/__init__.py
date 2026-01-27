"""
Connector Framework

Multi-SIEM connector framework for ingesting alerts from various data sources
and executing actions via different integrations.

Data Sources:
- Panther
- Google SecOps (Chronicle)
- Splunk Enterprise Security
- Microsoft Sentinel
- Elastic Security

Action Connectors:
- Jira
- Slack
- PagerDuty
- Microsoft Teams
- CrowdStrike
- SentinelOne
- ServiceNow
- Webhook
- HTTP
"""

from app.services.connectors.base import (
    ConnectionTestResult,
    ActionResult,
    DataSourceConnector,
    ActionConnector,
    ConnectorRegistry,
    get_connector_registry,
)

__all__ = [
    "ConnectionTestResult",
    "ActionResult",
    "DataSourceConnector",
    "ActionConnector",
    "ConnectorRegistry",
    "get_connector_registry",
]
