"""
Data Source Connectors

Integrations for ingesting and normalizing security alerts from various platforms.
"""

# SIEM
# Cloud Security
from app.services.connectors.data_sources.aws_security_hub import AWSSecurityHubConnector

# Network Security
from app.services.connectors.data_sources.cloudflare import CloudflareConnector

# EDR
from app.services.connectors.data_sources.crowdstrike_falcon import CrowdStrikeFalconConnector
from app.services.connectors.data_sources.elastic import ElasticConnector
from app.services.connectors.data_sources.entra_id import EntraIDConnector

# Runtime Security
from app.services.connectors.data_sources.falco import FalcoConnector
from app.services.connectors.data_sources.gcp_security_command_center import (
    GCPSecurityCommandCenterConnector,
)
from app.services.connectors.data_sources.google_secops import GoogleSecOpsConnector
from app.services.connectors.data_sources.microsoft_defender import MicrosoftDefenderConnector

# Identity
from app.services.connectors.data_sources.okta import OktaConnector
from app.services.connectors.data_sources.panther import PantherDataSourceConnector

# Cloud Security Posture
from app.services.connectors.data_sources.prowler import ProwlerConnector
from app.services.connectors.data_sources.sentinel import SentinelConnector
from app.services.connectors.data_sources.sentinelone import SentinelOneConnector
from app.services.connectors.data_sources.splunk import SplunkConnector
from app.services.connectors.data_sources.unifi import UnifiConnector

__all__ = [
    # SIEM
    "PantherDataSourceConnector",
    "GoogleSecOpsConnector",
    "SplunkConnector",
    "SentinelConnector",
    "ElasticConnector",
    # EDR
    "CrowdStrikeFalconConnector",
    "SentinelOneConnector",
    "MicrosoftDefenderConnector",
    # Cloud Security
    "AWSSecurityHubConnector",
    "GCPSecurityCommandCenterConnector",
    "ProwlerConnector",
    # Runtime Security
    "FalcoConnector",
    # Identity
    "OktaConnector",
    "EntraIDConnector",
    # Network Security
    "CloudflareConnector",
    "UnifiConnector",
]
