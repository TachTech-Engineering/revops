"""
Two-way alert status sync — connector push-back behavior (DB-free).

When an alert is closed/resolved in RevOps, connectors whose source has
mutable alert state push the change back (CrowdStrike, SentinelOne threats,
AWS Security Hub). Stateless or scan-state sources (Falco, Prowler) must
report the capability as unsupported instead of pretending to sync.
"""

import uuid

from app.db.models import NormalizedAlert
from app.services.connectors.data_sources.aws_security_hub import (
    STATUS_PUSH_MAP as AWS_STATUS_MAP,
)
from app.services.connectors.data_sources.aws_security_hub import (
    AWSSecurityHubConnector,
)
from app.services.connectors.data_sources.crowdstrike_falcon import (
    STATUS_PUSH_MAP as CS_STATUS_MAP,
)
from app.services.connectors.data_sources.falco import FalcoConnector
from app.services.connectors.data_sources.prowler import ProwlerConnector
from app.services.connectors.data_sources.sentinelone import (
    STATUS_PUSH_ENDPOINTS as S1_ENDPOINTS,
)
from app.services.connectors.data_sources.sentinelone import SentinelOneConnector
from app.services.connectors.data_sources.splunk import SplunkConnector

CONNECTOR_ID = uuid.uuid4()


def _alert(**overrides) -> NormalizedAlert:
    fields = {
        "id": uuid.uuid4(),
        "connector_id": CONNECTOR_ID,
        "source_type": "test",
        "external_id": "ext-1",
        "title": "t",
        "severity": "high",
        "status": "open",
        "raw_data": {},
    }
    fields.update(overrides)
    return NormalizedAlert(**fields)


# ==================== default (unsupported) behavior ====================


async def test_base_default_reports_unsupported():
    connector = SplunkConnector(CONNECTOR_ID, {}, {})
    result = await connector.push_status_update(_alert(), "closed")
    assert result.supported is False
    assert result.success is False
    assert "does not support" in result.message


async def test_falco_and_prowler_explain_why_unsupported():
    falco = FalcoConnector(CONNECTOR_ID, {}, {"ingest_token": "t"})
    result = await falco.push_status_update(_alert(), "closed")
    assert result.supported is False
    assert "stateless" in result.message

    prowler = ProwlerConnector(CONNECTOR_ID, {}, {"api_token": "t"})
    result = await prowler.push_status_update(_alert(), "closed")
    assert result.supported is False
    assert "scan" in result.message


# ==================== status mappings ====================


def test_crowdstrike_status_push_map_covers_all_normalized_statuses():
    assert CS_STATUS_MAP == {
        "open": "new",
        "acknowledged": "in_progress",
        "resolved": "closed",
        "closed": "closed",
    }


def test_aws_status_push_map_covers_all_normalized_statuses():
    assert AWS_STATUS_MAP == {
        "open": "NEW",
        "acknowledged": "NOTIFIED",
        "resolved": "RESOLVED",
        "closed": "SUPPRESSED",
    }


def test_sentinelone_endpoints_map_resolution_statuses():
    assert S1_ENDPOINTS["resolved"].endswith("mark-as-resolved")
    assert S1_ENDPOINTS["closed"].endswith("mark-as-resolved")
    assert S1_ENDPOINTS["open"].endswith("mark-as-unresolved")
    assert "acknowledged" not in S1_ENDPOINTS


# ==================== guard conditions (no network needed) ====================


async def test_sentinelone_skips_non_threat_alerts():
    connector = SentinelOneConnector(
        CONNECTOR_ID, {"console_url": "https://example.sentinelone.net"}, {"api_token": "t"}
    )
    result = await connector.push_status_update(_alert(raw_data={"alertInfo": {}}), "closed")
    assert result.supported is False
    assert "threats" in result.message


async def test_sentinelone_rejects_unmapped_status():
    connector = SentinelOneConnector(
        CONNECTOR_ID, {"console_url": "https://example.sentinelone.net"}, {"api_token": "t"}
    )
    result = await connector.push_status_update(_alert(raw_data={"threatInfo": {}}), "acknowledged")
    assert result.supported is False
    assert "acknowledged" in result.message


async def test_aws_requires_product_arn():
    connector = AWSSecurityHubConnector(
        CONNECTOR_ID,
        {"region": "us-east-1"},
        {"access_key_id": "k", "secret_access_key": "s"},
    )
    result = await connector.push_status_update(_alert(raw_data={}), "resolved")
    assert result.supported is False
    assert "ProductArn" in result.message
