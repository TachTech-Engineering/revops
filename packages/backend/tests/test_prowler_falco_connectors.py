"""
Prowler and Falco connector tests — DB-free normalization and buffering.

Prowler is a polling connector against the Prowler App API (JSON:API
findings); Falco is push-based, draining events buffered by the ingest
webhook (POST /api/v1/ingest/falco/{connector_id}). Both must produce
NormalizedAlerts the sync path can persist and dedupe on external_id.
"""

import uuid
from datetime import UTC, datetime

from app.services.connectors.base import get_connector_registry
from app.services.connectors.data_sources.falco import FalcoConnector
from app.services.connectors.data_sources.prowler import ProwlerConnector
from app.services.falco_event_buffer import FalcoEvent

CONNECTOR_ID = uuid.uuid4()


# ==================== Registry ====================


def test_prowler_and_falco_are_registered_data_sources():
    registry = get_connector_registry()
    assert registry.get_data_source("prowler") is ProwlerConnector
    assert registry.get_data_source("falco") is FalcoConnector


# ==================== Prowler ====================


def _prowler_finding(**attr_overrides) -> dict:
    attributes = {
        "uid": "prowler-aws-iam_root_mfa_enabled-123456789012-us-east-1-root",
        "status": "FAIL",
        "status_extended": "Root account does not have MFA enabled.",
        "severity": "critical",
        "check_id": "iam_root_mfa_enabled",
        "check_metadata": {
            "checkid": "iam_root_mfa_enabled",
            "checktitle": "Ensure MFA is enabled for the root account",
            "description": "The root account should have MFA enabled.",
            "risk": "Root credentials without MFA are a single point of failure.",
            "remediation": {"recommendation": {"text": "Enable MFA for root."}},
            "provider": "aws",
            "servicename": "iam",
            "categories": ["identity-access"],
        },
        "muted": False,
        "inserted_at": "2026-08-14T10:00:00Z",
        "updated_at": "2026-08-14T11:00:00Z",
    }
    attributes.update(attr_overrides)
    return {"type": "findings", "id": str(uuid.uuid4()), "attributes": attributes}


def _prowler_connector(**config) -> ProwlerConnector:
    return ProwlerConnector(CONNECTOR_ID, config, {"api_token": "t"})


def test_prowler_normalize_maps_core_fields():
    alert = _prowler_connector().normalize_alert(_prowler_finding())

    assert alert.source_type == "prowler"
    assert alert.external_id == ("prowler-aws-iam_root_mfa_enabled-123456789012-us-east-1-root")
    assert alert.title == "Ensure MFA is enabled for the root account"
    assert alert.severity == "critical"
    assert alert.status == "open"
    assert alert.rule_id == "iam_root_mfa_enabled"
    assert "provider:aws" in alert.tags
    assert "service:iam" in alert.tags
    assert "Remediation: Enable MFA for root." in alert.description
    assert alert.created_at_source.isoformat().startswith("2026-08-14T10:00")


def test_prowler_normalize_pass_and_muted_statuses():
    connector = _prowler_connector()
    assert connector.normalize_alert(_prowler_finding(status="PASS")).status == "resolved"
    assert connector.normalize_alert(_prowler_finding(muted=True)).status == "closed"


def test_prowler_normalize_survives_sparse_finding():
    alert = _prowler_connector().normalize_alert({"attributes": {}})
    assert alert.external_id  # falls back to a generated id
    assert alert.severity == "medium"
    assert alert.status == "open"


def test_prowler_severity_informational_maps_to_info():
    alert = _prowler_connector().normalize_alert(_prowler_finding(severity="informational"))
    assert alert.severity == "info"


async def test_prowler_requires_some_credential():
    connector = ProwlerConnector(CONNECTOR_ID, {}, {})
    result = await connector.test_connection()
    assert result.success is False
    assert "credentials missing" in result.message


# ==================== Falco event buffer ====================


# ==================== Falco connector ====================


def _falco_event(**overrides) -> dict:
    event = {
        "hostname": "node-1",
        "output": "18:31:21.457: Warning Sensitive file opened for reading "
        "(user=root command=cat /etc/shadow)",
        "priority": "Warning",
        "rule": "Read sensitive file untrusted",
        "source": "syscall",
        "tags": ["filesystem", "mitre_credential_access", "T1555"],
        "time": "2026-08-14T18:31:21.457157775Z",
        "output_fields": {
            "user.name": "root",
            "proc.cmdline": "cat /etc/shadow",
            "container.name": "billing-api",
            "k8s.ns.name": "prod",
        },
    }
    event.update(overrides)
    return event


def _falco_connector(**config) -> FalcoConnector:
    return FalcoConnector(uuid.uuid4(), config, {"ingest_token": "secret"})


def test_falco_normalize_maps_core_fields():
    alert = _falco_connector().normalize_alert(_falco_event())

    assert alert.source_type == "falco"
    assert alert.title == "Falco: Read sensitive file untrusted"
    assert alert.severity == "medium"  # Warning
    assert alert.status == "open"
    assert alert.rule_name == "Read sensitive file untrusted"
    assert "host:node-1" in alert.tags
    assert "container:billing-api" in alert.tags
    assert "namespace:prod" in alert.tags
    assert alert.mitre_tactics == ["Credential Access"]
    assert alert.mitre_techniques == ["T1555"]
    assert "proc.cmdline: cat /etc/shadow" in alert.description


def test_falco_external_id_is_stable_for_identical_events():
    connector = _falco_connector()
    first = connector.normalize_alert(_falco_event())
    second = connector.normalize_alert(_falco_event())
    assert first.external_id == second.external_id

    different = connector.normalize_alert(_falco_event(rule="Terminal shell in container"))
    assert different.external_id != first.external_id


def test_falco_priority_severity_map():
    connector = _falco_connector()
    expectations = {
        "Emergency": "critical",
        "Alert": "critical",
        "Critical": "critical",
        "Error": "high",
        "Warning": "medium",
        "Notice": "low",
        "Informational": "info",
        "Debug": "info",
    }
    for priority, expected in expectations.items():
        assert connector.normalize_severity(priority) == expected


class _StubSession:
    """Stand-in for AsyncSessionLocal() in DB-free tests."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def commit(self):
        return None


def _patch_buffer(monkeypatch, queued: list[dict], *, remaining_after: int = 0):
    """Serve `queued` from a fake durable buffer; record what was claimed."""
    state = {"queued": [FalcoEvent(payload=p, received_at=datetime(2026, 1, 1)) for p in queued]}

    async def fake_claim(db, connector_id, limit=100):
        taken, state["queued"] = state["queued"][:limit], state["queued"][limit:]
        return taken

    async def fake_count(db, connector_id):
        return len(state["queued"]) if remaining_after == 0 else remaining_after

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", lambda: _StubSession())
    monkeypatch.setattr("app.services.falco_event_buffer.claim_events", fake_claim)
    monkeypatch.setattr("app.services.falco_event_buffer.count_pending", fake_count)
    return state


async def test_falco_fetch_filters_below_min_priority(monkeypatch):
    connector = _falco_connector(min_priority="warning")
    _patch_buffer(
        monkeypatch,
        [
            _falco_event(priority="Critical", rule="Crit rule"),
            _falco_event(priority="Notice", rule="Noise rule"),
        ],
    )

    since = datetime(2020, 1, 1, tzinfo=UTC)
    alerts, cursor = await connector.fetch_alerts(since=since, limit=100)

    assert [a.rule_name for a in alerts] == ["Crit rule"]
    assert cursor is None


async def test_falco_fetch_signals_more_when_events_remain(monkeypatch):
    connector = _falco_connector()
    state = _patch_buffer(monkeypatch, [_falco_event(rule=f"rule-{i}") for i in range(3)])

    since = datetime(2020, 1, 1, tzinfo=UTC)
    alerts, cursor = await connector.fetch_alerts(since=since, limit=2)
    assert len(alerts) == 2
    assert cursor == "more", "sync loop must keep draining while events remain"

    alerts, cursor = await connector.fetch_alerts(since=since, limit=2)
    assert len(alerts) == 1
    assert cursor is None
    assert state["queued"] == []


async def test_falco_test_connection_reports_webhook_path(monkeypatch):
    _patch_buffer(monkeypatch, [])
    connector = _falco_connector()
    result = await connector.test_connection()
    assert result.success is True
    assert result.details["webhook_path"] == (f"/api/v1/ingest/falco/{connector.connector_id}")

    no_token = FalcoConnector(uuid.uuid4(), {}, {})
    result = await no_token.test_connection()
    assert result.success is False
