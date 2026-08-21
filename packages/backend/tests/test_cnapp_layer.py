"""
CNAPP layer tests — DB-free normalization and rule evaluation.

Trivy is push-based like Falco (reports buffered by the ingest webhook,
expanded to per-finding alerts on sync); the attack path engine correlates
Prowler/Trivy/Falco alerts per asset into toxic-combination findings. These
tests cover the pure logic: report expansion, severity/dedup behavior, and
each built-in toxic combination rule.
"""

import uuid

from app.db.models import AssetType, CloudAsset, NormalizedAlert
from app.services.attack_path_service import (
    AssetContext,
    _build_path,
    _risk_score,
    _rule_exposed_exploitable_vuln,
    _rule_exposed_secret,
    _rule_privileged_identity_risk,
    _rule_public_data_store,
    _rule_runtime_on_vulnerable_workload,
)
from app.services.connectors.base import get_connector_registry
from app.services.connectors.data_sources.trivy import TrivyConnector

CONNECTOR_ID = uuid.uuid4()
ORG_ID = uuid.uuid4()


# ==================== Trivy connector ====================


def _trivy_connector(**config) -> TrivyConnector:
    return TrivyConnector(CONNECTOR_ID, config, {"ingest_token": "t"})


def _trivy_report(**overrides) -> dict:
    report = {
        "SchemaVersion": 2,
        "ArtifactName": "nginx:1.25",
        "ArtifactType": "container_image",
        "CreatedAt": "2026-08-20T10:00:00Z",
        "Results": [
            {
                "Target": "nginx:1.25 (debian 12.1)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.9",
                        "FixedVersion": "3.0.11",
                        "Severity": "CRITICAL",
                        "Title": "OpenSSL heap overflow",
                        "Description": "A heap overflow in OpenSSL.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0002",
                        "PkgName": "zlib",
                        "InstalledVersion": "1.2.13",
                        "Severity": "MEDIUM",
                    },
                ],
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "AVDID": "AVD-DS-0002",
                        "Title": "Image runs as root",
                        "Severity": "HIGH",
                        "Message": "Specify a non-root user in the Dockerfile",
                        "Resolution": "Add a USER statement",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key ID",
                        "StartLine": 3,
                    }
                ],
            }
        ],
    }
    report.update(overrides)
    return report


def test_trivy_is_registered_data_source():
    registry = get_connector_registry()
    assert registry.get_data_source("trivy") is TrivyConnector


def test_trivy_report_expands_to_per_finding_alerts():
    alerts = _trivy_connector(min_severity="low")._expand_report(_trivy_report())
    # CVE-2024-0001 (critical), CVE-2024-0002 (medium), misconfig (high), secret (critical)
    assert len(alerts) == 4
    kinds = {a.raw_data["finding_kind"] for a in alerts}
    assert kinds == {"vulnerabilities", "misconfigurations", "secrets"}
    assert all(a.source_type == "trivy" for a in alerts)


def test_trivy_min_severity_filters_findings():
    alerts = _trivy_connector(min_severity="critical")._expand_report(_trivy_report())
    assert {a.severity for a in alerts} == {"critical"}
    assert len(alerts) == 2  # critical CVE + critical secret


def test_trivy_only_fixed_drops_unfixable_vulns():
    alerts = _trivy_connector(min_severity="low", only_fixed=True)._expand_report(
        _trivy_report()
    )
    vuln_ids = {a.rule_id for a in alerts if a.raw_data["finding_kind"] == "vulnerabilities"}
    assert vuln_ids == {"CVE-2024-0001"}  # CVE-2024-0002 has no FixedVersion


def test_trivy_include_classes_filters_kinds():
    alerts = _trivy_connector(
        min_severity="low", include_classes=["vulnerabilities"]
    )._expand_report(_trivy_report())
    assert {a.raw_data["finding_kind"] for a in alerts} == {"vulnerabilities"}


def test_trivy_vuln_alert_fields():
    alerts = _trivy_connector(min_severity="critical")._expand_report(_trivy_report())
    vuln = next(a for a in alerts if a.rule_id == "CVE-2024-0001")
    assert vuln.title == "Trivy: CVE-2024-0001 in openssl (nginx:1.25)"
    assert vuln.severity == "critical"
    assert "cve:CVE-2024-0001" in vuln.tags
    assert "artifact:nginx:1.25" in vuln.tags
    assert "fix_available" in vuln.tags
    assert "trivy_kind:vulnerabilities" in vuln.tags
    assert vuln.external_id.startswith("trivy-")
    assert "fixed in 3.0.11" in vuln.description


def test_trivy_external_id_is_stable_across_rescans():
    connector = _trivy_connector(min_severity="critical")
    first = connector._expand_report(_trivy_report())
    second = connector._expand_report(_trivy_report())
    assert [a.external_id for a in first] == [a.external_id for a in second]


def test_trivy_severity_mapping():
    connector = _trivy_connector()
    assert connector.normalize_severity("CRITICAL") == "critical"
    assert connector.normalize_severity("UNKNOWN") == "info"
    assert connector.normalize_severity("nonsense") == "medium"


# ==================== Attack path rules ====================


def _asset(asset_type=AssetType.VM_INSTANCE, exposed=False, **kwargs) -> CloudAsset:
    return CloudAsset(
        id=uuid.uuid4(),
        organization_id=ORG_ID,
        external_id=kwargs.pop("external_id", "host:web-01"),
        asset_type=asset_type,
        name=kwargs.pop("name", "web-01"),
        internet_exposed=exposed,
        criticality=kwargs.pop("criticality", 5),
        **kwargs,
    )


def _alert(source_type: str, severity: str = "high", tags: list | None = None, **kwargs):
    return NormalizedAlert(
        id=uuid.uuid4(),
        organization_id=ORG_ID,
        connector_id=CONNECTOR_ID,
        source_type=source_type,
        external_id=str(uuid.uuid4()),
        title=kwargs.pop("title", f"{source_type} finding"),
        severity=severity,
        status="open",
        tags=tags or [],
        **kwargs,
    )


def _ctx(asset, **lists) -> AssetContext:
    return AssetContext(
        asset=asset,
        exposure_alerts=lists.get("exposure", []),
        vuln_alerts=lists.get("vulns", []),
        exploited_vuln_alerts=lists.get("exploited", []),
        runtime_alerts=lists.get("runtime", []),
        iam_alerts=lists.get("iam", []),
        secret_alerts=lists.get("secrets", []),
    )


def test_exposed_exploitable_vuln_requires_both_conditions():
    kev_vuln = _alert("trivy", "critical", ["kev", "trivy_kind:vulnerabilities"])
    exposure = _alert("prowler", "high", title="Security group open to the internet (public)")

    # Vulnerable but not exposed: no match
    assert _rule_exposed_exploitable_vuln(_ctx(_asset(), exploited=[kev_vuln])) is None
    # Exposed but not vulnerable: no match
    assert _rule_exposed_exploitable_vuln(_ctx(_asset(exposed=True))) is None
    # Both: critical finding
    match = _rule_exposed_exploitable_vuln(
        _ctx(_asset(exposed=True), exploited=[kev_vuln], exposure=[exposure])
    )
    assert match is not None
    assert match["severity"] == "critical"
    assert match["rule_key"] == "exposed_exploitable_vuln"
    assert "actively exploited" in match["title"]


def test_exposed_critical_vuln_matches_without_kev():
    critical_vuln = _alert("trivy", "critical", ["trivy_kind:vulnerabilities"])
    match = _rule_exposed_exploitable_vuln(_ctx(_asset(exposed=True), vulns=[critical_vuln]))
    assert match is not None
    assert "critical" in match["title"]


def test_runtime_on_vulnerable_workload():
    runtime = _alert("falco", "high")
    vuln = _alert("trivy", "high", ["trivy_kind:vulnerabilities"])

    assert _rule_runtime_on_vulnerable_workload(_ctx(_asset(), runtime=[runtime])) is None
    assert _rule_runtime_on_vulnerable_workload(_ctx(_asset(), vulns=[vuln])) is None
    match = _rule_runtime_on_vulnerable_workload(
        _ctx(_asset(), runtime=[runtime], vulns=[vuln])
    )
    assert match is not None
    assert match["severity"] == "critical"
    assert set(match["evidence"]) == {runtime, vuln}


def test_public_data_store_only_matches_data_assets():
    exposure = _alert("prowler", "high", title="S3 bucket allows public read")
    # VM with exposure finding: not a data store, no match
    assert _rule_public_data_store(_ctx(_asset(exposed=True), exposure=[exposure])) is None

    bucket = _asset(AssetType.STORAGE_BUCKET, exposed=True, name="customer-data")
    match = _rule_public_data_store(_ctx(bucket, exposure=[exposure]))
    assert match is not None
    assert match["severity"] == "high"

    classified = _asset(
        AssetType.STORAGE_BUCKET, exposed=True, data_classification="pii"
    )
    match = _rule_public_data_store(_ctx(classified, exposure=[exposure]))
    assert match["severity"] == "critical"


def test_exposed_secret_rule():
    secret = _alert("trivy", "critical", ["trivy_kind:secrets"])
    assert _rule_exposed_secret(_ctx(_asset(), secrets=[secret])) is None  # not exposed
    match = _rule_exposed_secret(_ctx(_asset(exposed=True), secrets=[secret]))
    assert match is not None
    assert match["severity"] == "critical"


def test_privileged_identity_risk_only_on_identity_assets():
    iam_alert = _alert("prowler", "critical", ["service:iam"], title="Root MFA disabled")
    # IAM findings on a VM asset do not trigger the identity rule
    assert _rule_privileged_identity_risk(_ctx(_asset(), iam=[iam_alert])) is None

    identity = _asset(AssetType.IAM_IDENTITY, name="root", external_id="aws:iam::root")
    match = _rule_privileged_identity_risk(_ctx(identity, iam=[iam_alert]))
    assert match is not None
    assert match["severity"] == "critical"

    weaker = _alert("prowler", "high", ["service:iam"])
    match = _rule_privileged_identity_risk(_ctx(identity, iam=[weaker]))
    assert match["severity"] == "high"


def test_risk_score_bounded_and_ordered():
    kev_vuln = _alert("trivy", "critical", ["kev", "trivy_kind:vulnerabilities"])
    plain_vuln = _alert("trivy", "critical", ["trivy_kind:vulnerabilities"])
    exposed = _asset(exposed=True, criticality=10)

    kev_match = _rule_exposed_exploitable_vuln(_ctx(exposed, exploited=[kev_vuln]))
    plain_match = _rule_exposed_exploitable_vuln(_ctx(exposed, vulns=[plain_vuln]))

    kev_score = _risk_score(_ctx(exposed), kev_match)
    plain_score = _risk_score(_ctx(exposed), plain_match)
    assert 0 < plain_score < kev_score <= 100


def test_build_path_produces_renderable_graph():
    asset = _asset(exposed=True, account_id="123456789012", provider="aws")
    vuln = _alert("trivy", "critical", ["kev", "trivy_kind:vulnerabilities"])
    match = _rule_exposed_exploitable_vuln(_ctx(asset, exploited=[vuln]))
    path = _build_path(_ctx(asset), match)

    node_ids = {n["id"] for n in path["nodes"]}
    assert "internet" in node_ids
    assert "asset" in node_ids
    assert "account" in node_ids  # blast radius node
    # Every edge references defined nodes
    for edge in path["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
