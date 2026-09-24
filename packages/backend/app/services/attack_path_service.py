"""
Attack Path Service (toxic combination engine)

The correlation layer that makes separate scanners act like a CNAPP: findings
from different tools are individually medium-noise, but compounding on one
asset they describe an attack path. Wiz's core insight, applied to the
Falco + Prowler + Trivy stack:

- Prowler proves *exposure* (public security group, public bucket)
- Trivy proves *exploitability* (CVE present; KEV/EPSS prove it is exploited)
- Falco proves *activity* (something is already behaving badly at runtime)
- Prowler IAM findings prove *blast radius* (over-privileged identities)

Each built-in rule below matches one toxic combination per asset. Evaluation
is idempotent: one AttackPathFinding row per (rule, asset), updated in place,
resolved when a contributing condition clears, and escalated to an Incident
on first detection for critical paths.
"""

import logging
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import (
    AssetAlertLink,
    AssetType,
    AttackPathFinding,
    AttackPathStatus,
    CloudAsset,
    Incident,
    IncidentAlert,
    IncidentSeverity,
    IncidentStatus,
    NormalizedAlert,
)

logger = logging.getLogger(__name__)

ACTIVE_ALERT_STATUSES = ("open", "acknowledged")


@dataclass
class AssetContext:
    """Everything known about one asset, classified for rule evaluation."""

    asset: CloudAsset
    exposure_alerts: list[NormalizedAlert]
    vuln_alerts: list[NormalizedAlert]  # trivy vulnerabilities, high+
    exploited_vuln_alerts: list[NormalizedAlert]  # KEV or EPSS-high subset
    runtime_alerts: list[NormalizedAlert]  # falco, high+
    iam_alerts: list[NormalizedAlert]  # identity/permission findings, high+
    secret_alerts: list[NormalizedAlert]  # trivy exposed secrets

    @property
    def is_exposed(self) -> bool:
        return self.asset.internet_exposed or bool(self.exposure_alerts)


def _has_tag(alert: NormalizedAlert, tag: str) -> bool:
    return tag in (alert.tags or [])


def _severity_rank(severity: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        (severity or "").lower(), 0
    )


async def _build_context(
    db: AsyncSession, organization_id: UUID, asset: CloudAsset
) -> AssetContext:
    """Load and classify the asset's active alerts."""
    result = await db.execute(
        select(NormalizedAlert)
        .join(AssetAlertLink, AssetAlertLink.alert_id == NormalizedAlert.id)
        .where(
            and_(
                AssetAlertLink.asset_id == asset.id,
                NormalizedAlert.organization_id == organization_id,
                NormalizedAlert.status.in_(ACTIVE_ALERT_STATUSES),
            )
        )
    )
    alerts = list(result.scalars().all())

    ctx = AssetContext(asset, [], [], [], [], [], [])
    for alert in alerts:
        rank = _severity_rank(alert.severity)

        if _looks_like_exposure(alert):
            ctx.exposure_alerts.append(alert)

        if alert.source_type == "trivy":
            if _has_tag(alert, "trivy_kind:vulnerabilities") and rank >= 3:
                ctx.vuln_alerts.append(alert)
                if _has_tag(alert, "kev") or _has_tag(alert, "epss_high"):
                    ctx.exploited_vuln_alerts.append(alert)
            if _has_tag(alert, "trivy_kind:secrets"):
                ctx.secret_alerts.append(alert)
        elif alert.source_type == "falco" and rank >= 3:
            ctx.runtime_alerts.append(alert)
        elif alert.source_type == "prowler" and rank >= 3 and _looks_like_iam(alert):
            ctx.iam_alerts.append(alert)
    return ctx


def _looks_like_exposure(alert: NormalizedAlert) -> bool:
    from app.services.asset_service import EXPOSURE_PATTERN

    return bool(
        EXPOSURE_PATTERN.search(alert.rule_id or "")
        or EXPOSURE_PATTERN.search(alert.title or "")
    )


def _looks_like_iam(alert: NormalizedAlert) -> bool:
    tags = alert.tags or []
    return (
        "service:iam" in tags
        or "category:identity-access" in tags
        or "admin" in (alert.rule_id or "").lower()
        or "privilege" in (alert.title or "").lower()
    )


# ==================== Built-in toxic combination rules ====================


def _rule_exposed_exploitable_vuln(ctx: AssetContext) -> dict | None:
    """Internet-exposed asset carrying an exploitable vulnerability."""
    if not ctx.is_exposed:
        return None
    vulns = ctx.exploited_vuln_alerts or [
        a for a in ctx.vuln_alerts if _severity_rank(a.severity) >= 4
    ]
    if not vulns:
        return None
    exploited = bool(ctx.exploited_vuln_alerts)
    return {
        "rule_key": "exposed_exploitable_vuln",
        "severity": "critical",
        "title": f"Internet-exposed {ctx.asset.asset_type.value} with "
        + ("actively exploited" if exploited else "critical")
        + f" vulnerability: {ctx.asset.name}",
        "description": (
            f"{ctx.asset.name} is reachable from the internet"
            + (
                f" ({len(ctx.exposure_alerts)} exposure finding(s) from Prowler)"
                if ctx.exposure_alerts
                else ""
            )
            + f" and carries {len(vulns)} "
            + (
                "vulnerability(ies) known to be exploited in the wild (CISA KEV / "
                "high EPSS score)"
                if exploited
                else "critical vulnerability(ies)"
            )
            + ". An attacker can reach the vulnerable service directly. "
            "Patch or remove the exposure first - either action breaks the path."
        ),
        "risk_boost": 30 if exploited else 15,
        "evidence": ctx.exposure_alerts + vulns,
        "path_middle": [("exposure", "Internet exposure"), ("vuln", "Exploitable CVE")],
    }


def _rule_runtime_on_vulnerable_workload(ctx: AssetContext) -> dict | None:
    """Runtime threat detected on a workload that is also vulnerable."""
    if not ctx.runtime_alerts or not ctx.vuln_alerts:
        return None
    return {
        "rule_key": "runtime_on_vulnerable_workload",
        "severity": "critical",
        "title": f"Runtime threat on vulnerable workload: {ctx.asset.name}",
        "description": (
            f"Falco detected {len(ctx.runtime_alerts)} high-severity runtime "
            f"event(s) on {ctx.asset.name}, which also carries "
            f"{len(ctx.vuln_alerts)} high/critical vulnerability(ies). "
            "Suspicious behavior on a host with a known-vulnerable attack "
            "surface is the signature of active exploitation - treat as a "
            "live incident, not a patching backlog item."
        ),
        "risk_boost": 35,
        "evidence": ctx.runtime_alerts + ctx.vuln_alerts,
        "path_middle": [("vuln", "Known vulnerability"), ("runtime", "Runtime threat")],
    }


def _rule_public_data_store(ctx: AssetContext) -> dict | None:
    """Data store (bucket/database) with a public-exposure finding."""
    if ctx.asset.asset_type not in (AssetType.STORAGE_BUCKET, AssetType.DATABASE):
        return None
    if not ctx.exposure_alerts:
        return None
    classified = ctx.asset.data_classification
    return {
        "rule_key": "public_data_store",
        "severity": "critical" if classified else "high",
        "title": f"Publicly exposed data store: {ctx.asset.name}",
        "description": (
            f"The {ctx.asset.asset_type.value} '{ctx.asset.name}' has "
            f"{len(ctx.exposure_alerts)} public-exposure finding(s)"
            + (f" and is classified as {classified}" if classified else "")
            + ". Public data stores are the most common cloud breach vector; "
            "restrict access and audit access logs for prior exfiltration."
        ),
        "risk_boost": 25 if classified else 15,
        "evidence": ctx.exposure_alerts,
        "path_middle": [("exposure", "Public access")],
    }


def _rule_exposed_secret(ctx: AssetContext) -> dict | None:
    """Exposed workload whose artifact also leaks credentials."""
    if not ctx.secret_alerts:
        return None
    if not ctx.is_exposed:
        return None
    return {
        "rule_key": "exposed_workload_with_secrets",
        "severity": "critical",
        "title": f"Internet-exposed workload contains hardcoded secrets: {ctx.asset.name}",
        "description": (
            f"{ctx.asset.name} is internet-reachable and its artifact contains "
            f"{len(ctx.secret_alerts)} hardcoded secret(s) found by Trivy. "
            "Compromise of the workload immediately yields working credentials "
            "for lateral movement. Rotate the credentials and remove them from "
            "the artifact."
        ),
        "risk_boost": 30,
        "evidence": ctx.exposure_alerts + ctx.secret_alerts,
        "path_middle": [("exposure", "Internet exposure"), ("secret", "Hardcoded secret")],
    }


def _rule_privileged_identity_risk(ctx: AssetContext) -> dict | None:
    """Identity/account with high-severity IAM misconfiguration findings.

    CIEM-lite: without a full permission graph, high-severity IAM findings
    (root without MFA, wildcard admin policies, stale privileged keys) on an
    identity or account asset are the actionable subset of what a CIEM
    product would surface.
    """
    if ctx.asset.asset_type not in (
        AssetType.IAM_IDENTITY,
        AssetType.IAM_ROLE,
        AssetType.CLOUD_ACCOUNT,
    ):
        return None
    if not ctx.iam_alerts:
        return None
    worst = max(_severity_rank(a.severity) for a in ctx.iam_alerts)
    return {
        "rule_key": "privileged_identity_risk",
        "severity": "critical" if worst >= 4 else "high",
        "title": f"Over-privileged or unprotected identity: {ctx.asset.name}",
        "description": (
            f"{len(ctx.iam_alerts)} high-severity IAM finding(s) on "
            f"'{ctx.asset.name}'. Identities with excessive privileges or "
            "missing protections (MFA, key rotation) turn any workload "
            "compromise in this account into a full account compromise."
        ),
        "risk_boost": 20,
        "evidence": ctx.iam_alerts,
        "path_middle": [("iam", "Privileged identity weakness")],
    }


TOXIC_COMBINATION_RULES = [
    _rule_exposed_exploitable_vuln,
    _rule_runtime_on_vulnerable_workload,
    _rule_public_data_store,
    _rule_exposed_secret,
    _rule_privileged_identity_risk,
]

ALL_RULE_KEYS = [
    "exposed_exploitable_vuln",
    "runtime_on_vulnerable_workload",
    "public_data_store",
    "exposed_workload_with_secrets",
    "privileged_identity_risk",
]


def _build_path(ctx: AssetContext, match: dict) -> dict:
    """Build the nodes/edges payload the frontend renders as the attack path."""
    asset = ctx.asset
    nodes = [
        {"id": "internet", "label": "Internet", "type": "internet"},
    ]
    edges = []
    prev = "internet"
    for node_id, label in match["path_middle"]:
        nodes.append({"id": node_id, "label": label, "type": node_id})
        edges.append({"source": prev, "target": node_id})
        prev = node_id
    nodes.append(
        {
            "id": "asset",
            "label": asset.name,
            "type": asset.asset_type.value,
            "asset_id": str(asset.id),
        }
    )
    edges.append({"source": prev, "target": "asset"})
    if asset.account_id:
        nodes.append(
            {
                "id": "account",
                "label": f"{asset.provider or 'cloud'}:{asset.account_id}",
                "type": "cloud_account",
            }
        )
        edges.append({"source": "asset", "target": "account", "label": "blast radius"})
    return {"nodes": nodes, "edges": edges}


def _risk_score(ctx: AssetContext, match: dict) -> float:
    """0-100 composite: severity base + rule boost + asset criticality."""
    base = {"critical": 60.0, "high": 45.0, "medium": 30.0}.get(match["severity"], 20.0)
    score = base + match.get("risk_boost", 0)
    # criticality 1-10 contributes up to +10
    score += min(max(ctx.asset.criticality, 1), 10)
    return min(score, 100.0)


async def _create_incident(
    db: AsyncSession, organization_id: UUID, finding: AttackPathFinding, match: dict
) -> Incident:
    """Escalate a critical attack path to an incident with its evidence linked."""
    incident = Incident(
        organization_id=organization_id,
        title=f"[Attack Path] {finding.title}",
        description=(
            f"{finding.description}\n\n"
            f"Auto-created by the attack path engine (rule: {finding.rule_key}, "
            f"risk score: {finding.risk_score:.0f}/100)."
        ),
        status=IncidentStatus.OPEN,
        severity=IncidentSeverity.CRITICAL,
        tags=["attack-path", f"rule:{finding.rule_key}"],
        created_by="attack_path_engine",
    )
    db.add(incident)
    await db.flush()
    for alert in match["evidence"]:
        db.add(
            IncidentAlert(
                organization_id=organization_id,
                incident_id=incident.id,
                alert_id=str(alert.id),
                added_by="attack_path_engine",
            )
        )
    return incident


async def evaluate_asset(
    db: AsyncSession, organization_id: UUID, asset: CloudAsset
) -> list[AttackPathFinding]:
    """Run every toxic-combination rule against one asset.

    Upserts findings for matched rules and resolves previously-open findings
    whose combination no longer holds.
    """
    ctx = await _build_context(db, organization_id, asset)
    now = utcnow()

    existing_result = await db.execute(
        select(AttackPathFinding).where(
            and_(
                AttackPathFinding.organization_id == organization_id,
                AttackPathFinding.asset_id == asset.id,
            )
        )
    )
    existing = {f.rule_key: f for f in existing_result.scalars().all()}

    matched: list[AttackPathFinding] = []
    matched_keys: set[str] = set()

    for rule in TOXIC_COMBINATION_RULES:
        match = rule(ctx)
        if not match:
            continue
        matched_keys.add(match["rule_key"])
        alert_ids = [str(a.id) for a in match["evidence"]]
        risk = _risk_score(ctx, match)
        path = _build_path(ctx, match)

        finding = existing.get(match["rule_key"])
        if finding:
            finding.title = match["title"]
            finding.description = match["description"]
            finding.severity = match["severity"]
            finding.risk_score = risk
            finding.path = path
            finding.alert_ids = alert_ids
            finding.last_evaluated = now
            if finding.status == AttackPathStatus.RESOLVED:
                # The combination re-appeared; reopen (a dismissal stays dismissed)
                finding.status = AttackPathStatus.OPEN
                finding.resolved_at = None
        else:
            finding = AttackPathFinding(
                organization_id=organization_id,
                asset_id=asset.id,
                rule_key=match["rule_key"],
                title=match["title"],
                description=match["description"],
                severity=match["severity"],
                risk_score=risk,
                path=path,
                alert_ids=alert_ids,
                last_evaluated=now,
            )
            db.add(finding)
            await db.flush()
            if match["severity"] == "critical":
                try:
                    incident = await _create_incident(db, organization_id, finding, match)
                    finding.incident_id = incident.id
                    logger.info(
                        f"Attack path {finding.rule_key} on asset {asset.name} "
                        f"escalated to incident {incident.id}"
                    )
                except Exception:
                    logger.exception("Failed to create incident for attack path finding")
        matched.append(finding)

    # Resolve open findings whose combination no longer holds
    for rule_key, finding in existing.items():
        if rule_key in matched_keys:
            continue
        if finding.status == AttackPathStatus.OPEN:
            finding.status = AttackPathStatus.RESOLVED
            finding.resolved_at = now
            finding.last_evaluated = now

    return matched


async def evaluate_assets(
    db: AsyncSession, organization_id: UUID, asset_ids: set[UUID]
) -> int:
    """Evaluate a set of assets (those touched by a sync batch).

    Returns the number of open attack path findings across them. Contained
    per asset: evaluation must never abort the sync that triggered it.
    """
    total = 0
    for asset_id in asset_ids:
        try:
            result = await db.execute(
                select(CloudAsset).where(
                    and_(
                        CloudAsset.id == asset_id,
                        CloudAsset.organization_id == organization_id,
                    )
                )
            )
            asset = result.scalar_one_or_none()
            if not asset:
                continue
            findings = await evaluate_asset(db, organization_id, asset)
            total += sum(1 for f in findings if f.status == AttackPathStatus.OPEN)
        except Exception:
            logger.exception(f"Attack path evaluation failed for asset {asset_id}")
    return total
