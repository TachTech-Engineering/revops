from fastapi import APIRouter, Depends

from app.api.v1 import (
    # Phase 5: Advanced Features
    ai,
    alert_clusters,
    alerts,
    analytics,
    audit,
    auth,
    cases,
    compliance,
    # SecOps Platform: Connector Framework, Pipelines & Workflows
    connectors,
    converter,
    correlation_rules,
    dashboards,
    enrichment,
    escalation,
    executive_summary,
    falco_ingest,
    # Other
    feeds,
    fonoster,
    health,
    incidents,
    ioc_search,
    iocs,
    logs,
    migrate,
    mitre,
    nl_queries,
    notes,
    notifications,
    pipelines,
    playbook_templates,
    playbooks,
    presence,
    queries,
    recommendations,
    roles,
    rule_health,
    # New Features: Rule Management, Triage, Clustering, Escalation, On-Call, Trends
    rule_versions,
    rules,
    saved_queries,
    scheduled_reports,
    settings,
    # SOC Collaboration Features
    simulations,
    sla,
    sso_config,
    suppression,
    # Threat Hunting
    threat_hunting,
    threat_intel,
    trend_analytics,
    triage,
    twilio_webhook,
    users,
    webhooks,
    websocket,
    workflows,
)
from app.api.v1.deps import get_current_user_with_org, require_org_role
from app.db import UserRoleType

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(
    sso_config.router, prefix="/organizations/{organization_id}/sso", tags=["sso-config"]
)
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
# Note: rule_health must be registered BEFORE rules to avoid /{rule_id} catching /health
api_router.include_router(rule_health.router, prefix="/rules/health", tags=["rule-health"])
api_router.include_router(
    rules.router,
    prefix="/rules",
    tags=["rules"],
    # These handlers take no auth dep of their own; without this the whole
    # router was reachable unauthenticated. Analyst is the floor because
    # every mutating detection-rule endpoint lives here.
    dependencies=[Depends(require_org_role(UserRoleType.ANALYST))],
)
api_router.include_router(converter.router, prefix="/converter", tags=["converter"])
api_router.include_router(migrate.router, prefix="/migrate", tags=["migration"])
api_router.include_router(
    queries.router,
    prefix="/queries",
    tags=["queries"],
    # No auth dep in the handler; query execution reaches an operator-supplied
    # Panther host, so unauthenticated access was an SSRF vector.
    dependencies=[Depends(get_current_user_with_org)],
)
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(saved_queries.router, prefix="/saved-queries", tags=["saved-queries"])
api_router.include_router(suppression.router, prefix="/suppression-rules", tags=["suppression"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
api_router.include_router(ioc_search.router, prefix="/ioc", tags=["ioc-search"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["threat-intel"])
api_router.include_router(roles.router, prefix="/roles", tags=["roles"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(websocket.router, tags=["websocket"])
# Note: playbook_templates must be registered BEFORE playbooks to avoid
# playbooks' GET /{playbook_id} catching /templates and /suggestions
api_router.include_router(
    playbook_templates.router, prefix="/playbooks", tags=["playbook-templates"]
)
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
api_router.include_router(
    scheduled_reports.router, prefix="/scheduled-reports", tags=["scheduled-reports"]
)
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(
    correlation_rules.router, prefix="/correlation-rules", tags=["correlation-rules"]
)
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(enrichment.router, prefix="/enrichment", tags=["enrichment"])
api_router.include_router(dashboards.router, prefix="/dashboards", tags=["dashboards"])
api_router.include_router(mitre.router, prefix="/mitre", tags=["mitre"])
api_router.include_router(sla.router, prefix="/sla", tags=["sla"])
api_router.include_router(notes.router, prefix="/notes", tags=["notes"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["notifications"])

# Phase 5: Advanced Features
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
api_router.include_router(
    recommendations.router, prefix="/recommendations", tags=["recommendations"]
)
api_router.include_router(simulations.router, prefix="/simulations", tags=["simulations"])

# SecOps Platform: Connector Framework, Pipelines & Workflows
api_router.include_router(connectors.router, prefix="/connectors", tags=["connectors"])
api_router.include_router(pipelines.router, prefix="/pipelines", tags=["pipelines"])
api_router.include_router(workflows.router, prefix="/workflows", tags=["workflows"])

# New Features
api_router.include_router(rule_versions.router, prefix="/rules", tags=["rule-versions"])
api_router.include_router(triage.router, prefix="/triage", tags=["triage"])
api_router.include_router(nl_queries.router, prefix="/queries", tags=["nl-queries"])
api_router.include_router(alert_clusters.router, prefix="/alert-clusters", tags=["alert-clusters"])
api_router.include_router(escalation.router, prefix="/escalation-policies", tags=["escalation"])
api_router.include_router(trend_analytics.router, prefix="/analytics", tags=["trend-analytics"])
api_router.include_router(fonoster.router, prefix="/fonoster", tags=["fonoster"])
api_router.include_router(twilio_webhook.router, prefix="/twilio", tags=["twilio-webhook"])
api_router.include_router(falco_ingest.router, prefix="/ingest", tags=["falco-ingest"])

# SOC Collaboration Features
api_router.include_router(presence.router, prefix="/presence", tags=["presence"])

# Threat Hunting
api_router.include_router(threat_hunting.router, tags=["threat-hunting"])

# Other
api_router.include_router(executive_summary.router, tags=["executive"])
api_router.include_router(feeds.router, prefix="/feeds", tags=["feeds"])
api_router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["iocs"])
