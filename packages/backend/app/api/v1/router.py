from fastapi import APIRouter

from app.api.v1 import (
    auth,
    alerts,
    rules,
    converter,
    health,
    queries,
    analytics,
    saved_queries,
    suppression,
    settings,
    webhooks,
    ioc_search,
    threat_intel,
    roles,
    audit,
    websocket,
    playbooks,
    scheduled_reports,
    incidents,
    correlation_rules,
    cases,
    enrichment,
    dashboards,
    mitre,
    sla,
    notes,
    notifications,
    # Phase 5: Advanced Features
    ai,
    recommendations,
    simulations,
    # SecOps Platform: Connector Framework & Workflows
    connectors,
    workflows,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(rules.router, prefix="/rules", tags=["rules"])
api_router.include_router(converter.router, prefix="/converter", tags=["converter"])
api_router.include_router(queries.router, prefix="/queries", tags=["queries"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(saved_queries.router, prefix="/saved-queries", tags=["saved-queries"])
api_router.include_router(suppression.router, prefix="/suppression-rules", tags=["suppression"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
api_router.include_router(ioc_search.router, prefix="/ioc", tags=["ioc-search"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["threat-intel"])
api_router.include_router(roles.router, prefix="/roles", tags=["roles"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(websocket.router, tags=["websocket"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
api_router.include_router(scheduled_reports.router, prefix="/scheduled-reports", tags=["scheduled-reports"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(correlation_rules.router, prefix="/correlation-rules", tags=["correlation-rules"])
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(enrichment.router, prefix="/enrichment", tags=["enrichment"])
api_router.include_router(dashboards.router, prefix="/dashboards", tags=["dashboards"])
api_router.include_router(mitre.router, prefix="/mitre", tags=["mitre"])
api_router.include_router(sla.router, prefix="/sla", tags=["sla"])
api_router.include_router(notes.router, prefix="/notes", tags=["notes"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["notifications"])

# Phase 5: Advanced Features
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
api_router.include_router(recommendations.router, prefix="/recommendations", tags=["recommendations"])
api_router.include_router(simulations.router, prefix="/simulations", tags=["simulations"])

# SecOps Platform: Connector Framework & Workflows
api_router.include_router(connectors.router, prefix="/connectors", tags=["connectors"])
api_router.include_router(workflows.router, prefix="/workflows", tags=["workflows"])
