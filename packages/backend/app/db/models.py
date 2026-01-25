from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import String, Text, Boolean, Integer, DateTime, JSON, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum


class Base(DeclarativeBase):
    pass


class UserRoleType(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class ReportFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class WebhookType(str, enum.Enum):
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


class PlaybookStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class ExecutionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


class ActionType(str, enum.Enum):
    WEBHOOK = "webhook"
    JIRA_TICKET = "jira_ticket"
    SERVICENOW_TICKET = "servicenow_ticket"
    UPDATE_ALERT = "update_alert"
    RUN_QUERY = "run_query"
    CROWDSTRIKE_ISOLATE = "crowdstrike_isolate"
    SENTINELONE_ISOLATE = "sentinelone_isolate"
    FIREWALL_BLOCK = "firewall_block"
    SOAR_TRIGGER = "soar_trigger"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CaseActivityType(str, enum.Enum):
    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    PRIORITY_CHANGED = "priority_changed"
    ASSIGNEE_CHANGED = "assignee_changed"
    COMMENT_ADDED = "comment_added"
    INCIDENT_LINKED = "incident_linked"
    INCIDENT_UNLINKED = "incident_unlinked"
    ATTACHMENT_ADDED = "attachment_added"
    UPDATED = "updated"


class EnrichmentType(str, enum.Enum):
    IP_GEOLOCATION = "ip_geolocation"
    IP_REPUTATION = "ip_reputation"
    DOMAIN_WHOIS = "domain_whois"
    DOMAIN_REPUTATION = "domain_reputation"
    FILE_HASH = "file_hash"
    USER_LOOKUP = "user_lookup"
    ASSET_LOOKUP = "asset_lookup"
    CUSTOM_API = "custom_api"


class WidgetType(str, enum.Enum):
    ALERT_SUMMARY = "alert_summary"
    ALERTS_BY_SEVERITY = "alerts_by_severity"
    ALERTS_BY_STATUS = "alerts_by_status"
    ALERTS_OVER_TIME = "alerts_over_time"
    TOP_RULES = "top_rules"
    RECENT_ALERTS = "recent_alerts"
    INCIDENT_SUMMARY = "incident_summary"
    CASE_SUMMARY = "case_summary"
    SLA_STATUS = "sla_status"
    CUSTOM_QUERY = "custom_query"


class MitreTactic(str, enum.Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SLAStatus(str, enum.Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    BREACHED = "breached"


class SavedQuery(Base):
    __tablename__ = "saved_queries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sql: Mapped[str] = mapped_column(Text, nullable=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(255), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # alert_summary, sla_metrics, etc.
    frequency: Mapped[ReportFrequency] = mapped_column(SQLEnum(ReportFrequency), default=ReportFrequency.DAILY)
    recipients: Mapped[list] = mapped_column(JSON, default=list)  # List of email addresses
    filters: Mapped[dict] = mapped_column(JSON, default=dict)  # Report-specific filters
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Specific rule to suppress
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # Suppress by severity
    title_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)  # Regex pattern for title
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserSettings(Base):
    __tablename__ = "user_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    theme: Mapped[str] = mapped_column(String(20), default="dark")
    default_time_range: Mapped[int] = mapped_column(Integer, default=7)  # Days
    alerts_per_page: Mapped[int] = mapped_column(Integer, default=50)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notification_severities: Mapped[list] = mapped_column(JSON, default=lambda: ["CRITICAL", "HIGH"])
    keyboard_shortcuts_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    webhook_type: Mapped[WebhookType] = mapped_column(SQLEnum(WebhookType), default=WebhookType.GENERIC)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    severity_filter: Mapped[list] = mapped_column(JSON, default=lambda: ["CRITICAL", "HIGH"])
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserRole(Base):
    __tablename__ = "user_roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    role: Mapped[UserRoleType] = mapped_column(SQLEnum(UserRoleType), default=UserRoleType.VIEWER)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_conditions: Mapped[dict] = mapped_column(JSON, default=dict)  # severity, rule_id, etc.
    actions: Mapped[list] = mapped_column(JSON, default=list)  # List of action configs
    status: Mapped[PlaybookStatus] = mapped_column(SQLEnum(PlaybookStatus), default=PlaybookStatus.DRAFT)
    auto_execute: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ExecutionStatus] = mapped_column(SQLEnum(ExecutionStatus), default=ExecutionStatus.PENDING)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    action_results: Mapped[list] = mapped_column(JSON, default=list)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(SQLEnum(IncidentStatus), default=IncidentStatus.OPEN)
    severity: Mapped[IncidentSeverity] = mapped_column(SQLEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM)
    assignee: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    added_by: Mapped[str] = mapped_column(String(255), default="system")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)  # time_window, field_matches, etc.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_create_incident: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(SQLEnum(CaseStatus), default=CaseStatus.OPEN)
    priority: Mapped[CasePriority] = mapped_column(SQLEnum(CasePriority), default=CasePriority.MEDIUM)
    assignee: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    incident_ids: Mapped[list] = mapped_column(JSON, default=list)  # Linked incidents
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CaseActivity(Base):
    __tablename__ = "case_activities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    activity_type: Mapped[CaseActivityType] = mapped_column(SQLEnum(CaseActivityType), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    old_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CaseAttachment(Base):
    __tablename__ = "case_attachments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class EnrichmentPipeline(Base):
    __tablename__ = "enrichment_pipelines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enrichment_type: Mapped[EnrichmentType] = mapped_column(SQLEnum(EnrichmentType), nullable=False)
    source_field: Mapped[str] = mapped_column(String(255), nullable=False)  # Field to extract value from alert
    target_field: Mapped[str] = mapped_column(String(255), nullable=False)  # Field to store enrichment result
    api_endpoint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # For custom API enrichments
    api_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    api_key_env: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Environment variable for API key
    cache_ttl_minutes: Mapped[int] = mapped_column(Integer, default=60)  # Cache duration
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_enrich: Mapped[bool] = mapped_column(Boolean, default=False)  # Auto-run on new alerts
    severity_filter: Mapped[list] = mapped_column(JSON, default=list)  # Only enrich alerts with these severities
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    input_value: Mapped[str] = mapped_column(String(1000), nullable=False)  # The value that was enriched
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # SHA256 of input for lookup
    result: Mapped[dict] = mapped_column(JSON, default=dict)  # Enrichment result
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AlertEnrichment(Base):
    __tablename__ = "alert_enrichments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_field: Mapped[str] = mapped_column(String(255), nullable=False)
    source_value: Mapped[str] = mapped_column(Text, nullable=False)
    enrichment_data: Mapped[dict] = mapped_column(JSON, default=dict)
    enriched_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CustomDashboard(Base):
    __tablename__ = "custom_dashboards"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    layout: Mapped[list] = mapped_column(JSON, default=list)  # react-grid-layout format
    widgets: Mapped[list] = mapped_column(JSON, default=list)  # Widget configurations
    owner_email: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g., T1059
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    subtechnique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # e.g., T1059.001
    subtechnique_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tactic: Mapped[MitreTactic] = mapped_column(SQLEnum(MitreTactic), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SLAPolicy(Base):
    __tablename__ = "sla_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Time to acknowledge (minutes) by severity
    ack_time_critical: Mapped[int] = mapped_column(Integer, default=15)  # 15 minutes
    ack_time_high: Mapped[int] = mapped_column(Integer, default=60)  # 1 hour
    ack_time_medium: Mapped[int] = mapped_column(Integer, default=240)  # 4 hours
    ack_time_low: Mapped[int] = mapped_column(Integer, default=1440)  # 24 hours
    # Time to resolve (minutes) by severity
    resolve_time_critical: Mapped[int] = mapped_column(Integer, default=240)  # 4 hours
    resolve_time_high: Mapped[int] = mapped_column(Integer, default=480)  # 8 hours
    resolve_time_medium: Mapped[int] = mapped_column(Integer, default=1440)  # 24 hours
    resolve_time_low: Mapped[int] = mapped_column(Integer, default=4320)  # 72 hours
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Optional rule filters - if empty, applies to all alerts
    rule_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SLAMetric(Base):
    __tablename__ = "sla_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    # Timestamps
    alert_created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # SLA targets (copied from policy at creation time)
    ack_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    resolve_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    # SLA status
    ack_status: Mapped[SLAStatus] = mapped_column(SQLEnum(SLAStatus), default=SLAStatus.ON_TRACK)
    resolve_status: Mapped[SLAStatus] = mapped_column(SQLEnum(SLAStatus), default=SLAStatus.ON_TRACK)
    # Actual times (in minutes)
    ack_time_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    resolve_time_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NoteResourceType(str, enum.Enum):
    ALERT = "alert"
    INCIDENT = "incident"
    CASE = "case"
    RULE = "rule"


class NotificationType(str, enum.Enum):
    MENTION = "mention"
    ALERT_ASSIGNED = "alert_assigned"
    INCIDENT_ASSIGNED = "incident_assigned"
    CASE_ASSIGNED = "case_assigned"
    COMMENT_REPLY = "comment_reply"
    SLA_WARNING = "sla_warning"
    SLA_BREACH = "sla_breach"
    PLAYBOOK_COMPLETED = "playbook_completed"
    PLAYBOOK_FAILED = "playbook_failed"


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    resource_type: Mapped[NoteResourceType] = mapped_column(SQLEnum(NoteResourceType), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    mentions: Mapped[list] = mapped_column(JSON, default=list)  # List of mentioned user emails
    is_edited: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)  # For replies
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    notification_type: Mapped[NotificationType] = mapped_column(SQLEnum(NotificationType), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Who triggered the notification
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
