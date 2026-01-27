from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import String, Text, Boolean, Integer, DateTime, JSON, Enum as SQLEnum, ForeignKey, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
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


# ==================== Authentication Models ====================

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRoleType] = mapped_column(SQLEnum(UserRoleType), default=UserRoleType.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="users")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User")


# ==================== Tenant-Scoped Models ====================
# All models below include organization_id for multi-tenancy

class SavedQuery(Base):
    __tablename__ = "saved_queries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    """Legacy role assignment - prefer using User.role instead"""
    __tablename__ = "user_roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRoleType] = mapped_column(SQLEnum(UserRoleType), default=UserRoleType.VIEWER)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('ix_user_roles_org_email', 'organization_id', 'email', unique=True),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    added_by: Mapped[str] = mapped_column(String(255), default="system")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    case_number: Mapped[str] = mapped_column(String(50), nullable=False)
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

    __table_args__ = (
        Index('ix_cases_org_number', 'organization_id', 'case_number', unique=True),
    )


class CaseActivity(Base):
    __tablename__ = "case_activities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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


# Phase 5: IOC Types
class IOCType(str, enum.Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"


class IOCSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Phase 5: Threat Feed Types
class FeedType(str, enum.Enum):
    OTX = "otx"
    ABUSECH_FEODO = "abusech_feodo"
    ABUSECH_URLHAUS = "abusech_urlhaus"
    CUSTOM_CSV = "custom_csv"
    CUSTOM_STIX = "custom_stix"


class FeedStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"


# Phase 5: Simulation Types
class SimulationFramework(str, enum.Enum):
    ATOMIC_RED_TEAM = "atomic"
    STRATUS_RED_TEAM = "stratus"


class SimulationStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# Phase 5: Recommendation Status
class RecommendationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"


# Phase 5: LLM Provider
class LLMProvider(str, enum.Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


# ==================== CONNECTOR FRAMEWORK ENUMS ====================

class ConnectorCategory(str, enum.Enum):
    DATA_SOURCE = "data_source"  # Ingest alerts from SIEMs
    ACTION = "action"            # Execute response actions


class ConnectorStatus(str, enum.Enum):
    CONNECTED = "connected"
    ERROR = "error"
    DISABLED = "disabled"
    PENDING = "pending"


class DataSourceType(str, enum.Enum):
    PANTHER = "panther"
    GOOGLE_SECOPS = "google_secops"
    SPLUNK = "splunk"
    MICROSOFT_SENTINEL = "sentinel"
    ELASTIC_SECURITY = "elastic"


class ActionConnectorType(str, enum.Enum):
    JIRA = "jira"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    TEAMS = "teams"
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    SERVICENOW = "servicenow"
    WEBHOOK = "webhook"
    HTTP = "http"


# ==================== WORKFLOW ENGINE ENUMS ====================

class WorkflowStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    INACTIVE = "inactive"


class NodeType(str, enum.Enum):
    # Triggers
    TRIGGER_ALERT = "trigger_alert"
    TRIGGER_SCHEDULE = "trigger_schedule"
    TRIGGER_WEBHOOK = "trigger_webhook"
    TRIGGER_MANUAL = "trigger_manual"
    # Actions
    HTTP_REQUEST = "http_request"
    CONNECTOR_ACTION = "connector_action"
    # Logic
    CONDITION = "condition"
    TRANSFORM = "transform"
    DELAY = "delay"
    LOOP = "loop"
    # Utility
    SET_VARIABLE = "set_variable"


class WorkflowExecutionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
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


# Phase 5: IOC Management Models
class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    ioc_type: Mapped[IOCType] = mapped_column(SQLEnum(IOCType), nullable=False)
    value: Mapped[str] = mapped_column(String(2000), nullable=False, index=True)
    severity: Mapped[IOCSeverity] = mapped_column(SQLEnum(IOCSeverity), default=IOCSeverity.MEDIUM)
    source: Mapped[str] = mapped_column(String(255), nullable=False)  # Manual, feed name, etc.
    feed_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Phase 5: Threat Feed Models
class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    feed_type: Mapped[FeedType] = mapped_column(SQLEnum(FeedType), nullable=False)
    status: Mapped[FeedStatus] = mapped_column(SQLEnum(FeedStatus), default=FeedStatus.ACTIVE)
    update_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class FeedSyncLog(Base):
    __tablename__ = "feed_sync_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    feed_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # success, failed
    iocs_added: Mapped[int] = mapped_column(Integer, default=0)
    iocs_updated: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# Phase 5: AI Summary Cache
class AISummaryCache(Base):
    __tablename__ = "ai_summary_cache"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)  # alert, incident
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    summary_text: Mapped[str] = mapped_column(Text, nullable=False)
    model_used: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[LLMProvider] = mapped_column(SQLEnum(LLMProvider), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# Phase 5: Rule Recommendations
class RuleRecommendation(Base):
    __tablename__ = "rule_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    log_source: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)  # From catalog
    rule_code: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    confidence_score: Mapped[float] = mapped_column(default=0.8)
    status: Mapped[RecommendationStatus] = mapped_column(SQLEnum(RecommendationStatus), default=RecommendationStatus.PENDING)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RuleRecommendationDismissal(Base):
    __tablename__ = "rule_recommendation_dismissals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    recommendation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    dismissed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dismissed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# Phase 5: Attack Simulation Models
class SimulationTemplate(Base):
    __tablename__ = "simulation_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Note: SimulationTemplate is system-wide (catalog), not per-org
    framework: Mapped[SimulationFramework] = mapped_column(SQLEnum(SimulationFramework), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)  # e.g., atomic-T1003-0
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g., T1003
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_tactic: Mapped[str] = mapped_column(String(100), nullable=False, default="Unknown")
    mitre_technique: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    platforms: Mapped[list] = mapped_column(JSON, default=list)  # windows, linux, macos, aws, azure, gcp
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Atomic Red Team specific fields
    executor_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # powershell, cmd, bash, sh, manual
    executor_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Command to execute
    executor_cleanup: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Cleanup command
    input_arguments: Mapped[dict] = mapped_column(JSON, default=dict)  # Input arguments with defaults
    dependencies: Mapped[list] = mapped_column(JSON, default=list)  # Dependencies to check

    # Stratus Red Team specific fields
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # aws, azure, gcp
    cloud_permissions: Mapped[list] = mapped_column(JSON, default=list)  # Required IAM permissions
    detonation_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Stratus detonation
    cleanup_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Stratus cleanup

    # General fields
    test_data: Mapped[dict] = mapped_column(JSON, default=dict)  # Additional framework-specific data
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[SimulationStatus] = mapped_column(SQLEnum(SimulationStatus), default=SimulationStatus.PENDING)
    targets: Mapped[list] = mapped_column(JSON, default=list)  # List of target identifiers
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    detection_expected: Mapped[bool] = mapped_column(Boolean, default=True)
    detection_found: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_rule_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SimulationResult(Base):
    __tablename__ = "simulation_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    detection_details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ==================== CONNECTOR FRAMEWORK MODELS ====================

class Connector(Base):
    """
    Unified connector model for both data sources (SIEMs) and action connectors.
    Supports multi-SIEM alert ingestion and response action execution.
    """
    __tablename__ = "connectors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[ConnectorCategory] = mapped_column(SQLEnum(ConnectorCategory), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., "panther", "jira", "slack"
    status: Mapped[ConnectorStatus] = mapped_column(SQLEnum(ConnectorStatus), default=ConnectorStatus.PENDING)

    # Encrypted credentials (use Fernet encryption)
    credentials_encrypted: Mapped[Optional[bytes]] = mapped_column(nullable=True)

    # Non-sensitive configuration (JSON)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Health tracking
    last_health_check: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # For data sources: sync configuration
    sync_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=5)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_sync_cursor: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)  # Pagination cursor

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NormalizedAlert(Base):
    """
    Normalized alert model for unified view across all SIEM sources.
    All alerts are mapped to a common schema regardless of origin.
    """
    __tablename__ = "normalized_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # panther, splunk, sentinel, etc.
    external_id: Mapped[str] = mapped_column(String(500), nullable=False)  # Original alert ID from source

    # Normalized fields (consistent across all sources)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # critical, high, medium, low, info
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # open, acknowledged, resolved, closed

    # Timestamps from source
    created_at_source: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at_source: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Detection information
    rule_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rule_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Enrichment and classification
    tags: Mapped[list] = mapped_column(JSON, default=list)
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)

    # Raw data preserved for reference
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # Local timestamps
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('ix_normalized_alerts_org_connector', 'organization_id', 'connector_id'),
        Index('ix_normalized_alerts_org_external', 'organization_id', 'external_id'),
    )


# ==================== WORKFLOW ENGINE MODELS ====================

class Workflow(Base):
    """
    Visual workflow definition with Tines-like automation capabilities.
    Supports drag-and-drop builder with branching, loops, and templating.
    """
    __tablename__ = "workflows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[WorkflowStatus] = mapped_column(SQLEnum(WorkflowStatus), default=WorkflowStatus.DRAFT)

    # Trigger configuration
    trigger_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # alert, schedule, webhook, manual
    trigger_config: Mapped[dict] = mapped_column(JSON, default=dict)  # Trigger-specific config

    # React Flow viewport state
    viewport: Mapped[dict] = mapped_column(JSON, default=lambda: {"x": 0, "y": 0, "zoom": 1})

    # Versioning
    version: Mapped[int] = mapped_column(Integer, default=1)

    # Tags for organization
    tags: Mapped[list] = mapped_column(JSON, default=list)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkflowNode(Base):
    """
    Individual node in a workflow graph.
    Represents triggers, actions, conditions, transforms, loops, etc.
    Note: organization_id is derived from workflow relationship.
    """
    __tablename__ = "workflow_nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    node_key: Mapped[str] = mapped_column(String(100), nullable=False)  # Unique key within workflow, e.g., "step_1"
    node_type: Mapped[NodeType] = mapped_column(SQLEnum(NodeType), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)  # Display label

    # Position in React Flow canvas
    position_x: Mapped[float] = mapped_column(default=0.0)
    position_y: Mapped[float] = mapped_column(default=0.0)

    # Type-specific configuration (JSON)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Error handling
    on_error: Mapped[str] = mapped_column(String(50), default="fail")  # fail, continue, goto_node
    error_handler_node: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Node key to goto on error

    # Timeout
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('ix_workflow_nodes_workflow_key', 'workflow_id', 'node_key', unique=True),
    )


class WorkflowEdge(Base):
    """
    Connection between workflow nodes defining execution flow.
    Supports conditional branching with source handles (true/false, loop_item/loop_complete).
    Note: organization_id is derived from workflow relationship.
    """
    __tablename__ = "workflow_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    source_node_key: Mapped[str] = mapped_column(String(100), nullable=False)
    source_handle: Mapped[str] = mapped_column(String(50), default="default")  # default, true, false, loop_item, loop_complete
    target_node_key: Mapped[str] = mapped_column(String(100), nullable=False)

    # Optional condition expression for conditional edges
    condition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Edge styling/metadata
    label: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class WorkflowExecution(Base):
    """
    Execution instance of a workflow.
    Tracks overall status, trigger data, and accumulated context.
    """
    __tablename__ = "workflow_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    workflow_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    workflow_version: Mapped[int] = mapped_column(Integer, default=1)  # Version at time of execution
    status: Mapped[WorkflowExecutionStatus] = mapped_column(
        SQLEnum(WorkflowExecutionStatus), default=WorkflowExecutionStatus.PENDING
    )

    # Trigger data that initiated the workflow
    trigger_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # Accumulated execution context (all step outputs)
    context: Mapped[dict] = mapped_column(JSON, default=dict)

    # Workflow variables
    variables: Mapped[dict] = mapped_column(JSON, default=dict)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failed_node_key: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class WorkflowStepExecution(Base):
    """
    Execution record for individual workflow step/node.
    Tracks inputs, outputs, timing, and errors for each step.
    Note: organization_id is derived from execution relationship.
    """
    __tablename__ = "workflow_step_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workflow_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    node_key: Mapped[str] = mapped_column(String(100), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Execution status
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # pending, running, completed, failed, skipped

    # I/O data
    input_data: Mapped[dict] = mapped_column(JSON, default=dict)
    output_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Loop tracking
    loop_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    loop_item: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
