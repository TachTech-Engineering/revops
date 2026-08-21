import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, validates

from app.core.time_utils import utcnow


class Base(DeclarativeBase):
    pass


class UserRoleType(enum.StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class SSOProvider(enum.StrEnum):
    GOOGLE = "google"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    SAML = "saml"  # Generic SAML 2.0


class ReportFrequency(enum.StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class WebhookType(enum.StrEnum):
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


class PlaybookStatus(enum.StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class ExecutionStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


class ActionType(enum.StrEnum):
    WEBHOOK = "webhook"
    JIRA_TICKET = "jira_ticket"
    SERVICENOW_TICKET = "servicenow_ticket"
    UPDATE_ALERT = "update_alert"
    RUN_QUERY = "run_query"
    CROWDSTRIKE_ISOLATE = "crowdstrike_isolate"
    SENTINELONE_ISOLATE = "sentinelone_isolate"
    FIREWALL_BLOCK = "firewall_block"
    SOAR_TRIGGER = "soar_trigger"


class IncidentStatus(enum.StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CaseStatus(enum.StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CaseActivityType(enum.StrEnum):
    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    PRIORITY_CHANGED = "priority_changed"
    ASSIGNEE_CHANGED = "assignee_changed"
    COMMENT_ADDED = "comment_added"
    INCIDENT_LINKED = "incident_linked"
    INCIDENT_UNLINKED = "incident_unlinked"
    ATTACHMENT_ADDED = "attachment_added"
    UPDATED = "updated"


class EnrichmentType(enum.StrEnum):
    IP_GEOLOCATION = "ip_geolocation"
    IP_REPUTATION = "ip_reputation"
    DOMAIN_WHOIS = "domain_whois"
    DOMAIN_REPUTATION = "domain_reputation"
    FILE_HASH = "file_hash"
    USER_LOOKUP = "user_lookup"
    ASSET_LOOKUP = "asset_lookup"
    CUSTOM_API = "custom_api"


class WidgetType(enum.StrEnum):
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


class MitreTactic(enum.StrEnum):
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


class SLAStatus(enum.StrEnum):
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
    settings: Mapped[dict | None] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="organization")
    sso_configs: Mapped[list["OrganizationSSO"]] = relationship(
        "OrganizationSSO", back_populates="organization", cascade="all, delete-orphan"
    )


class OrganizationSSO(Base):
    """
    Per-organization SSO configuration.
    Allows each tenant to configure their own identity provider.
    """

    __tablename__ = "organization_sso"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[SSOProvider] = mapped_column(SQLEnum(SSOProvider), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Display name for the login button (e.g., "Sign in with Acme Corp")
    display_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # OAuth2/OIDC Configuration (encrypted credentials stored separately)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret_encrypted: Mapped[bytes] = mapped_column(nullable=False)  # Fernet encrypted

    # Provider-specific settings
    # For Okta: domain (e.g., "acme.okta.com")
    # For Azure AD: tenant_id
    # For SAML: metadata_url or entity_id
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # SAML-specific fields
    metadata_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sso_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate: Mapped[str | None] = mapped_column(Text, nullable=True)  # PEM format, encrypted
    # Additional SAML settings as JSON
    # (idp_entity_id, idp_sso_url, idp_slo_url, idp_x509_cert, etc.)
    saml_settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Email domain restrictions (comma-separated, e.g., "acme.com,acme.org")
    # If set, only users with these email domains can use this SSO
    allowed_email_domains: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # Auto-provisioning settings
    auto_create_users: Mapped[bool] = mapped_column(Boolean, default=True)
    default_role: Mapped[UserRoleType] = mapped_column(
        SQLEnum(UserRoleType), default=UserRoleType.VIEWER
    )

    # Audit
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="sso_configs"
    )

    __table_args__ = (
        # Each org can only have one config per provider
        Index("ix_org_sso_org_provider", "organization_id", "provider", unique=True),
    )


class OrganizationAPIKeys(Base):
    """
    Per-organization API key storage for LLM providers.
    Allows each tenant to configure their own API keys.
    Keys are encrypted using Fernet symmetric encryption.
    """

    __tablename__ = "organization_api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Provider name (e.g., "openai", "anthropic")
    provider: Mapped[str] = mapped_column(String(50), nullable=False)

    # Encrypted API key (Fernet encrypted)
    api_key_encrypted: Mapped[bytes] = mapped_column(nullable=False)

    # Optional model override (if not set, uses system default)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Key status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Audit
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        # Each org can only have one key per provider
        Index("ix_org_api_keys_org_provider", "organization_id", "provider", unique=True),
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Nullable for SSO-only users
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRoleType] = mapped_column(SQLEnum(UserRoleType), default=UserRoleType.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )

    # SSO fields
    sso_provider: Mapped[SSOProvider | None] = mapped_column(SQLEnum(SSOProvider), nullable=True)
    sso_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Provider's unique user ID

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization", back_populates="users"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User")


class PasswordResetToken(Base):
    """Password reset tokens.

    Previously these lived in a module-level dict, which is wrong in two ways
    once there is more than one replica: a token minted on pod A is rejected by
    pod B, and every token is lost on restart. Only the hash is stored, so a
    database read does not yield a usable token.
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Single-use: set the moment the token is redeemed.
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped["User"] = relationship("User")


class FalcoIngestEvent(Base):
    """Falco alerts received on the ingest webhook, awaiting the sync cycle.

    These were held in a process-global in-memory deque. The ingest endpoint
    answers 202 Accepted immediately, so with multiple replicas any pod restart
    between the webhook call and the next sync silently discarded accepted
    runtime-security alerts.

    Claim semantics are at-least-once: ``claimed_at`` is stamped when a sync
    picks a row up, and a claim older than FALCO_CLAIM_STALE_MINUTES is
    re-claimable so a crashed sync recovers instead of losing events. That is
    safe because the Falco connector derives ``external_id`` from a content
    fingerprint, so a re-processed event collides with
    ``uq_normalized_alerts_org_connector_external`` and is dropped rather than
    duplicated.
    """

    __tablename__ = "falco_ingest_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connectors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        # The drain orders by received_at within a connector and filters on
        # claimed_at, so index the three together.
        Index(
            "ix_falco_ingest_events_connector_claim",
            "connector_id",
            "claimed_at",
            "received_at",
        ),
    )


class OrganizationTelephonyConfig(Base):
    """Per-organization telephony (Fonoster) configuration.

    This was a process-global singleton, so one tenant saving their carrier
    credentials overwrote another's and escalation calls dialled out under the
    wrong account. Mirrors OrganizationAPIKeys: secret encrypted at rest, one
    row per organization.
    """

    __tablename__ = "organization_telephony_config"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    api_endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    access_key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # Fernet-encrypted; never returned by the API.
    access_key_secret_encrypted: Mapped[bytes] = mapped_column(nullable=False)
    default_caller_id: Mapped[str] = mapped_column(String(50), nullable=False)
    tts_voice: Mapped[str] = mapped_column(String(50), default="en-US-Standard-A")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (Index("ix_org_telephony_org", "organization_id", unique=True),)


# ==================== Tenant-Scoped Models ====================
# All models below include organization_id for multi-tenancy


class SavedQuery(Base):
    __tablename__ = "saved_queries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sql: Mapped[str] = mapped_column(Text, nullable=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(255), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # alert_summary, sla_metrics, etc.
    frequency: Mapped[ReportFrequency] = mapped_column(
        SQLEnum(ReportFrequency), default=ReportFrequency.DAILY
    )
    recipients: Mapped[list] = mapped_column(JSON, default=list)  # List of email addresses
    filters: Mapped[dict] = mapped_column(JSON, default=dict)  # Report-specific filters
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Specific rule to suppress
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)  # Suppress by severity
    title_pattern: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )  # Regex pattern for title
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class UserSettings(Base):
    __tablename__ = "user_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    theme: Mapped[str] = mapped_column(String(20), default="dark")
    default_time_range: Mapped[int] = mapped_column(Integer, default=7)  # Days
    alerts_per_page: Mapped[int] = mapped_column(Integer, default=50)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notification_severities: Mapped[list] = mapped_column(
        JSON, default=lambda: ["CRITICAL", "HIGH"]
    )
    keyboard_shortcuts_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    webhook_type: Mapped[WebhookType] = mapped_column(
        SQLEnum(WebhookType), default=WebhookType.GENERIC
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    severity_filter: Mapped[list] = mapped_column(JSON, default=lambda: ["CRITICAL", "HIGH"])
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class UserRole(Base):
    """Legacy role assignment - prefer using User.role instead"""

    __tablename__ = "user_roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRoleType] = mapped_column(SQLEnum(UserRoleType), default=UserRoleType.VIEWER)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (Index("ix_user_roles_org_email", "organization_id", "email", unique=True),)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_conditions: Mapped[dict] = mapped_column(JSON, default=dict)  # severity, rule_id, etc.
    actions: Mapped[list] = mapped_column(JSON, default=list)  # List of action configs
    status: Mapped[PlaybookStatus] = mapped_column(
        SQLEnum(PlaybookStatus), default=PlaybookStatus.DRAFT
    )
    auto_execute: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    playbook_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ExecutionStatus] = mapped_column(
        SQLEnum(ExecutionStatus), default=ExecutionStatus.PENDING
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    action_results: Mapped[list] = mapped_column(JSON, default=list)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(
        SQLEnum(IncidentStatus), default=IncidentStatus.OPEN
    )
    severity: Mapped[IncidentSeverity] = mapped_column(
        SQLEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM
    )
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    added_by: Mapped[str] = mapped_column(String(255), default="system")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)  # time_window, field_matches, etc.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_create_incident: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    case_number: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(SQLEnum(CaseStatus), default=CaseStatus.OPEN)
    priority: Mapped[CasePriority] = mapped_column(
        SQLEnum(CasePriority), default=CasePriority.MEDIUM
    )
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    incident_ids: Mapped[list] = mapped_column(JSON, default=list)  # Linked incidents
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (Index("ix_cases_org_number", "organization_id", "case_number", unique=True),)


class CaseActivity(Base):
    __tablename__ = "case_activities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    activity_type: Mapped[CaseActivityType] = mapped_column(
        SQLEnum(CaseActivityType), nullable=False
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EnrichmentPipeline(Base):
    __tablename__ = "enrichment_pipelines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enrichment_type: Mapped[EnrichmentType] = mapped_column(SQLEnum(EnrichmentType), nullable=False)
    source_field: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # Field to extract value from alert
    target_field: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # Field to store enrichment result
    api_endpoint: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # For custom API enrichments
    api_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    api_key_env: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Environment variable for API key
    cache_ttl_minutes: Mapped[int] = mapped_column(Integer, default=60)  # Cache duration
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_enrich: Mapped[bool] = mapped_column(Boolean, default=False)  # Auto-run on new alerts
    severity_filter: Mapped[list] = mapped_column(
        JSON, default=list
    )  # Only enrich alerts with these severities
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    pipeline_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    input_value: Mapped[str] = mapped_column(
        String(1000), nullable=False
    )  # The value that was enriched
    input_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # SHA256 of input for lookup
    result: Mapped[dict] = mapped_column(JSON, default=dict)  # Enrichment result
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CustomDashboard(Base):
    __tablename__ = "custom_dashboards"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    layout: Mapped[list] = mapped_column(JSON, default=list)  # react-grid-layout format
    widgets: Mapped[list] = mapped_column(JSON, default=list)  # Widget configurations
    owner_email: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


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
    subtechnique_id: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # e.g., T1059.001
    subtechnique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tactic: Mapped[MitreTactic] = mapped_column(SQLEnum(MitreTactic), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class SLAPolicy(Base):
    __tablename__ = "sla_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


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
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # SLA targets (copied from policy at creation time)
    ack_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    resolve_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    # SLA status
    ack_status: Mapped[SLAStatus] = mapped_column(SQLEnum(SLAStatus), default=SLAStatus.ON_TRACK)
    resolve_status: Mapped[SLAStatus] = mapped_column(
        SQLEnum(SLAStatus), default=SLAStatus.ON_TRACK
    )
    # Actual times (in minutes)
    ack_time_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolve_time_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class NoteResourceType(enum.StrEnum):
    ALERT = "alert"
    INCIDENT = "incident"
    CASE = "case"
    RULE = "rule"


class NotificationType(enum.StrEnum):
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
class IOCType(enum.StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"


class IOCSeverity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Phase 5: Threat Feed Types
class FeedType(enum.StrEnum):
    OTX = "otx"
    ABUSECH_FEODO = "abusech_feodo"
    ABUSECH_URLHAUS = "abusech_urlhaus"
    CUSTOM_CSV = "custom_csv"
    CUSTOM_STIX = "custom_stix"


class FeedStatus(enum.StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"


# Phase 5: Simulation Types
class SimulationFramework(enum.StrEnum):
    ATOMIC_RED_TEAM = "atomic"
    STRATUS_RED_TEAM = "stratus"


class SimulationStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# Phase 5: Recommendation Status
class RecommendationStatus(enum.StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"


# Phase 5: LLM Provider
class LLMProvider(enum.StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


# ==================== CONNECTOR FRAMEWORK ENUMS ====================


class ConnectorCategory(enum.StrEnum):
    DATA_SOURCE = "data_source"  # Ingest alerts/detections
    ACTION = "action"  # Execute response actions


class DataSourceCategory(enum.StrEnum):
    """Categories for data source connectors."""

    SIEM = "siem"  # Security Information & Event Management
    EDR = "edr"  # Endpoint Detection & Response
    XDR = "xdr"  # Extended Detection & Response
    CLOUD_SECURITY = "cloud_security"  # Cloud Security Posture Management
    VULNERABILITY = "vulnerability"  # Vulnerability / workload scanning
    IDENTITY = "identity"  # Identity & Access Management
    EMAIL_SECURITY = "email_security"  # Email Security Gateways
    NETWORK = "network"  # Network Detection & Response


class ConnectorStatus(enum.StrEnum):
    CONNECTED = "connected"
    ERROR = "error"
    DISABLED = "disabled"
    PENDING = "pending"


class DataSourceType(enum.StrEnum):
    # SIEM
    PANTHER = "panther"
    GOOGLE_SECOPS = "google_secops"
    SPLUNK = "splunk"
    MICROSOFT_SENTINEL = "sentinel"
    ELASTIC_SECURITY = "elastic"
    SUMO_LOGIC = "sumo_logic"
    # EDR
    CROWDSTRIKE_FALCON = "crowdstrike_falcon"
    MICROSOFT_DEFENDER = "microsoft_defender"
    CARBON_BLACK = "carbon_black"
    SENTINELONE_EDR = "sentinelone_edr"
    # XDR
    CORTEX_XDR = "cortex_xdr"
    TREND_VISION_ONE = "trend_vision_one"
    # Cloud Security
    AWS_SECURITY_HUB = "aws_security_hub"
    AWS_GUARDDUTY = "aws_guardduty"
    GCP_SECURITY_COMMAND_CENTER = "gcp_scc"
    AZURE_DEFENDER = "azure_defender"
    WIZ = "wiz"
    ORCA = "orca"
    PROWLER = "prowler"
    # Runtime Security
    FALCO = "falco"
    # Vulnerability Management
    TRIVY = "trivy"
    # Identity
    OKTA = "okta"
    AZURE_AD_IDENTITY = "azure_ad_identity"
    CROWDSTRIKE_IDENTITY = "crowdstrike_identity"
    # Email Security
    PROOFPOINT = "proofpoint"
    MIMECAST = "mimecast"
    MICROSOFT_DEFENDER_EMAIL = "microsoft_defender_email"
    # Network
    DARKTRACE = "darktrace"
    VECTRA = "vectra"


# Mapping of data source types to their categories
DATA_SOURCE_CATEGORIES: dict[DataSourceType, DataSourceCategory] = {
    # SIEM
    DataSourceType.PANTHER: DataSourceCategory.SIEM,
    DataSourceType.GOOGLE_SECOPS: DataSourceCategory.SIEM,
    DataSourceType.SPLUNK: DataSourceCategory.SIEM,
    DataSourceType.MICROSOFT_SENTINEL: DataSourceCategory.SIEM,
    DataSourceType.ELASTIC_SECURITY: DataSourceCategory.SIEM,
    DataSourceType.SUMO_LOGIC: DataSourceCategory.SIEM,
    # EDR
    DataSourceType.CROWDSTRIKE_FALCON: DataSourceCategory.EDR,
    DataSourceType.MICROSOFT_DEFENDER: DataSourceCategory.EDR,
    DataSourceType.CARBON_BLACK: DataSourceCategory.EDR,
    DataSourceType.SENTINELONE_EDR: DataSourceCategory.EDR,
    # XDR
    DataSourceType.CORTEX_XDR: DataSourceCategory.XDR,
    DataSourceType.TREND_VISION_ONE: DataSourceCategory.XDR,
    # Cloud Security
    DataSourceType.AWS_SECURITY_HUB: DataSourceCategory.CLOUD_SECURITY,
    DataSourceType.AWS_GUARDDUTY: DataSourceCategory.CLOUD_SECURITY,
    DataSourceType.GCP_SECURITY_COMMAND_CENTER: DataSourceCategory.CLOUD_SECURITY,
    DataSourceType.AZURE_DEFENDER: DataSourceCategory.CLOUD_SECURITY,
    DataSourceType.WIZ: DataSourceCategory.CLOUD_SECURITY,
    DataSourceType.ORCA: DataSourceCategory.CLOUD_SECURITY,
    DataSourceType.PROWLER: DataSourceCategory.CLOUD_SECURITY,
    # Runtime Security (Falco watches host/container behavior, closest to EDR)
    DataSourceType.FALCO: DataSourceCategory.EDR,
    # Vulnerability Management
    DataSourceType.TRIVY: DataSourceCategory.VULNERABILITY,
    # Identity
    DataSourceType.OKTA: DataSourceCategory.IDENTITY,
    DataSourceType.AZURE_AD_IDENTITY: DataSourceCategory.IDENTITY,
    DataSourceType.CROWDSTRIKE_IDENTITY: DataSourceCategory.IDENTITY,
    # Email Security
    DataSourceType.PROOFPOINT: DataSourceCategory.EMAIL_SECURITY,
    DataSourceType.MIMECAST: DataSourceCategory.EMAIL_SECURITY,
    DataSourceType.MICROSOFT_DEFENDER_EMAIL: DataSourceCategory.EMAIL_SECURITY,
    # Network
    DataSourceType.DARKTRACE: DataSourceCategory.NETWORK,
    DataSourceType.VECTRA: DataSourceCategory.NETWORK,
}


class ActionConnectorType(enum.StrEnum):
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


class WorkflowStatus(enum.StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    INACTIVE = "inactive"


class NodeType(enum.StrEnum):
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


class WorkflowExecutionStatus(enum.StrEnum):
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
    resource_type: Mapped[NoteResourceType] = mapped_column(
        SQLEnum(NoteResourceType), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    mentions: Mapped[list] = mapped_column(JSON, default=list)  # List of mentioned user emails
    is_edited: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )  # For replies
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    notification_type: Mapped[NotificationType] = mapped_column(
        SQLEnum(NotificationType), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # Who triggered the notification
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    feed_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


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
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


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
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    confidence_score: Mapped[float] = mapped_column(default=0.8)
    status: Mapped[RecommendationStatus] = mapped_column(
        SQLEnum(RecommendationStatus), default=RecommendationStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class RuleRecommendationDismissal(Base):
    __tablename__ = "rule_recommendation_dismissals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    recommendation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    dismissed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    dismissed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# Phase 5: Attack Simulation Models
class SimulationTemplate(Base):
    __tablename__ = "simulation_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Note: SimulationTemplate is system-wide (catalog), not per-org
    framework: Mapped[SimulationFramework] = mapped_column(
        SQLEnum(SimulationFramework), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True
    )  # e.g., atomic-T1003-0
    mitre_technique_id: Mapped[str | None] = mapped_column(String(50), nullable=True)  # e.g., T1003
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_tactic: Mapped[str] = mapped_column(String(100), nullable=False, default="Unknown")
    mitre_technique: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    platforms: Mapped[list] = mapped_column(
        JSON, default=list
    )  # windows, linux, macos, aws, azure, gcp
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Atomic Red Team specific fields
    executor_type: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )  # powershell, cmd, bash, sh, manual
    executor_command: Mapped[str | None] = mapped_column(Text, nullable=True)  # Command to execute
    executor_cleanup: Mapped[str | None] = mapped_column(Text, nullable=True)  # Cleanup command
    input_arguments: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # Input arguments with defaults
    dependencies: Mapped[list] = mapped_column(JSON, default=list)  # Dependencies to check

    # Stratus Red Team specific fields
    cloud_provider: Mapped[str | None] = mapped_column(String(20), nullable=True)  # aws, azure, gcp
    cloud_permissions: Mapped[list] = mapped_column(JSON, default=list)  # Required IAM permissions
    detonation_command: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # Stratus detonation
    cleanup_command: Mapped[str | None] = mapped_column(Text, nullable=True)  # Stratus cleanup

    # General fields
    test_data: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # Additional framework-specific data
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[SimulationStatus] = mapped_column(
        SQLEnum(SimulationStatus), default=SimulationStatus.PENDING
    )
    targets: Mapped[list] = mapped_column(JSON, default=list)  # List of target identifiers
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    detection_expected: Mapped[bool] = mapped_column(Boolean, default=True)
    detection_found: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SimulationResult(Base):
    __tablename__ = "simulation_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    detection_details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[ConnectorCategory] = mapped_column(SQLEnum(ConnectorCategory), nullable=False)
    connector_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # e.g., "panther", "jira", "slack"
    status: Mapped[ConnectorStatus] = mapped_column(
        SQLEnum(ConnectorStatus), default=ConnectorStatus.PENDING
    )

    # Encrypted credentials (use Fernet encryption)
    credentials_encrypted: Mapped[bytes | None] = mapped_column(nullable=True)

    # Non-sensitive configuration (JSON)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Health tracking
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # For data sources: sync configuration
    sync_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=5)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sync_cursor: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )  # Pagination cursor

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


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
    source_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # panther, splunk, sentinel, etc.
    external_id: Mapped[str] = mapped_column(
        String(500), nullable=False
    )  # Original alert ID from source

    # Normalized fields (consistent across all sources)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # critical, high, medium, low, info
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # open, acknowledged, resolved, closed

    # Timestamps from source
    created_at_source: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at_source: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Detection information
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Enrichment and classification (using JSONB for better PostgreSQL support)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # Raw data preserved for reference
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # Local timestamps
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_normalized_alerts_org_connector", "organization_id", "connector_id"),
        Index("ix_normalized_alerts_org_external", "organization_id", "external_id"),
        # The connector sync does a check-then-insert, so two overlapping syncs
        # of the same connector both miss the check and insert the same alert.
        # The database is the only place that race can actually be settled.
        Index(
            "uq_normalized_alerts_org_connector_external",
            "organization_id",
            "connector_id",
            "external_id",
            unique=True,
        ),
    )

    @validates("source_type", "external_id", "title", "severity", "status", "rule_id", "rule_name")
    def _clamp_to_column_width(self, key: str, value: str | None) -> str | None:
        # These fields carry unbounded external SIEM data (Panther alert titles
        # routinely embed full command lines and exceed 500 chars, and the
        # connectors reuse the title as rule_name); over-long values otherwise
        # abort the whole sync batch with StringDataRightTruncationError. The
        # untruncated original is always preserved in raw_data.
        if isinstance(value, str):
            limit = getattr(type(self).__table__.columns[key].type, "length", None)
            if limit is not None and len(value) > limit:
                return value[:limit]
        return value


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
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[WorkflowStatus] = mapped_column(
        SQLEnum(WorkflowStatus), default=WorkflowStatus.DRAFT
    )

    # Trigger configuration
    trigger_type: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )  # alert, schedule, webhook, manual
    trigger_config: Mapped[dict] = mapped_column(JSON, default=dict)  # Trigger-specific config

    # React Flow viewport state
    viewport: Mapped[dict] = mapped_column(JSON, default=lambda: {"x": 0, "y": 0, "zoom": 1})

    # Versioning
    version: Mapped[int] = mapped_column(Integer, default=1)

    # Tags for organization
    tags: Mapped[list] = mapped_column(JSON, default=list)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class WorkflowNode(Base):
    """
    Individual node in a workflow graph.
    Represents triggers, actions, conditions, transforms, loops, etc.
    Note: organization_id is derived from workflow relationship.
    """

    __tablename__ = "workflow_nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_key: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # Unique key within workflow, e.g., "step_1"
    node_type: Mapped[NodeType] = mapped_column(SQLEnum(NodeType), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)  # Display label

    # Position in React Flow canvas
    position_x: Mapped[float] = mapped_column(default=0.0)
    position_y: Mapped[float] = mapped_column(default=0.0)

    # Type-specific configuration (JSON)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Error handling
    on_error: Mapped[str] = mapped_column(String(50), default="fail")  # fail, continue, goto_node
    error_handler_node: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )  # Node key to goto on error

    # Timeout
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_workflow_nodes_workflow_key", "workflow_id", "node_key", unique=True),
    )


class WorkflowEdge(Base):
    """
    Connection between workflow nodes defining execution flow.
    Supports conditional branching with source handles (true/false, loop_item/loop_complete).
    Note: organization_id is derived from workflow relationship.
    """

    __tablename__ = "workflow_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_node_key: Mapped[str] = mapped_column(String(100), nullable=False)
    source_handle: Mapped[str] = mapped_column(
        String(50), default="default"
    )  # default, true, false, loop_item, loop_complete
    target_node_key: Mapped[str] = mapped_column(String(100), nullable=False)

    # Optional condition expression for conditional edges
    condition: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Edge styling/metadata
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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
    workflow_version: Mapped[int] = mapped_column(
        Integer, default=1
    )  # Version at time of execution
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
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    failed_node_key: Mapped[str | None] = mapped_column(String(100), nullable=True)

    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WorkflowStepExecution(Base):
    """
    Execution record for individual workflow step/node.
    Tracks inputs, outputs, timing, and errors for each step.
    Note: organization_id is derived from execution relationship.
    """

    __tablename__ = "workflow_step_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workflow_executions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_key: Mapped[str] = mapped_column(String(100), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Execution status
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # pending, running, completed, failed, skipped

    # I/O data
    input_data: Mapped[dict] = mapped_column(JSON, default=dict)
    output_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Loop tracking
    loop_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    loop_item: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ==================== DATA PIPELINE ENUMS ====================


class PipelineStatus(enum.StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class StageType(enum.StrEnum):
    # Transform stages
    OCSF_TRANSFORM = "ocsf_transform"
    FIELD_MAPPER = "field_mapper"
    PARSE_JSON = "parse_json"
    # Filter stages
    CONDITION_FILTER = "condition_filter"
    SAMPLE = "sample"
    DEDUPE = "dedupe"
    # Route stages
    ROUTE = "route"


class StageCategory(enum.StrEnum):
    TRANSFORM = "transform"
    FILTER = "filter"
    ROUTE = "route"


class PipelineExecutionStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DestinationType(enum.StrEnum):
    DATABASE = "database"
    S3 = "s3"
    WEBHOOK = "webhook"
    KAFKA = "kafka"
    DISCARD = "discard"


# ==================== DATA PIPELINE MODELS ====================


class Pipeline(Base):
    """
    Data Pipeline for processing raw log data through configurable stages.
    Transform → Filter → Route pipeline architecture.
    """

    __tablename__ = "pipelines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[PipelineStatus] = mapped_column(
        SQLEnum(PipelineStatus), default=PipelineStatus.DRAFT
    )

    # Source configuration
    source_connector_ids: Mapped[list] = mapped_column(
        JSON, default=list
    )  # Which connectors feed this
    source_log_types: Mapped[list] = mapped_column(JSON, default=list)  # Filter by log type

    # React Flow viewport state
    viewport: Mapped[dict] = mapped_column(JSON, default=lambda: {"x": 0, "y": 0, "zoom": 1})

    # Processing settings
    batch_size: Mapped[int] = mapped_column(Integer, default=1000)

    # Metrics cache (updated periodically)
    events_last_24h: Mapped[int] = mapped_column(Integer, default=0)
    reduction_percentage: Mapped[float] = mapped_column(default=0.0)
    avg_processing_ms: Mapped[float] = mapped_column(default=0.0)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    stages: Mapped[list["PipelineStage"]] = relationship(
        "PipelineStage", back_populates="pipeline", cascade="all, delete-orphan"
    )
    edges: Mapped[list["PipelineEdge"]] = relationship(
        "PipelineEdge", back_populates="pipeline", cascade="all, delete-orphan"
    )


class PipelineStage(Base):
    """
    Individual stage in a data pipeline.
    Represents transform, filter, or route operations.
    """

    __tablename__ = "pipeline_stages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pipelines.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    node_key: Mapped[str] = mapped_column(String(100), nullable=False)  # React Flow node ID
    stage_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # e.g., ocsf_transform, condition_filter
    category: Mapped[StageCategory] = mapped_column(SQLEnum(StageCategory), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)

    # Position in React Flow canvas
    position_x: Mapped[float] = mapped_column(default=0.0)
    position_y: Mapped[float] = mapped_column(default=0.0)

    # Stage-specific configuration
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Multiple output handles (for route stages)
    output_handles: Mapped[list] = mapped_column(
        JSON, default=list
    )  # [{"id": "match", "label": "Match"}, ...]

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationship
    pipeline: Mapped["Pipeline"] = relationship("Pipeline", back_populates="stages")

    __table_args__ = (
        Index("ix_pipeline_stages_pipeline_key", "pipeline_id", "node_key", unique=True),
    )


class PipelineEdge(Base):
    """
    Connection between pipeline stages defining data flow.
    """

    __tablename__ = "pipeline_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pipelines.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source_node_key: Mapped[str] = mapped_column(String(100), nullable=False)
    source_handle: Mapped[str] = mapped_column(String(50), default="default")
    target_node_key: Mapped[str] = mapped_column(String(100), nullable=False)

    # Optional condition for conditional routing
    condition: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationship
    pipeline: Mapped["Pipeline"] = relationship("Pipeline", back_populates="edges")


class PipelineDestination(Base):
    """
    Destination configuration for pipeline output routing.
    """

    __tablename__ = "pipeline_destinations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination_type: Mapped[DestinationType] = mapped_column(
        SQLEnum(DestinationType), nullable=False
    )
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    credentials_encrypted: Mapped[bytes | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class PipelineExecution(Base):
    """
    Execution record for a pipeline run.
    Tracks metrics and status for each execution.
    """

    __tablename__ = "pipeline_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    pipeline_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    status: Mapped[PipelineExecutionStatus] = mapped_column(
        SQLEnum(PipelineExecutionStatus), default=PipelineExecutionStatus.PENDING
    )

    # Metrics
    events_received: Mapped[int] = mapped_column(Integer, default=0)
    events_output: Mapped[int] = mapped_column(Integer, default=0)
    events_filtered: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    bytes_output: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ==================== FEATURE 1: RULE VERSION HISTORY ====================


class RuleChangeType(enum.StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    ENABLED = "enabled"
    DISABLED = "disabled"
    DELETED = "deleted"


class RuleVersion(Base):
    """
    Tracks version history for detection rules.
    Stores complete snapshots for rollback capability.
    """

    __tablename__ = "rule_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    change_type: Mapped[RuleChangeType] = mapped_column(SQLEnum(RuleChangeType), nullable=False)

    # Full rule snapshot for rollback
    rule_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Changed fields for quick diff reference
    changed_fields: Mapped[list] = mapped_column(JSON, default=list)

    # AI-generated change summary
    change_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    changed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index(
            "ix_rule_versions_rule_version", "organization_id", "rule_id", "version", unique=True
        ),
    )


# ==================== FEATURE 2: STALE RULE DETECTION ====================


class RuleHealth(Base):
    """
    Tracks health metrics for detection rules.
    Used for stale rule detection and health monitoring.
    """

    __tablename__ = "rule_health"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False)

    # Trigger statistics
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    trigger_count_7d: Mapped[int] = mapped_column(Integer, default=0)
    trigger_count_30d: Mapped[int] = mapped_column(Integer, default=0)
    trigger_count_90d: Mapped[int] = mapped_column(Integer, default=0)

    # Health assessment
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False)
    health_score: Mapped[float] = mapped_column(default=100.0)  # 0-100 score
    stale_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Rule metadata
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    owner_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    last_checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (Index("ix_rule_health_org_rule", "organization_id", "rule_id", unique=True),)


# ==================== FEATURE 3: AUTO-TRIAGE SUGGESTIONS ====================


class TriageSuggestion(Base):
    """
    AI-generated triage suggestions for alerts.
    Includes severity/priority recommendations with confidence scores.
    """

    __tablename__ = "triage_suggestions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Suggestions
    suggested_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    suggested_priority: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence_score: Mapped[float] = mapped_column(nullable=False)  # 0.0-1.0

    # AI reasoning
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    contributing_factors: Mapped[list] = mapped_column(JSON, default=list)

    # Feedback tracking
    was_accepted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    feedback_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    feedback_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AssetCriticality(Base):
    """
    Asset importance rules for triage prioritization.
    Matches by hostname, IP, user, service patterns.
    """

    __tablename__ = "asset_criticality"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Matching criteria (regex patterns)
    match_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # hostname, ip, user, service
    match_pattern: Mapped[str] = mapped_column(String(500), nullable=False)

    # Criticality level (1-10, 10 being most critical)
    criticality_level: Mapped[int] = mapped_column(Integer, nullable=False)

    # Optional business context
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    data_classification: Mapped[str | None] = mapped_column(String(100), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


# ==================== FEATURE 4: NATURAL LANGUAGE QUERIES ====================


class NLQueryHistory(Base):
    """
    History of natural language queries and their translations.
    Used for learning and improving query translations.
    """

    __tablename__ = "nl_query_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Query details
    natural_query: Mapped[str] = mapped_column(Text, nullable=False)
    generated_sql: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Execution details
    was_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Feedback for learning
    was_helpful: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    feedback_comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ==================== FEATURE 5: AI ALERT CLUSTERING ====================


class AlertClusterStatus(enum.StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AlertCluster(Base):
    """
    Groups similar alerts to reduce analyst fatigue.
    AI-generated cluster with summary and metadata.
    """

    __tablename__ = "alert_clusters"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Cluster metadata
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[AlertClusterStatus] = mapped_column(
        SQLEnum(AlertClusterStatus), default=AlertClusterStatus.OPEN
    )

    # Clustering criteria
    primary_rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cluster_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # rule_based, entity_based, time_based

    # Statistics
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    first_alert_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_alert_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Common entities across alerts
    common_entities: Mapped[dict] = mapped_column(JSON, default=dict)

    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class AlertClusterMember(Base):
    """
    Links alerts to clusters with similarity score.
    """

    __tablename__ = "alert_cluster_members"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_clusters.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    similarity_score: Mapped[float] = mapped_column(nullable=False)  # 0.0-1.0
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_cluster_members_cluster_alert", "cluster_id", "alert_id", unique=True),
    )


# ==================== FEATURE 6: AI PLAYBOOK GENERATION ====================


class PlaybookTemplate(Base):
    """
    AI-generated playbook templates from incident resolution patterns.
    """

    __tablename__ = "playbook_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Template content
    trigger_conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    actions: Mapped[list] = mapped_column(JSON, default=list)

    # AI generation metadata
    confidence_score: Mapped[float] = mapped_column(nullable=False)
    source_incident_count: Mapped[int] = mapped_column(Integer, default=0)
    generated_from_patterns: Mapped[list] = mapped_column(JSON, default=list)

    # Approval status
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Converted to playbook?
    converted_playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class IncidentResolutionPattern(Base):
    """
    Extracted resolution steps from closed incidents.
    Used to train playbook generation.
    """

    __tablename__ = "incident_resolution_patterns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # Pattern metadata
    alert_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Extracted steps
    resolution_steps: Mapped[list] = mapped_column(JSON, default=list)
    time_to_resolve_minutes: Mapped[int] = mapped_column(Integer, nullable=False)

    # For pattern matching
    pattern_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


# ==================== FEATURE 7: ESCALATION POLICIES ====================


class EscalationNotificationType(enum.StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PHONE_CALL = "phone_call"
    SMS = "sms"


class EscalationPolicy(Base):
    """
    Time-based escalation chains for unacknowledged alerts.
    """

    __tablename__ = "escalation_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Matching criteria
    severity_filter: Mapped[list] = mapped_column(JSON, default=list)  # Empty = all severities
    rule_filter: Mapped[list] = mapped_column(JSON, default=list)  # Empty = all rules

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Custom message templates for notifications
    # Supports placeholders: {title}, {severity}, {id}, {description}, {rule}, {time}, {source}
    call_message_template: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default="Alert from {source}: {title}. Severity: {severity}. {description}",
    )
    sms_message_template: Mapped[str | None] = mapped_column(
        Text, nullable=True, default="[{source}] {severity} Alert: {title}. ID: {id}"
    )

    # Webhook configuration
    webhook_secret: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # HMAC-SHA256 signing secret
    webhook_headers: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # Custom headers for webhook requests

    # Relationship
    steps: Mapped[list["EscalationStep"]] = relationship(
        "EscalationStep", back_populates="policy", cascade="all, delete-orphan"
    )


class EscalationStep(Base):
    """
    Individual step in an escalation chain.
    """

    __tablename__ = "escalation_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("escalation_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    delay_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False
    )  # Minutes after previous step

    notification_type: Mapped[EscalationNotificationType] = mapped_column(
        SQLEnum(EscalationNotificationType), nullable=False
    )

    # Targets (email addresses, channel IDs, user IDs, etc.)
    targets: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationship
    policy: Mapped["EscalationPolicy"] = relationship("EscalationPolicy", back_populates="steps")

    __table_args__ = (
        Index("ix_escalation_steps_policy_order", "policy_id", "step_order", unique=True),
    )


class EscalationStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class AlertEscalation(Base):
    """
    Tracks active escalations per alert.
    """

    __tablename__ = "alert_escalations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    status: Mapped[EscalationStatus] = mapped_column(
        SQLEnum(EscalationStatus), default=EscalationStatus.PENDING
    )
    current_step: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    next_escalation_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # History of sent notifications
    notification_history: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


# ==================== FEATURE 8: ON-CALL SCHEDULING ====================


# ==================== FEATURE 9: TREND ANALYSIS ====================


class AlertTrendCache(Base):
    """
    Pre-computed trend data by time bucket.
    """

    __tablename__ = "alert_trend_cache"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Time bucket
    bucket_type: Mapped[str] = mapped_column(String(20), nullable=False)  # hourly, daily, weekly
    bucket_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    bucket_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Aggregated metrics
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    by_severity: Mapped[dict] = mapped_column(JSON, default=dict)
    by_status: Mapped[dict] = mapped_column(JSON, default=dict)
    by_rule: Mapped[dict] = mapped_column(JSON, default=dict)

    # Trend indicators
    change_from_previous: Mapped[float | None] = mapped_column(nullable=True)  # Percentage change

    computed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index(
            "ix_trend_cache_org_bucket",
            "organization_id",
            "bucket_type",
            "bucket_start",
            unique=True,
        ),
    )


class AnomalyType(enum.StrEnum):
    VOLUME_SPIKE = "volume_spike"
    VOLUME_DROP = "volume_drop"
    NEW_RULE_ACTIVITY = "new_rule_activity"
    UNUSUAL_PATTERN = "unusual_pattern"
    SEVERITY_SHIFT = "severity_shift"


class AnomalyDetection(Base):
    """
    Detected anomalies in alert patterns.
    """

    __tablename__ = "anomaly_detections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )

    anomaly_type: Mapped[AnomalyType] = mapped_column(SQLEnum(AnomalyType), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Anomaly details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    detected_value: Mapped[float] = mapped_column(nullable=False)
    expected_value: Mapped[float] = mapped_column(nullable=False)
    deviation_percentage: Mapped[float] = mapped_column(nullable=False)

    # Context
    related_rule_ids: Mapped[list] = mapped_column(JSON, default=list)
    time_range_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    time_range_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Status
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ==================== FEATURE: REAL-TIME PRESENCE ====================


class AlertPresence(Base):
    """
    Tracks which users are currently viewing an alert.
    Used for real-time collaboration awareness.
    """

    __tablename__ = "alert_presence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )

    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    user_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Presence tracking
    started_viewing_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_alert_presence_alert_org", "alert_id", "organization_id"),
        Index("ix_alert_presence_user", "user_id"),
    )


# ==================== FEATURE: CORRELATION TIME WINDOWS ====================


class AlertCorrelationWindow(Base):
    """
    Tracks multi-alert correlation windows for threshold-based rules.
    Used by correlation service to track alert counts within time windows.
    """

    __tablename__ = "alert_correlation_windows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    window_key: Mapped[str] = mapped_column(
        String(500), nullable=False
    )  # Hash of aggregation fields
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    first_alert_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_alert_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_correlation_windows_org_rule", "organization_id", "rule_id"),
        Index("ix_correlation_windows_key", "window_key"),
    )


# ==================== FEATURE: COMPLIANCE DASHBOARD ====================


class ComplianceStatus(enum.StrEnum):
    NOT_IMPLEMENTED = "not_implemented"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"


class ComplianceFramework(Base):
    """
    Compliance framework definition (e.g., SOC2, ISO 27001, HIPAA, PCI DSS).
    """

    __tablename__ = "compliance_frameworks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    implemented_controls: Mapped[int] = mapped_column(Integer, default=0)
    coverage_percentage: Mapped[float] = mapped_column(default=0.0)
    last_assessment_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_assessment_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    controls: Mapped[list["ComplianceControl"]] = relationship(
        "ComplianceControl", back_populates="framework", cascade="all, delete-orphan"
    )
    assessments: Mapped[list["ComplianceAssessment"]] = relationship(
        "ComplianceAssessment", back_populates="framework", cascade="all, delete-orphan"
    )


class ComplianceControl(Base):
    """
    Individual compliance control within a framework.
    """

    __tablename__ = "compliance_controls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., "CC1.1"
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ComplianceStatus] = mapped_column(
        SQLEnum(ComplianceStatus), default=ComplianceStatus.NOT_IMPLEMENTED
    )
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_links: Mapped[list] = mapped_column(JSON, default=list)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationship
    framework: Mapped["ComplianceFramework"] = relationship(
        "ComplianceFramework", back_populates="controls"
    )

    __table_args__ = (
        Index("ix_compliance_controls_framework", "framework_id"),
        Index("ix_compliance_controls_unique", "framework_id", "control_id", unique=True),
    )


class ComplianceAssessment(Base):
    """
    Point-in-time compliance assessment for a framework.
    """

    __tablename__ = "compliance_assessments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assessment_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    coverage_score: Mapped[float] = mapped_column(default=0.0)
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    implemented_count: Mapped[int] = mapped_column(Integer, default=0)
    partial_count: Mapped[int] = mapped_column(Integer, default=0)
    not_implemented_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    assessor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationship
    framework: Mapped["ComplianceFramework"] = relationship(
        "ComplianceFramework", back_populates="assessments"
    )


# ==================== FEATURE: THREAT HUNTING ====================


class HuntStatus(enum.StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ThreatHunt(Base):
    """
    Threat hunting hypothesis and investigation.
    """

    __tablename__ = "threat_hunts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    data_sources: Mapped[list] = mapped_column(JSONB, default=list)
    status: Mapped[HuntStatus] = mapped_column(SQLEnum(HuntStatus), default=HuntStatus.DRAFT)
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    queries: Mapped[list["HuntQuery"]] = relationship(
        "HuntQuery", back_populates="hunt", cascade="all, delete-orphan"
    )
    results: Mapped[list["HuntResult"]] = relationship(
        "HuntResult", back_populates="hunt", cascade="all, delete-orphan"
    )


class HuntQuery(Base):
    """
    Query associated with a threat hunt.
    """

    __tablename__ = "hunt_queries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_hunts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sql_query: Mapped[str] = mapped_column(Text, nullable=False)
    query_type: Mapped[str] = mapped_column(String(50), default="detection")
    expected_results: Mapped[str | None] = mapped_column(Text, nullable=True)
    order_index: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationship
    hunt: Mapped["ThreatHunt"] = relationship("ThreatHunt", back_populates="queries")


class HuntResultStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class HuntResult(Base):
    """
    Execution result from a hunt query.
    """

    __tablename__ = "hunt_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    hunt_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_hunts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    query_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunt_queries.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[HuntResultStatus] = mapped_column(
        SQLEnum(HuntResultStatus), default=HuntResultStatus.PENDING
    )
    results_count: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[list] = mapped_column(JSONB, default=list)
    raw_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationship
    hunt: Mapped["ThreatHunt"] = relationship("ThreatHunt", back_populates="results")


# ==================== CLOUD SECURITY (CNAPP) MODELS ====================
# Asset inventory, vulnerability enrichment, and toxic-combination findings.
# Falco (runtime) + Prowler (posture) + Trivy (vulnerabilities) alerts are
# linked to CloudAssets, and the attack path engine correlates across sources
# per asset -- the graph-and-context layer, not another scanner.


class IngestEvent(Base):
    """Webhook-pushed events awaiting a connector's sync cycle.

    Generic sibling of FalcoIngestEvent for push-based connectors added after
    it (Trivy today). Same at-least-once claim semantics: connectors derive
    ``external_id`` from a content fingerprint, so a re-processed event
    collides with ``uq_normalized_alerts_org_connector_external`` and is
    dropped rather than duplicated.
    """

    __tablename__ = "ingest_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connectors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index(
            "ix_ingest_events_connector_claim",
            "connector_id",
            "claimed_at",
            "received_at",
        ),
    )


class CveEnrichment(Base):
    """Exploitability context for a CVE: EPSS score and CISA KEV membership.

    Global (not org-scoped): a CVE's exploitability is a fact about the CVE,
    not about a tenant. Synced daily from the public FIRST EPSS and CISA KEV
    feeds and used to prioritize vulnerability alerts the way Wiz does --
    "exploited in the wild" beats raw CVSS.
    """

    __tablename__ = "cve_enrichment"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)  # e.g. CVE-2024-3094
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0..1
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0..1
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_vulnerability_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class AssetType(enum.StrEnum):
    HOST = "host"
    VM_INSTANCE = "vm_instance"
    CONTAINER = "container"
    CONTAINER_IMAGE = "container_image"
    K8S_POD = "k8s_pod"
    K8S_NAMESPACE = "k8s_namespace"
    K8S_CLUSTER = "k8s_cluster"
    CLOUD_ACCOUNT = "cloud_account"
    STORAGE_BUCKET = "storage_bucket"
    DATABASE = "database"
    IAM_IDENTITY = "iam_identity"
    IAM_ROLE = "iam_role"
    NETWORK = "network"
    SERVERLESS_FUNCTION = "serverless_function"
    LOAD_BALANCER = "load_balancer"
    SERVICE = "service"
    OTHER = "other"


class CloudAsset(Base):
    """A cloud/workload asset observed by any connected security tool.

    Rows are upserted from two directions: cheaply, by extracting resource
    identity from Prowler/Trivy/Falco findings as they are ingested; and in
    bulk, from an external inventory sync (Cartography/CloudQuery) via
    POST /api/v1/assets/import. ``external_id`` is the provider-native ID
    (ARN, GCP resource name) when known, else a derived stable key like
    ``host:web-01`` or ``image:nginx:1.25``.
    """

    __tablename__ = "cloud_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    external_id: Mapped[str] = mapped_column(String(1000), nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(SQLEnum(AssetType), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)  # aws, gcp, azure, k8s
    account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Exposure and business context feeding attack-path evaluation
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    criticality: Mapped[int] = mapped_column(Integer, default=5)  # 1-10, matches AssetCriticality
    data_classification: Mapped[str | None] = mapped_column(String(100), nullable=True)

    labels: Mapped[dict] = mapped_column(JSONB, default=dict)  # provider tags/labels
    attrs: Mapped[dict] = mapped_column(JSONB, default=dict)  # type-specific attributes
    sources: Mapped[list] = mapped_column(JSONB, default=list)  # source_types that observed it

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        # Upserts race across concurrent connector syncs exactly like alert
        # inserts do; the unique index is what settles them.
        Index(
            "uq_cloud_assets_org_external",
            "organization_id",
            "external_id",
            unique=True,
        ),
        Index("ix_cloud_assets_org_type", "organization_id", "asset_type"),
    )

    @validates("external_id", "name", "provider", "account_id", "region", "data_classification")
    def _clamp_to_column_width(self, key: str, value: str | None) -> str | None:
        # Asset identity comes from external scanner output (image names with
        # digests, ARNs embedded in finding UIDs) and can exceed the column.
        if isinstance(value, str):
            limit = getattr(type(self).__table__.columns[key].type, "length", None)
            if limit is not None and len(value) > limit:
                return value[:limit]
        return value


class AssetRelationship(Base):
    """A directed edge between two assets (runs_on, contains, can_access...)."""

    __tablename__ = "asset_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # runs_on, contains, member_of, assumes_role, can_access, exposes
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)
    attrs: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index(
            "uq_asset_relationships_edge",
            "organization_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            unique=True,
        ),
    )


class AssetAlertLink(Base):
    """Links a normalized alert to the asset(s) it concerns."""

    __tablename__ = "asset_alert_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("uq_asset_alert_links_pair", "asset_id", "alert_id", unique=True),
    )


class AttackPathStatus(enum.StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class AttackPathFinding(Base):
    """A toxic combination detected on an asset.

    Synthesized by the attack path engine when independent findings from
    different tools compound on one asset (e.g. internet exposure from
    Prowler + an actively-exploited CVE from Trivy). ``path`` holds the
    nodes/edges rendered by the frontend graph view. One row per
    (rule, asset): re-evaluation updates the row rather than duplicating it,
    and resolves it when a contributing condition clears.
    """

    __tablename__ = "attack_path_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_key: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[AttackPathStatus] = mapped_column(
        SQLEnum(AttackPathStatus), default=AttackPathStatus.OPEN, index=True
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100

    # Graph payload for visualization: {"nodes": [...], "edges": [...]}
    path: Mapped[dict] = mapped_column(JSONB, default=dict)
    # Contributing NormalizedAlert IDs (evidence)
    alert_ids: Mapped[list] = mapped_column(JSONB, default=list)

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    first_detected: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_evaluated: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index(
            "uq_attack_path_findings_rule_asset",
            "organization_id",
            "rule_key",
            "asset_id",
            unique=True,
        ),
    )
