from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Panther API Configuration
    panther_api_host: str = ""
    panther_api_token: str = ""

    # Application Configuration
    secret_key: str = "dev-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # CORS Configuration
    cors_origins: str = "http://localhost:3000"

    # Public URL (for generating external callback URLs behind proxies)
    public_base_url: str = ""  # e.g., "https://ttrevops.com"

    # Redis Configuration
    redis_host: str = "localhost"
    redis_port: int = 6379

    # Database Configuration
    database_url: str = "postgresql+asyncpg://panther:panther@localhost:5432/panther_dashboard"

    # Threat Intel API Keys (optional)
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""  # AlienVault OTX

    # LLM Providers (Phase 5)
    openai_api_key: str = ""
    openai_model: str = "gpt-4"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-5-sonnet-latest"
    default_llm_provider: str = "anthropic"

    # Attack Simulation (Phase 5)
    atomic_red_team_path: str = ""  # Local path or GitHub URL
    stratus_red_team_path: str = ""

    # Cloud credentials for Stratus Red Team execution
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    gcp_project_id: str = ""
    gcp_service_account_key: str = ""  # Path to service account JSON

    # RBAC
    admin_emails: str = ""  # Comma-separated list of admin emails

    # SSO Configuration
    # Google OAuth
    google_client_id: str = ""
    google_client_secret: str = ""

    # Okta OAuth/OIDC
    okta_domain: str = ""  # e.g., your-org.okta.com
    okta_client_id: str = ""
    okta_client_secret: str = ""

    # SSO Settings
    sso_auto_create_users: bool = True  # Auto-create users on first SSO login
    sso_default_role: str = "VIEWER"  # Default role for SSO-created users

    # SMTP for scheduled reports
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""

    # Playbook integrations - Tickets
    jira_url: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    servicenow_url: str = ""
    servicenow_user: str = ""
    servicenow_password: str = ""

    # Playbook integrations - EDR
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    sentinelone_url: str = ""
    sentinelone_api_token: str = ""

    # Playbook integrations - Firewall/SOAR
    firewall_api_url: str = ""
    firewall_api_token: str = ""
    soar_webhook_url: str = ""
    soar_api_token: str = ""

    # Connector Framework - Encryption
    encryption_key: str = ""  # Fernet key for encrypting connector credentials

    # Connector Framework - Alert Sync
    alert_sync_batch_size: int = 100
    alert_sync_max_age_days: int = 30

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = False

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]

    @property
    def admin_emails_list(self) -> list[str]:
        if not self.admin_emails:
            return []
        return [email.strip().lower() for email in self.admin_emails.split(",") if email.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
