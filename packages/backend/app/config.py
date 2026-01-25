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

    # Redis Configuration
    redis_host: str = "localhost"
    redis_port: int = 6379

    # Database Configuration
    database_url: str = "postgresql+asyncpg://panther:panther@localhost:5432/panther_dashboard"

    # Threat Intel API Keys (optional)
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # RBAC
    admin_emails: str = ""  # Comma-separated list of admin emails

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
