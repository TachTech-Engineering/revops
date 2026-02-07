"""
Migration to add the organization_sso table for per-organization SSO configuration.

Run this script to create the table for multi-tenant SSO support.
"""
import asyncio
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Individual migration statements (executed separately)
MIGRATION_STATEMENTS = [
    # Update SSO provider enum to include new providers
    """
    DO $$ BEGIN
        ALTER TYPE ssoprovider ADD VALUE IF NOT EXISTS 'azure_ad';
        ALTER TYPE ssoprovider ADD VALUE IF NOT EXISTS 'saml';
    EXCEPTION
        WHEN undefined_object THEN
            CREATE TYPE ssoprovider AS ENUM ('google', 'okta', 'azure_ad', 'saml');
    END $$
    """,
    # Create organization_sso table
    """
    CREATE TABLE IF NOT EXISTS organization_sso (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        provider ssoprovider NOT NULL,
        is_enabled BOOLEAN DEFAULT TRUE,
        display_name VARCHAR(100),
        client_id VARCHAR(255) NOT NULL,
        client_secret_encrypted BYTEA NOT NULL,
        domain VARCHAR(255),
        tenant_id VARCHAR(255),
        metadata_url TEXT,
        entity_id VARCHAR(500),
        sso_url TEXT,
        certificate TEXT,
        allowed_email_domains VARCHAR(1000),
        auto_create_users BOOLEAN DEFAULT TRUE,
        default_role userroletype DEFAULT 'viewer',
        created_by VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    # Create indexes
    "CREATE INDEX IF NOT EXISTS ix_organization_sso_org_id ON organization_sso(organization_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_org_sso_org_provider ON organization_sso(organization_id, provider)",
    # Add trigger function for updated_at
    """
    CREATE OR REPLACE FUNCTION update_organization_sso_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """,
    # Drop existing trigger if exists
    "DROP TRIGGER IF EXISTS organization_sso_updated_at ON organization_sso",
    # Create trigger
    """
    CREATE TRIGGER organization_sso_updated_at
        BEFORE UPDATE ON organization_sso
        FOR EACH ROW
        EXECUTE FUNCTION update_organization_sso_updated_at()
    """,
]


async def run_migration():
    """Run the migration to add organization_sso table."""
    engine = create_async_engine(settings.database_url, echo=True)

    logger.info("Starting migration: add_organization_sso")

    try:
        async with engine.begin() as conn:
            for i, stmt in enumerate(MIGRATION_STATEMENTS, 1):
                logger.info(f"Executing statement {i}/{len(MIGRATION_STATEMENTS)}: {stmt.strip()[:60]}...")
                await conn.execute(text(stmt))

            logger.info("Migration completed successfully!")
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_migration())
