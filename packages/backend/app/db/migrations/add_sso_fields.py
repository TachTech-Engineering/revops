"""
Migration to add SSO fields to the users table.

Run this script to add sso_provider and sso_id columns, and make hashed_password nullable.
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
    # Create SSO provider enum type if it doesn't exist
    """
    DO $$ BEGIN
        CREATE TYPE ssoprovider AS ENUM ('google', 'okta');
    EXCEPTION
        WHEN duplicate_object THEN null;
    END $$
    """,
    # Add sso_provider column to users table
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider ssoprovider",
    # Add sso_id column to users table
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_id VARCHAR(255)",
    # Make hashed_password nullable for SSO-only users
    "ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL",
    # Create index for faster SSO lookups
    "CREATE INDEX IF NOT EXISTS ix_users_sso_provider_id ON users (sso_provider, sso_id)",
]


async def run_migration():
    """Run the migration to add SSO fields."""
    engine = create_async_engine(settings.database_url, echo=True)

    logger.info("Starting migration: add_sso_fields")

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
