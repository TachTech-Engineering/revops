"""
Migration to add new columns to simulation_templates table for Phase 5.

Run this script to add columns for Atomic Red Team and Stratus Red Team support.
"""
import asyncio
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


MIGRATION_SQL = """
-- Add new columns to simulation_templates if they don't exist

-- Atomic Red Team specific fields
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(50);
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS executor_type VARCHAR(50);
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS executor_command TEXT;
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS executor_cleanup TEXT;
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS input_arguments JSONB DEFAULT '{}';
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS dependencies JSONB DEFAULT '[]';

-- Stratus Red Team specific fields
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS cloud_provider VARCHAR(20);
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS cloud_permissions JSONB DEFAULT '[]';
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS detonation_command TEXT;
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS cleanup_command TEXT;

-- General fields
ALTER TABLE simulation_templates ADD COLUMN IF NOT EXISTS test_data JSONB DEFAULT '{}';
"""


async def run_migration():
    """Run the migration to add new columns."""
    engine = create_async_engine(settings.database_url, echo=True)

    logger.info("Starting migration: add_simulation_template_columns")

    try:
        async with engine.begin() as conn:
            # Execute each statement separately for better error handling
            statements = [s.strip() for s in MIGRATION_SQL.split(';') if s.strip() and not s.strip().startswith('--')]

            for stmt in statements:
                logger.info(f"Executing: {stmt[:60]}...")
                await conn.execute(text(stmt))

            logger.info("Migration completed successfully!")
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_migration())
