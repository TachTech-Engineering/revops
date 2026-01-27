import asyncio
import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def run_migrations(conn) -> None:
    """Run schema migrations to add any missing columns."""
    from sqlalchemy import text

    # Migration: Add new columns to simulation_templates for Phase 5
    migration_sql = """
    DO $$
    BEGIN
        -- Atomic Red Team specific fields
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='mitre_technique_id') THEN
            ALTER TABLE simulation_templates ADD COLUMN mitre_technique_id VARCHAR(50);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='executor_type') THEN
            ALTER TABLE simulation_templates ADD COLUMN executor_type VARCHAR(50);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='executor_command') THEN
            ALTER TABLE simulation_templates ADD COLUMN executor_command TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='executor_cleanup') THEN
            ALTER TABLE simulation_templates ADD COLUMN executor_cleanup TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='input_arguments') THEN
            ALTER TABLE simulation_templates ADD COLUMN input_arguments JSONB DEFAULT '{}';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='dependencies') THEN
            ALTER TABLE simulation_templates ADD COLUMN dependencies JSONB DEFAULT '[]';
        END IF;

        -- Stratus Red Team specific fields
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='cloud_provider') THEN
            ALTER TABLE simulation_templates ADD COLUMN cloud_provider VARCHAR(20);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='cloud_permissions') THEN
            ALTER TABLE simulation_templates ADD COLUMN cloud_permissions JSONB DEFAULT '[]';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='detonation_command') THEN
            ALTER TABLE simulation_templates ADD COLUMN detonation_command TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='cleanup_command') THEN
            ALTER TABLE simulation_templates ADD COLUMN cleanup_command TEXT;
        END IF;

        -- General fields
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='simulation_templates' AND column_name='test_data') THEN
            ALTER TABLE simulation_templates ADD COLUMN test_data JSONB DEFAULT '{}';
        END IF;
    END $$;
    """

    try:
        await conn.execute(text(migration_sql))
        logger.info("Database migrations applied successfully")
    except Exception as e:
        logger.warning(f"Migration check failed (table may not exist yet): {e}")


async def init_db(max_retries: int = 10, retry_delay: float = 2.0) -> None:
    """Initialize database with retry logic for container startup."""
    from app.db.models import Base

    for attempt in range(max_retries):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                # Run migrations to add any missing columns
                await run_migrations(conn)
            logger.info("Database initialized successfully")
            return
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Database connection failed (attempt {attempt + 1}/{max_retries}): {e}")
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts")
                raise
