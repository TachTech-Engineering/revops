import asyncio
import logging
import os
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

logger = logging.getLogger(__name__)

# Advisory lock serializing all schema/seed work across replicas and the
# Alembic migration Job. Keep in sync with SCHEMA_ADVISORY_LOCK_ID in
# app/db/run_migrations.py (not imported from there so that
# `python -m app.db.run_migrations` doesn't re-import its own module).
# 0x52564F50 == ascii "RVOP".
SCHEMA_ADVISORY_LOCK_ID = 0x52564F50


def _auto_migrate_enabled() -> bool:
    """Whether startup should create/patch the schema itself.

    Read from the environment (not app.config) so it can be toggled per
    deployment without a settings change. Defaults to true so local
    docker-compose development keeps working with zero configuration.
    In k8s the schema is managed by the Alembic migration Job
    (app/db/run_migrations.py); set AUTO_MIGRATE=false there.
    """
    return os.environ.get("AUTO_MIGRATE", "true").strip().lower() in ("1", "true", "yes", "on")


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

    # Migration: Add role column to users table
    user_role_migration = """
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='users' AND column_name='role') THEN
            ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'viewer';
        END IF;
    END $$;
    """

    try:
        await conn.execute(text(user_role_migration))
        logger.info("User role migration applied successfully")
    except Exception as e:
        logger.warning(f"User role migration failed: {e}")

    # Migration: Add new columns to simulation_templates for Phase 5
    migration_sql = """
    DO $$
    BEGIN
        -- Atomic Red Team specific fields
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='mitre_technique_id') THEN
            ALTER TABLE simulation_templates ADD COLUMN mitre_technique_id VARCHAR(50);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='executor_type') THEN
            ALTER TABLE simulation_templates ADD COLUMN executor_type VARCHAR(50);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='executor_command') THEN
            ALTER TABLE simulation_templates ADD COLUMN executor_command TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='executor_cleanup') THEN
            ALTER TABLE simulation_templates ADD COLUMN executor_cleanup TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='input_arguments') THEN
            ALTER TABLE simulation_templates ADD COLUMN input_arguments JSONB DEFAULT '{}';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='dependencies') THEN
            ALTER TABLE simulation_templates ADD COLUMN dependencies JSONB DEFAULT '[]';
        END IF;

        -- Stratus Red Team specific fields
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='cloud_provider') THEN
            ALTER TABLE simulation_templates ADD COLUMN cloud_provider VARCHAR(20);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='cloud_permissions') THEN
            ALTER TABLE simulation_templates ADD COLUMN cloud_permissions JSONB DEFAULT '[]';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='detonation_command') THEN
            ALTER TABLE simulation_templates ADD COLUMN detonation_command TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='cleanup_command') THEN
            ALTER TABLE simulation_templates ADD COLUMN cleanup_command TEXT;
        END IF;

        -- General fields
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_name='simulation_templates' AND column_name='test_data') THEN
            ALTER TABLE simulation_templates ADD COLUMN test_data JSONB DEFAULT '{}';
        END IF;
    END $$;
    """

    try:
        await conn.execute(text(migration_sql))
        logger.info("Database migrations applied successfully")
    except Exception as e:
        logger.warning(f"Migration check failed (table may not exist yet): {e}")


async def seed_default_correlation_rules() -> None:
    """Seed default correlation rules for auto-incident creation."""
    from sqlalchemy import select

    from app.db.models import CorrelationRule, Organization

    async with AsyncSessionLocal() as db:
        try:
            # Get all organizations
            result = await db.execute(select(Organization))
            organizations = result.scalars().all()

            for org in organizations:
                # Check if default high-severity rule already exists
                existing = await db.execute(
                    select(CorrelationRule).where(
                        CorrelationRule.organization_id == org.id,
                        CorrelationRule.name == "Auto-Incident: Critical/High Severity Alerts",
                    )
                )
                if existing.scalar_one_or_none():
                    continue

                # Create default rule for high-severity alerts
                rule = CorrelationRule(
                    organization_id=org.id,
                    name="Auto-Incident: Critical/High Severity Alerts",
                    description="Automatically creates incidents from critical and high "
                    "severity alerts from any data source connector.",
                    conditions={
                        "severity_filter": ["critical", "high"],
                        "min_alerts": 1,
                        "time_window_minutes": 60,
                    },
                    is_active=True,
                    auto_create_incident=True,
                    created_by="system",
                )
                db.add(rule)
                logger.info(f"Created default correlation rule for organization {org.name}")

            await db.commit()
            logger.info("Default correlation rules seeded successfully")
        except Exception as e:
            logger.warning(f"Failed to seed default correlation rules: {e}")
            await db.rollback()


async def init_db(max_retries: int = 10, retry_delay: float = 2.0) -> None:
    """Initialize database with retry logic for container startup.

    The whole init runs under a Postgres advisory lock so that multiple
    replicas rolling out simultaneously cannot race each other on DDL or
    seeding. Schema creation (create_all + legacy column patches) only
    runs when AUTO_MIGRATE is enabled; when it is disabled the schema is
    expected to be managed by Alembic (app/db/run_migrations.py, run as a
    k8s Job before the rollout), which takes the same advisory lock.
    """
    from app.db.models import Base

    auto_migrate = _auto_migrate_enabled()

    for attempt in range(max_retries):
        try:
            async with engine.connect() as conn:
                # Session-level lock: serializes replicas (and the Alembic
                # migration Job, which uses the same key). Released in the
                # finally block below and, failing that, when the
                # connection closes.
                await conn.execute(
                    text("SELECT pg_advisory_lock(:key)"), {"key": SCHEMA_ADVISORY_LOCK_ID}
                )
                try:
                    if auto_migrate:
                        await conn.run_sync(Base.metadata.create_all)
                        # Run migrations to add any missing columns
                        await run_migrations(conn)
                        await conn.commit()
                        logger.info("Database initialized successfully")
                    else:
                        logger.info(
                            "AUTO_MIGRATE disabled; skipping create_all "
                            "(schema is managed by Alembic migrations)"
                        )

                    # Seed default correlation rules (still inside the lock)
                    await seed_default_correlation_rules()
                finally:
                    # Clear any aborted transaction so the unlock can run.
                    await conn.rollback()
                    await conn.execute(
                        text("SELECT pg_advisory_unlock(:key)"),
                        {"key": SCHEMA_ADVISORY_LOCK_ID},
                    )

            return
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(
                    f"Database connection failed (attempt {attempt + 1}/{max_retries}): {e}"
                )
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts")
                raise
