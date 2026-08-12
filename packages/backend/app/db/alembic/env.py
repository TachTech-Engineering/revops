"""Alembic migration environment (async, asyncpg).

URL resolution order:
  1. ``sqlalchemy.url`` on the Alembic config (set programmatically by
     app/db/run_migrations.py)
  2. the ``DATABASE_URL`` environment variable
  3. ``app.config.settings.database_url`` (local development fallback --
     imported lazily so migrations don't require the full app settings to
     validate when DATABASE_URL is provided)
"""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.db.models import Base
from app.db.run_migrations import SCHEMA_ADVISORY_LOCK_ID

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    url = config.get_main_option("sqlalchemy.url")
    if url:
        return url
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        from app.config import settings

        url = settings.database_url
    # Normalize to the async driver in case a plain postgres URL was given.
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def include_object(object, name, type_, reflected, compare_to):
    """Keep autogenerate scoped to model-owned tables.

    Tables that exist in the database but not in the models (e.g. tables
    created by other tooling) must not be dropped by autogenerate.
    """
    if type_ == "table" and reflected and compare_to is None:
        return False
    return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' (--sql) mode."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # Serialize schema changes against app replicas running their startup
    # DB init (app/db/session.py takes the same advisory lock).
    connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": SCHEMA_ADVISORY_LOCK_ID})
    try:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
        )

        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.execute(
            text("SELECT pg_advisory_unlock(:key)"), {"key": SCHEMA_ADVISORY_LOCK_ID}
        )


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
        await connection.commit()

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
