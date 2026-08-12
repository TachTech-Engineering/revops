"""Deploy-time migration entrypoint (run by the k8s migration Job).

Usage:
    python -m app.db.run_migrations

Behaviour:
  - Fresh/empty database          -> ``alembic upgrade head``
  - Alembic-managed database      -> ``alembic upgrade head``
  - Pre-Alembic database (tables
    exist, no alembic_version)    -> ``alembic stamp <baseline>`` then
                                     ``alembic upgrade head``

The pre-Alembic case covers existing production/staging databases whose
schema was built by Base.metadata.create_all: the baseline revision was
generated from the same models, so those databases are stamped at the
baseline and then upgraded through any newer revisions.

The database URL comes from the DATABASE_URL environment variable
(falling back to app.config.settings.database_url). Actual DDL execution
is serialized via a Postgres advisory lock taken in the Alembic env.py,
using the same lock id as the app's startup init in app/db/session.py.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Advisory lock id shared by every code path that touches the schema.
# alembic env.py imports it from here; app/db/session.py defines the same
# value locally (kept in sync by comment there) to avoid importing this
# module from the app. 0x52564F50 == ascii "RVOP".
SCHEMA_ADVISORY_LOCK_ID = 0x52564F50

logger = logging.getLogger("app.db.run_migrations")


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        from app.config import settings

        url = settings.database_url
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def _alembic_config(url: str):
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _baseline_revision(cfg) -> str:
    """The root of the revision tree (the initial full-schema migration)."""
    from alembic.script import ScriptDirectory

    bases = ScriptDirectory.from_config(cfg).get_bases()
    if len(bases) != 1:
        raise RuntimeError(f"Expected exactly one base revision, found: {bases}")
    return bases[0]


async def _inspect_database(url: str, max_retries: int = 10, retry_delay: float = 3.0):
    """Return (alembic_version_or_None, has_existing_schema)."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(url, pool_pre_ping=True)
    try:
        for attempt in range(max_retries):
            try:
                async with engine.connect() as conn:
                    version = None
                    has_version_table = (
                        await conn.execute(text("SELECT to_regclass('public.alembic_version')"))
                    ).scalar() is not None
                    if has_version_table:
                        version = (
                            await conn.execute(
                                text("SELECT version_num FROM alembic_version LIMIT 1")
                            )
                        ).scalar()
                    # 'users' and 'organizations' have existed since the first
                    # deployment; either one marks a pre-Alembic schema.
                    has_schema = (
                        await conn.execute(
                            text(
                                "SELECT to_regclass('public.users') IS NOT NULL"
                                " OR to_regclass('public.organizations') IS NOT NULL"
                            )
                        )
                    ).scalar()
                    return version, bool(has_schema)
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(
                        "Database not reachable (attempt %d/%d): %s",
                        attempt + 1,
                        max_retries,
                        e,
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    raise
    finally:
        await engine.dispose()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    from alembic import command

    url = _database_url()
    cfg = _alembic_config(url)
    baseline = _baseline_revision(cfg)

    version, has_schema = asyncio.run(_inspect_database(url))

    if version is not None:
        logger.info("Database is Alembic-managed at revision %s; upgrading to head", version)
    elif has_schema:
        logger.info(
            "Existing pre-Alembic schema detected (no alembic_version); "
            "stamping baseline %s before upgrading",
            baseline,
        )
        command.stamp(cfg, baseline)
    else:
        logger.info("Empty database detected; running full upgrade to head")

    command.upgrade(cfg, "head")
    logger.info("Migrations complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
