"""
Threat Feed Management Service.
Handles feed subscriptions, syncing, and IOC import.
"""

import csv
import io
import logging
import time
import uuid
from datetime import datetime, timedelta

import httpx
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IOC, FeedStatus, FeedSyncLog, FeedType, IOCSeverity, IOCType, ThreatFeed
from app.services.ioc_service import ioc_service

logger = logging.getLogger(__name__)


class FeedParser:
    """Parsers for different feed formats."""

    @staticmethod
    async def parse_abusech_feodo(content: str) -> list[dict]:
        """Parse Abuse.ch Feodo Tracker CSV feed."""
        iocs = []
        reader = csv.reader(io.StringIO(content))

        for row in reader:
            # Skip comments and empty lines
            if not row or row[0].startswith("#"):
                continue

            # Feodo format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
            if len(row) >= 6:
                try:
                    iocs.append(
                        {
                            "ioc_type": IOCType.IP_ADDRESS,
                            "value": row[1],
                            "severity": IOCSeverity.CRITICAL,  # Botnet C2 is critical
                            "description": f"Feodo Tracker - {row[5]} C2 server",
                            "tags": ["botnet", "c2", row[5].lower()]
                            if row[5]
                            else ["botnet", "c2"],
                            "first_seen": datetime.fromisoformat(row[0].replace(" ", "T"))
                            if row[0]
                            else None,
                        }
                    )
                except (ValueError, IndexError):
                    continue

        return iocs

    @staticmethod
    async def parse_abusech_urlhaus(content: str) -> list[dict]:
        """Parse Abuse.ch URLhaus CSV feed."""
        iocs = []
        reader = csv.reader(io.StringIO(content))

        for row in reader:
            # Skip comments and empty lines
            if not row or row[0].startswith("#"):
                continue

            # URLhaus format:
            # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            if len(row) >= 7:
                try:
                    tags = row[6].split(",") if row[6] else []
                    tags.append("malware")
                    if row[5]:
                        tags.append(row[5].lower())

                    iocs.append(
                        {
                            "ioc_type": IOCType.URL,
                            "value": row[2],
                            "severity": IOCSeverity.HIGH
                            if row[3] == "online"
                            else IOCSeverity.MEDIUM,
                            "description": f"URLhaus - {row[5]}"
                            if row[5]
                            else "URLhaus malicious URL",
                            "tags": list(set(tags)),
                            "first_seen": datetime.fromisoformat(row[1].replace(" ", "T"))
                            if row[1]
                            else None,
                        }
                    )
                except (ValueError, IndexError):
                    continue

        return iocs

    @staticmethod
    async def parse_otx_pulse(data: dict) -> list[dict]:
        """Parse AlienVault OTX pulse JSON."""
        iocs = []
        indicators = data.get("indicators", [])

        for ind in indicators:
            ind_type = ind.get("type", "")
            value = ind.get("indicator", "")

            # Map OTX type to IOC type
            ioc_type = None
            if ind_type == "IPv4":
                ioc_type = IOCType.IP_ADDRESS
            elif ind_type == "domain":
                ioc_type = IOCType.DOMAIN
            elif ind_type == "URL":
                ioc_type = IOCType.URL
            elif ind_type == "FileHash-MD5":
                ioc_type = IOCType.FILE_HASH_MD5
            elif ind_type == "FileHash-SHA1":
                ioc_type = IOCType.FILE_HASH_SHA1
            elif ind_type == "FileHash-SHA256":
                ioc_type = IOCType.FILE_HASH_SHA256
            elif ind_type == "email":
                ioc_type = IOCType.EMAIL

            if ioc_type and value:
                iocs.append(
                    {
                        "ioc_type": ioc_type,
                        "value": value,
                        "severity": IOCSeverity.MEDIUM,
                        "description": ind.get("description") or data.get("name"),
                        "tags": data.get("tags", [])[:5],
                        "first_seen": datetime.fromisoformat(
                            ind.get("created").replace("Z", "+00:00")
                        ).replace(tzinfo=None)
                        if ind.get("created")
                        else None,
                    }
                )

        return iocs

    @staticmethod
    async def parse_generic_csv(content: str, mapping: dict) -> list[dict]:
        """
        Parse a generic CSV feed with configurable column mapping.

        Args:
            content: CSV content
            mapping: Dictionary mapping CSV columns to IOC fields
                     e.g., {"value_column": 0, "type": "ip_address", "severity": "high"}
        """
        iocs = []
        reader = csv.reader(io.StringIO(content))

        value_col = mapping.get("value_column", 0)
        ioc_type = IOCType(mapping.get("type", "ip_address"))
        severity = IOCSeverity(mapping.get("severity", "medium"))
        skip_header = mapping.get("skip_header", True)

        for i, row in enumerate(reader):
            # Skip header if configured
            if skip_header and i == 0:
                continue

            # Skip comments and empty lines
            if not row or row[0].startswith("#"):
                continue

            try:
                if len(row) > value_col:
                    iocs.append(
                        {
                            "ioc_type": ioc_type,
                            "value": row[value_col].strip(),
                            "severity": severity,
                            "description": mapping.get("description", "Imported from CSV feed"),
                            "tags": mapping.get("tags", []),
                        }
                    )
            except (ValueError, IndexError):
                continue

        return iocs


class FeedService:
    """Service for managing threat feed subscriptions."""

    def __init__(self):
        self.parser = FeedParser()

    async def create_feed(
        self,
        db: AsyncSession,
        name: str,
        url: str,
        feed_type: FeedType,
        created_by: str,
        organization_id: uuid.UUID,
        update_interval_minutes: int = 60,
    ) -> ThreatFeed:
        """Create a new feed subscription owned by an organization."""
        feed = ThreatFeed(
            name=name,
            url=url,
            feed_type=feed_type,
            update_interval_minutes=update_interval_minutes,
            next_sync_at=datetime.utcnow(),
            created_by=created_by,
            organization_id=organization_id,
        )
        db.add(feed)
        await db.commit()
        await db.refresh(feed)
        return feed

    async def get_feed(
        self,
        db: AsyncSession,
        feed_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> ThreatFeed | None:
        """Get a feed by ID, scoped to an organization when one is provided."""
        query = select(ThreatFeed).where(ThreatFeed.id == feed_id)
        if organization_id is not None:
            query = query.where(ThreatFeed.organization_id == organization_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def list_feeds(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID,
        status: FeedStatus | None = None,
    ) -> list[ThreatFeed]:
        """List an organization's feeds, optionally filtered by status."""
        query = select(ThreatFeed).where(ThreatFeed.organization_id == organization_id)
        if status:
            query = query.where(ThreatFeed.status == status)
        query = query.order_by(ThreatFeed.created_at.desc())

        result = await db.execute(query)
        return list(result.scalars().all())

    async def update_feed(
        self,
        db: AsyncSession,
        feed_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
        **updates,
    ) -> ThreatFeed | None:
        """Update a feed, scoped to an organization when one is provided."""
        feed = await self.get_feed(db, feed_id, organization_id=organization_id)
        if not feed:
            return None

        # Never allow tenant reassignment through the generic update path
        updates.pop("organization_id", None)

        for key, value in updates.items():
            if hasattr(feed, key) and value is not None:
                setattr(feed, key, value)

        await db.commit()
        await db.refresh(feed)
        return feed

    async def delete_feed(
        self,
        db: AsyncSession,
        feed_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> bool:
        """Delete a feed and its IOCs, scoped to an organization when one is provided."""
        feed = await self.get_feed(db, feed_id, organization_id=organization_id)
        if not feed:
            return False

        # Delete associated IOCs
        await db.execute(IOC.__table__.delete().where(IOC.feed_id == feed_id))

        await db.delete(feed)
        await db.commit()
        return True

    async def sync_feed(
        self,
        db: AsyncSession,
        feed_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> dict:
        """
        Sync a single feed - fetch and import new IOCs.

        When organization_id is provided, the feed lookup is scoped to that
        organization. Imported IOCs are always attributed to the feed's own
        organization.

        Returns:
            Dictionary with sync results
        """
        feed = await self.get_feed(db, feed_id, organization_id=organization_id)
        if not feed:
            raise ValueError("Feed not found")

        start_time = time.time()
        result = {
            "feed_id": str(feed_id),
            "feed_name": feed.name,
            "status": "success",
            "iocs_added": 0,
            "iocs_updated": 0,
            "error": None,
        }

        # Guard against legacy rows created before organization_id was enforced.
        # IOC.organization_id and FeedSyncLog.organization_id are NOT NULL, so
        # syncing an org-less feed would crash mid-import; skip and log instead.
        if feed.organization_id is None:
            logger.warning(
                "Skipping sync for feed %s (%s): feed has no organization_id",
                feed.name,
                feed_id,
            )
            result["status"] = "skipped"
            result["error"] = "Feed has no organization_id; sync skipped"
            result["duration_ms"] = int((time.time() - start_time) * 1000)
            return result

        try:
            # Fetch feed content
            async with httpx.AsyncClient() as client:
                response = await client.get(feed.url, timeout=60.0)
                response.raise_for_status()
                content = response.text

            # Parse feed based on type
            if feed.feed_type == FeedType.ABUSECH_FEODO:
                iocs = await self.parser.parse_abusech_feodo(content)
            elif feed.feed_type == FeedType.ABUSECH_URLHAUS:
                iocs = await self.parser.parse_abusech_urlhaus(content)
            elif feed.feed_type == FeedType.OTX:
                data = response.json()
                iocs = await self.parser.parse_otx_pulse(data)
            elif feed.feed_type == FeedType.CUSTOM_CSV:
                # Use default CSV parsing (assumes IP in first column)
                iocs = await self.parser.parse_generic_csv(content, {"type": "ip_address"})
            else:
                raise ValueError(f"Unsupported feed type: {feed.feed_type}")

            # Import IOCs
            if iocs:
                import_result = await ioc_service.bulk_import(
                    db,
                    iocs=iocs,
                    source=feed.name,
                    created_by="feed_sync",
                    feed_id=feed_id,
                    organization_id=feed.organization_id,
                )
                result["iocs_added"] = import_result["added"]
                result["iocs_updated"] = import_result["updated"]

            # Update feed status
            feed.last_sync_at = datetime.utcnow()
            feed.next_sync_at = datetime.utcnow() + timedelta(minutes=feed.update_interval_minutes)
            feed.status = FeedStatus.ACTIVE
            feed.error_message = None
            feed.ioc_count = result["iocs_added"] + result["iocs_updated"]

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            feed.status = FeedStatus.ERROR
            feed.error_message = str(e)

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Log sync
        sync_log = FeedSyncLog(
            feed_id=feed_id,
            organization_id=feed.organization_id,
            status=result["status"],
            iocs_added=result["iocs_added"],
            iocs_updated=result["iocs_updated"],
            duration_ms=duration_ms,
            error=result["error"],
        )
        db.add(sync_log)
        await db.commit()

        result["duration_ms"] = duration_ms
        return result

    async def sync_all_active(
        self, db: AsyncSession, organization_id: uuid.UUID | None = None
    ) -> list[dict]:
        """
        Sync all active feeds that are due for update.

        When organization_id is provided, only that organization's feeds are
        synced. Each feed's IOCs are attributed to the feed's own organization.
        """
        results = []

        # Get feeds due for sync
        query = select(ThreatFeed).where(
            and_(
                ThreatFeed.status == FeedStatus.ACTIVE,
                ThreatFeed.next_sync_at <= datetime.utcnow(),
            )
        )
        if organization_id is not None:
            query = query.where(ThreatFeed.organization_id == organization_id)
        result = await db.execute(query)
        feeds = list(result.scalars().all())

        for feed in feeds:
            try:
                sync_result = await self.sync_feed(
                    db, feed.id, organization_id=feed.organization_id
                )
                results.append(sync_result)
            except Exception as e:
                results.append(
                    {
                        "feed_id": str(feed.id),
                        "feed_name": feed.name,
                        "status": "failed",
                        "error": str(e),
                    }
                )

        return results

    async def get_sync_logs(
        self,
        db: AsyncSession,
        feed_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
        limit: int = 20,
    ) -> list[FeedSyncLog]:
        """Get sync history for a feed, scoped to an organization when provided."""
        query = select(FeedSyncLog).where(FeedSyncLog.feed_id == feed_id)
        if organization_id is not None:
            query = query.where(FeedSyncLog.organization_id == organization_id)
        query = query.order_by(FeedSyncLog.synced_at.desc()).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())


# Singleton instance
feed_service = FeedService()
