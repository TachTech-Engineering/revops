"""
IOC Management Service for creating, searching, importing, and exporting IOCs.
"""

import csv
import io
import uuid
from datetime import datetime

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IOC, IOCSeverity, IOCType
from app.services.stix_service import stix_service


class IOCService:
    """Service for managing Indicators of Compromise."""

    async def create_ioc(
        self,
        db: AsyncSession,
        ioc_type: IOCType,
        value: str,
        source: str,
        created_by: str,
        severity: IOCSeverity = IOCSeverity.MEDIUM,
        description: str | None = None,
        tags: list[str] | None = None,
        feed_id: uuid.UUID | None = None,
        expires_at: datetime | None = None,
        organization_id: uuid.UUID | None = None,
    ) -> IOC:
        """Create a single IOC."""
        ioc = IOC(
            organization_id=organization_id,
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            source=source,
            feed_id=feed_id,
            description=description,
            tags=tags or [],
            expires_at=expires_at,
            created_by=created_by,
        )
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
        return ioc

    async def get_ioc(
        self,
        db: AsyncSession,
        ioc_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> IOC | None:
        """Get an IOC by ID, optionally scoped to an organization."""
        query = select(IOC).where(IOC.id == ioc_id)
        if organization_id is not None:
            query = query.where(IOC.organization_id == organization_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def update_ioc(
        self,
        db: AsyncSession,
        ioc_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
        **updates,
    ) -> IOC | None:
        """Update an IOC."""
        ioc = await self.get_ioc(db, ioc_id, organization_id=organization_id)
        if not ioc:
            return None

        for key, value in updates.items():
            if hasattr(ioc, key) and value is not None:
                setattr(ioc, key, value)

        ioc.last_seen = datetime.utcnow()
        await db.commit()
        await db.refresh(ioc)
        return ioc

    async def delete_ioc(
        self,
        db: AsyncSession,
        ioc_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> bool:
        """Delete an IOC."""
        ioc = await self.get_ioc(db, ioc_id, organization_id=organization_id)
        if not ioc:
            return False

        await db.delete(ioc)
        await db.commit()
        return True

    async def search(
        self,
        db: AsyncSession,
        query: str | None = None,
        ioc_type: IOCType | None = None,
        severity: IOCSeverity | None = None,
        source: str | None = None,
        is_active: bool | None = None,
        tags: list[str] | None = None,
        page: int = 1,
        page_size: int = 50,
        organization_id: uuid.UUID | None = None,
    ) -> tuple[list[IOC], int]:
        """Search IOCs with filters."""
        conditions = []

        if organization_id is not None:
            conditions.append(IOC.organization_id == organization_id)

        if query:
            conditions.append(IOC.value.ilike(f"%{query}%"))

        if ioc_type:
            conditions.append(IOC.ioc_type == ioc_type)

        if severity:
            conditions.append(IOC.severity == severity)

        if source:
            conditions.append(IOC.source.ilike(f"%{source}%"))

        if is_active is not None:
            conditions.append(IOC.is_active == is_active)

        if tags:
            # Check if any of the provided tags are in the IOC's tags
            for tag in tags:
                conditions.append(IOC.tags.contains([tag]))

        # Build query
        base_query = select(IOC)
        if conditions:
            base_query = base_query.where(and_(*conditions))

        # Get total count
        count_query = select(func.count()).select_from(IOC)
        if conditions:
            count_query = count_query.where(and_(*conditions))
        count_result = await db.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        offset = (page - 1) * page_size
        results_query = base_query.order_by(IOC.last_seen.desc()).offset(offset).limit(page_size)
        result = await db.execute(results_query)
        iocs = list(result.scalars().all())

        return iocs, total

    async def bulk_import(
        self,
        db: AsyncSession,
        iocs: list[dict],
        source: str,
        created_by: str,
        feed_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
    ) -> dict:
        """
        Bulk import IOCs.

        Returns:
            Dictionary with 'added' and 'updated' counts
        """
        added = 0
        updated = 0

        for ioc_data in iocs:
            ioc_type = ioc_data.get("ioc_type")
            value = ioc_data.get("value")

            if not ioc_type or not value:
                continue

            if isinstance(ioc_type, str):
                try:
                    ioc_type = IOCType(ioc_type)
                except ValueError:
                    continue

            # Check if IOC already exists
            existing_conditions = [IOC.ioc_type == ioc_type, IOC.value == value]
            if organization_id is not None:
                existing_conditions.append(IOC.organization_id == organization_id)
            result = await db.execute(select(IOC).where(and_(*existing_conditions)))
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing IOC
                existing.last_seen = datetime.utcnow()
                if ioc_data.get("severity"):
                    severity = ioc_data["severity"]
                    if isinstance(severity, str):
                        severity = IOCSeverity(severity)
                    existing.severity = severity
                if ioc_data.get("tags"):
                    # Merge tags
                    existing_tags = set(existing.tags or [])
                    new_tags = set(ioc_data["tags"])
                    existing.tags = list(existing_tags | new_tags)
                updated += 1
            else:
                # Create new IOC
                severity = ioc_data.get("severity", IOCSeverity.MEDIUM)
                if isinstance(severity, str):
                    try:
                        severity = IOCSeverity(severity)
                    except ValueError:
                        severity = IOCSeverity.MEDIUM

                new_ioc = IOC(
                    organization_id=organization_id,
                    ioc_type=ioc_type,
                    value=value,
                    severity=severity,
                    source=source,
                    feed_id=feed_id,
                    description=ioc_data.get("description"),
                    tags=ioc_data.get("tags", []),
                    first_seen=ioc_data.get("first_seen", datetime.utcnow()),
                    expires_at=ioc_data.get("expires_at"),
                    created_by=created_by,
                )
                db.add(new_ioc)
                added += 1

        await db.commit()
        return {"added": added, "updated": updated}

    async def import_stix(
        self,
        db: AsyncSession,
        bundle_data: dict,
        source: str,
        created_by: str,
        organization_id: uuid.UUID | None = None,
    ) -> dict:
        """Import IOCs from a STIX 2.1 bundle."""
        iocs = stix_service.parse_bundle(bundle_data)
        return await self.bulk_import(db, iocs, source, created_by, organization_id=organization_id)

    async def export_stix(
        self,
        db: AsyncSession,
        ioc_type: IOCType | None = None,
        is_active: bool | None = True,
        organization_id: uuid.UUID | None = None,
    ) -> dict:
        """Export IOCs as a STIX 2.1 bundle."""
        conditions = []

        if organization_id is not None:
            conditions.append(IOC.organization_id == organization_id)

        if ioc_type:
            conditions.append(IOC.ioc_type == ioc_type)

        if is_active is not None:
            conditions.append(IOC.is_active == is_active)

        query = select(IOC)
        if conditions:
            query = query.where(and_(*conditions))

        result = await db.execute(query)
        iocs = result.scalars().all()

        # Convert ORM objects to dictionaries
        ioc_dicts = []
        for ioc in iocs:
            ioc_dicts.append(
                {
                    "id": str(ioc.id),
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.value,
                    "severity": ioc.severity,
                    "description": ioc.description,
                    "tags": ioc.tags,
                    "source": ioc.source,
                    "first_seen": ioc.first_seen,
                    "expires_at": ioc.expires_at,
                    "created_at": ioc.created_at,
                }
            )

        return stix_service.create_bundle(ioc_dicts)

    async def export_csv(
        self,
        db: AsyncSession,
        ioc_type: IOCType | None = None,
        is_active: bool | None = True,
        organization_id: uuid.UUID | None = None,
    ) -> str:
        """Export IOCs as CSV."""
        conditions = []

        if organization_id is not None:
            conditions.append(IOC.organization_id == organization_id)

        if ioc_type:
            conditions.append(IOC.ioc_type == ioc_type)

        if is_active is not None:
            conditions.append(IOC.is_active == is_active)

        query = select(IOC)
        if conditions:
            query = query.where(and_(*conditions))

        result = await db.execute(query)
        iocs = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "type",
                "value",
                "severity",
                "source",
                "description",
                "tags",
                "first_seen",
                "last_seen",
                "expires_at",
                "is_active",
            ]
        )

        # Write data
        for ioc in iocs:
            writer.writerow(
                [
                    ioc.ioc_type.value,
                    ioc.value,
                    ioc.severity.value,
                    ioc.source,
                    ioc.description or "",
                    ",".join(ioc.tags or []),
                    ioc.first_seen.isoformat() if ioc.first_seen else "",
                    ioc.last_seen.isoformat() if ioc.last_seen else "",
                    ioc.expires_at.isoformat() if ioc.expires_at else "",
                    str(ioc.is_active),
                ]
            )

        return output.getvalue()

    async def get_stats(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID | None = None,
    ) -> dict:
        """Get IOC statistics."""
        org_conditions = []
        if organization_id is not None:
            org_conditions.append(IOC.organization_id == organization_id)

        # Total count
        total_query = select(func.count()).select_from(IOC)
        if org_conditions:
            total_query = total_query.where(*org_conditions)
        total_result = await db.execute(total_query)
        total = total_result.scalar() or 0

        # Active count
        active_query = select(func.count()).select_from(IOC).where(IOC.is_active.is_(True))
        if org_conditions:
            active_query = active_query.where(*org_conditions)
        active_result = await db.execute(active_query)
        active = active_result.scalar() or 0

        # By type
        type_query = select(IOC.ioc_type, func.count()).group_by(IOC.ioc_type)
        if org_conditions:
            type_query = type_query.where(*org_conditions)
        type_result = await db.execute(type_query)
        by_type = {str(row[0].value): row[1] for row in type_result.all()}

        # By severity
        severity_query = select(IOC.severity, func.count()).group_by(IOC.severity)
        if org_conditions:
            severity_query = severity_query.where(*org_conditions)
        severity_result = await db.execute(severity_query)
        by_severity = {str(row[0].value): row[1] for row in severity_result.all()}

        return {
            "total": total,
            "active": active,
            "by_type": by_type,
            "by_severity": by_severity,
        }


# Singleton instance
ioc_service = IOCService()
