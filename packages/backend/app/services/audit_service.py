from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AuditLog


class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        user_email: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """Log an audit event."""
        log_entry = AuditLog(
            user_email=user_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.db.add(log_entry)
        await self.db.flush()
        return log_entry


async def get_audit_service(db: AsyncSession) -> AuditService:
    """Factory function to create an audit service."""
    return AuditService(db)
