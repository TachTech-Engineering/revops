"""
Syslog UDP Server for receiving push-based log data.

Listens on UDP port 5514 for syslog messages from sources like UniFi.
Parses messages, looks up the associated connector, and creates alerts.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.db.models import Connector, NormalizedAlert, ConnectorStatus, ConnectorCategory
from app.services.connectors.data_sources.unifi_syslog import (
    UniFiSyslogConnector,
    parse_unifi_syslog,
)

logger = logging.getLogger(__name__)

# Syslog priority/facility parsing
SYSLOG_PATTERN = re.compile(
    r'^<(?P<priority>\d{1,3})>'
    r'(?:(?P<version>\d)\s+)?'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)?'
    r'(?:\s+(?P<procid>\S+))?'
    r'(?:\s+(?P<msgid>\S+))?'
    r'(?:\s+-\s+)?'
    r'(?P<message>.*)',
    re.DOTALL
)

# Simple BSD syslog format
BSD_SYSLOG_PATTERN = re.compile(
    r'^<(?P<priority>\d{1,3})>'
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<message>.*)',
    re.DOTALL
)


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(self, server: 'SyslogServer'):
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Syslog UDP server ready to receive messages")

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        """Handle incoming syslog datagram."""
        source_ip = addr[0]
        try:
            message = data.decode('utf-8', errors='replace').strip()
            logger.debug(f"Received syslog from {source_ip}: {message[:200]}")

            # Queue the message for async processing
            asyncio.create_task(self.server.process_message(message, source_ip))

        except Exception as e:
            logger.error(f"Error processing syslog from {source_ip}: {e}")

    def error_received(self, exc):
        logger.error(f"Syslog UDP error: {exc}")

    def connection_lost(self, exc):
        logger.warning(f"Syslog UDP connection lost: {exc}")


class SyslogServer:
    """
    Async syslog server that receives and processes log messages.

    Maps incoming syslog messages to connectors based on source IP,
    parses the messages, and creates NormalizedAlert records.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5514):
        self.host = host
        self.port = port
        self.transport = None
        self.protocol = None
        self._running = False
        self._connector_cache: dict[str, tuple[Connector, dict]] = {}
        self._cache_ttl = 300  # 5 minutes
        self._cache_timestamps: dict[str, float] = {}

    async def start(self):
        """Start the syslog server."""
        if self._running:
            logger.warning("Syslog server already running")
            return

        loop = asyncio.get_event_loop()

        try:
            self.transport, self.protocol = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self),
                local_addr=(self.host, self.port),
            )
            self._running = True
            logger.info(f"Syslog server started on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start syslog server: {e}")
            raise

    async def stop(self):
        """Stop the syslog server."""
        if self.transport:
            self.transport.close()
            self._running = False
            logger.info("Syslog server stopped")

    def parse_syslog(self, message: str) -> dict:
        """Parse a syslog message into components."""
        # Try RFC 5424 format first
        match = SYSLOG_PATTERN.match(message)
        if match:
            return match.groupdict()

        # Try BSD format
        match = BSD_SYSLOG_PATTERN.match(message)
        if match:
            return match.groupdict()

        # Return raw message if no pattern matches
        return {
            "priority": "14",  # Default: user.info
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": "unknown",
            "message": message,
        }

    async def get_connector_for_source(
        self, source_ip: str, db: AsyncSession
    ) -> Optional[tuple[Connector, dict]]:
        """
        Find the connector configured to receive from this source IP.

        Returns tuple of (connector, decrypted_config) or None.
        """
        import time

        # Check cache
        cache_key = source_ip
        if cache_key in self._connector_cache:
            cache_time = self._cache_timestamps.get(cache_key, 0)
            if time.time() - cache_time < self._cache_ttl:
                return self._connector_cache[cache_key]

        # Query for UniFi syslog connectors
        result = await db.execute(
            select(Connector).where(
                and_(
                    Connector.connector_type == "unifi_syslog",
                    Connector.status == ConnectorStatus.CONNECTED,
                    Connector.category == ConnectorCategory.DATA_SOURCE,
                )
            )
        )
        connectors = result.scalars().all()

        # Find connector that accepts this source IP
        for connector in connectors:
            config = connector.config or {}
            allowed_ips = config.get("allowed_ips", [])

            # If no IP filter, accept all
            if not allowed_ips or source_ip in allowed_ips:
                # Cache the result
                self._connector_cache[cache_key] = (connector, config)
                self._cache_timestamps[cache_key] = time.time()
                return connector, config

        logger.warning(f"No connector found for syslog source {source_ip}")
        return None

    async def process_message(self, raw_message: str, source_ip: str):
        """Process a syslog message and create an alert if applicable."""
        async with AsyncSessionLocal() as db:
            try:
                # Find connector for this source
                result = await self.get_connector_for_source(source_ip, db)
                if not result:
                    logger.debug(f"Ignoring syslog from unconfigured source: {source_ip}")
                    return

                connector, config = result

                # Parse the syslog envelope
                syslog_parts = self.parse_syslog(raw_message)
                message_content = syslog_parts.get("message", raw_message)

                # Parse the UniFi-specific content
                event_type, parsed_data = parse_unifi_syslog(message_content)

                # Check if this event type should be processed based on categories
                categories = config.get("categories", [])
                if categories and not self._event_matches_categories(event_type, categories):
                    logger.debug(f"Event {event_type} doesn't match configured categories")
                    return

                # Build the raw alert data
                raw_alert = {
                    "event_type": event_type,
                    "parsed": parsed_data,
                    "raw_message": raw_message,
                    "source_ip": source_ip,
                    "timestamp": self._parse_timestamp(syslog_parts.get("timestamp")),
                    "hostname": syslog_parts.get("hostname", "unknown"),
                    "priority": syslog_parts.get("priority", "14"),
                }

                # Create the connector instance for normalization
                unifi_connector = UniFiSyslogConnector(
                    connector_id=connector.id,
                    config=config,
                    credentials={},  # Syslog doesn't need credentials for receiving
                )

                # Normalize the alert
                alert = unifi_connector.normalize_alert(raw_alert)

                # Set the organization_id from the connector
                alert.organization_id = connector.organization_id

                # Check for duplicates (same external_id within a short window)
                existing = await db.execute(
                    select(NormalizedAlert.id).where(
                        and_(
                            NormalizedAlert.organization_id == connector.organization_id,
                            NormalizedAlert.connector_id == connector.id,
                            NormalizedAlert.external_id == alert.external_id,
                        )
                    ).limit(1)
                )

                if existing.scalar():
                    logger.debug(f"Duplicate alert {alert.external_id} - skipping")
                    return

                # Save the alert
                db.add(alert)
                await db.commit()

                logger.info(
                    f"Created alert from UniFi syslog: {alert.title[:50]}... "
                    f"(org={connector.organization_id}, severity={alert.severity})"
                )

            except Exception as e:
                logger.error(f"Error processing syslog message: {e}", exc_info=True)
                await db.rollback()

    def _event_matches_categories(self, event_type: str, categories: list[str]) -> bool:
        """Check if event type matches configured categories."""
        category_map = {
            "System": ["firmware_update", "device_adopted", "device_disconnected", "device_reconnected"],
            "Updates": ["firmware_update"],
            "Admins": ["admin_login", "admin_logout", "admin_login_failed", "config_changed"],
            "Backups": ["backup_completed", "backup_failed"],
            "Users": ["user_connected", "user_disconnected", "client_blocked"],
            "Threats": ["threat_detected", "ids_alert", "ips_block"],
            "Firewall": ["firewall_rule_triggered"],
        }

        for category in categories:
            if event_type in category_map.get(category, []):
                return True

        # Unknown events pass through if no specific filter
        if event_type == "unknown":
            return True

        return False

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse syslog timestamp to datetime."""
        if not timestamp_str:
            return datetime.utcnow()

        # Try various formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%b %d %H:%M:%S",  # BSD format
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                # Handle BSD format (no year)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.utcnow().year)
                # Remove timezone info for naive datetime
                if dt.tzinfo:
                    dt = dt.replace(tzinfo=None)
                return dt
            except ValueError:
                continue

        return datetime.utcnow()


# Global server instance
_syslog_server: Optional[SyslogServer] = None


def get_syslog_server() -> SyslogServer:
    """Get the global syslog server instance."""
    global _syslog_server
    if _syslog_server is None:
        _syslog_server = SyslogServer()
    return _syslog_server


async def start_syslog_server():
    """Start the global syslog server."""
    server = get_syslog_server()
    await server.start()


async def stop_syslog_server():
    """Stop the global syslog server."""
    global _syslog_server
    if _syslog_server:
        await _syslog_server.stop()
        _syslog_server = None
