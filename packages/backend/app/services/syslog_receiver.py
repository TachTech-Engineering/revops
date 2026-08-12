"""
Syslog Receiver Service

A singleton service that listens for syslog messages over UDP/TCP
and routes them to registered handlers based on source IP or message patterns.
"""

import asyncio
import logging
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID

from app.core.time_utils import utcnow

logger = logging.getLogger(__name__)


@dataclass
class SyslogMessage:
    """Parsed syslog message."""

    timestamp: datetime
    facility: int
    severity: int
    hostname: str
    app_name: str
    process_id: str | None
    message: str
    raw: str
    source_ip: str
    source_port: int

    @property
    def facility_name(self) -> str:
        """Human-readable facility name."""
        facilities = [
            "kern",
            "user",
            "mail",
            "daemon",
            "auth",
            "syslog",
            "lpr",
            "news",
            "uucp",
            "cron",
            "authpriv",
            "ftp",
            "ntp",
            "audit",
            "alert",
            "clock",
            "local0",
            "local1",
            "local2",
            "local3",
            "local4",
            "local5",
            "local6",
            "local7",
        ]
        return (
            facilities[self.facility]
            if self.facility < len(facilities)
            else f"facility{self.facility}"
        )

    @property
    def severity_name(self) -> str:
        """Human-readable severity name."""
        severities = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
        return (
            severities[self.severity]
            if self.severity < len(severities)
            else f"severity{self.severity}"
        )


@dataclass
class SyslogHandler:
    """Handler registration for syslog messages."""

    connector_id: UUID
    callback: Callable[[SyslogMessage], None]
    source_ips: set[str] = field(default_factory=set)  # Empty = all IPs
    hostname_patterns: list[re.Pattern] = field(default_factory=list)  # Empty = all hostnames
    app_name_patterns: list[re.Pattern] = field(default_factory=list)  # Empty = all apps


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(self, receiver: "SyslogReceiverService"):
        self.receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process received UDP datagram."""
        try:
            message = data.decode("utf-8", errors="replace")
            logger.info(
                f"Syslog UDP received from {addr[0]}:{addr[1]} - {len(data)} bytes: {message[:100]}"
            )
            self.receiver._process_message(message, addr[0], addr[1])
        except Exception as e:
            logger.error(f"Error processing syslog datagram: {e}")


class SyslogTCPHandler(asyncio.Protocol):
    """TCP protocol handler for syslog messages."""

    def __init__(self, receiver: "SyslogReceiverService"):
        self.receiver = receiver
        self.buffer = ""
        self.addr: tuple[str, int] = ("", 0)

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Handle new TCP connection."""
        peername = transport.get_extra_info("peername")
        if peername:
            self.addr = peername
        logger.debug(f"Syslog TCP connection from {self.addr}")

    def data_received(self, data: bytes) -> None:
        """Process received TCP data."""
        try:
            self.buffer += data.decode("utf-8", errors="replace")
            # Process complete messages (newline-delimited)
            while "\n" in self.buffer:
                message, self.buffer = self.buffer.split("\n", 1)
                if message.strip():
                    self.receiver._process_message(message, self.addr[0], self.addr[1])
        except Exception as e:
            logger.error(f"Error processing syslog TCP data: {e}")


class SyslogReceiverService:
    """
    Singleton service for receiving and routing syslog messages.

    Supports both UDP and TCP syslog protocols.
    """

    _instance: Optional["SyslogReceiverService"] = None

    def __new__(cls) -> "SyslogReceiverService":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._handlers: dict[UUID, SyslogHandler] = {}
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._running = False
        self._message_buffer: dict[UUID, list[SyslogMessage]] = defaultdict(list)
        self._buffer_max_size = 10000  # Max messages per connector
        self._lock = asyncio.Lock()

        # Syslog parsing patterns
        # RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        self._rfc3164_pattern = re.compile(
            r"<(\d+)>"  # Priority
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp
            r"(\S+)\s+"  # Hostname
            r"(\S+?)(?:\[(\d+)\])?:\s*"  # Tag and optional PID
            r"(.*)"  # Message
        )

        # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        self._rfc5424_pattern = re.compile(
            r"<(\d+)>"  # Priority
            r"(\d+)\s+"  # Version
            r"(\S+)\s+"  # Timestamp
            r"(\S+)\s+"  # Hostname
            r"(\S+)\s+"  # App-name
            r"(\S+)\s+"  # Procid
            r"(\S+)\s+"  # Msgid
            r"(?:\[.*?\]|-)\s*"  # Structured data (skip)
            r"(.*)"  # Message
        )

        # UniFi CEF format:
        # TIMESTAMP TIMESTAMP HOSTNAME CEF:0|Vendor|Product|Version|EventID|Name|...
        self._unifi_cef_pattern = re.compile(
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # BSD timestamp
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+"  # ISO timestamp
            r"(.+?)\s+"  # Hostname (e.g., "DK Dream Machine Pro")
            r"CEF:(\d+)\|"  # CEF version
            r"([^|]*)\|"  # Vendor
            r"([^|]*)\|"  # Product
            r"([^|]*)\|"  # Version
            r"([^|]*)\|"  # Event ID
            r"(.*)"  # Rest of message
        )

    async def start(
        self, udp_port: int = 514, tcp_port: int = 514, bind_address: str = "0.0.0.0"
    ) -> None:
        """Start the syslog receiver on specified ports."""
        if self._running:
            return

        loop = asyncio.get_event_loop()

        # Start UDP listener
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self), local_addr=(bind_address, udp_port)
            )
            self._udp_transport = transport
            logger.info(f"Syslog UDP receiver started on {bind_address}:{udp_port}")
        except Exception as e:
            logger.error(f"Failed to start syslog UDP receiver: {e}")

        # Start TCP listener
        try:
            server = await loop.create_server(
                lambda: SyslogTCPHandler(self), bind_address, tcp_port
            )
            self._tcp_server = server
            logger.info(f"Syslog TCP receiver started on {bind_address}:{tcp_port}")
        except Exception as e:
            logger.error(f"Failed to start syslog TCP receiver: {e}")

        self._running = True

    async def stop(self) -> None:
        """Stop the syslog receiver."""
        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None

        self._running = False
        logger.info("Syslog receiver stopped")

    def register_handler(
        self,
        connector_id: UUID,
        callback: Callable[[SyslogMessage], None],
        source_ips: list[str] | None = None,
        hostname_patterns: list[str] | None = None,
        app_name_patterns: list[str] | None = None,
    ) -> None:
        """
        Register a handler for syslog messages.

        Args:
            connector_id: UUID of the connector registering
            callback: Function to call with each matching message
            source_ips: List of source IPs to match (empty = all)
            hostname_patterns: Regex patterns for hostname matching
            app_name_patterns: Regex patterns for app name matching
        """
        handler = SyslogHandler(
            connector_id=connector_id,
            callback=callback,
            source_ips=set(source_ips or []),
            hostname_patterns=[re.compile(p, re.IGNORECASE) for p in (hostname_patterns or [])],
            app_name_patterns=[re.compile(p, re.IGNORECASE) for p in (app_name_patterns or [])],
        )
        self._handlers[connector_id] = handler
        logger.info(f"Registered syslog handler for connector {connector_id}")

    def unregister_handler(self, connector_id: UUID) -> None:
        """Remove a handler registration."""
        if connector_id in self._handlers:
            del self._handlers[connector_id]
            logger.info(f"Unregistered syslog handler for connector {connector_id}")

    def get_buffered_messages(self, connector_id: UUID, limit: int = 100) -> list[SyslogMessage]:
        """
        Get and clear buffered messages for a connector.

        Args:
            connector_id: UUID of the connector
            limit: Maximum messages to return

        Returns:
            List of buffered SyslogMessage objects
        """
        messages = self._message_buffer[connector_id][:limit]
        self._message_buffer[connector_id] = self._message_buffer[connector_id][limit:]
        return messages

    def get_buffer_size(self, connector_id: UUID) -> int:
        """Get current buffer size for a connector."""
        return len(self._message_buffer[connector_id])

    def _process_message(self, raw_message: str, source_ip: str, source_port: int) -> None:
        """Parse and route a syslog message to registered handlers."""
        logger.info(f"Processing syslog message from {source_ip}: {raw_message[:80]}")
        parsed = self._parse_message(raw_message, source_ip, source_port)
        if not parsed:
            logger.warning(f"Failed to parse syslog message: {raw_message[:100]}")
            return
        logger.info(
            f"Parsed syslog: hostname={parsed.hostname}, app={parsed.app_name}, "
            f"handlers={len(self._handlers)}"
        )

        # Route to matching handlers
        for connector_id, handler in self._handlers.items():
            logger.info(
                f"Checking handler {connector_id}: source_ips={handler.source_ips}, "
                f"patterns={[p.pattern for p in handler.hostname_patterns]}"
            )
            if self._matches_handler(parsed, handler):
                logger.info(f"Handler {connector_id} MATCHED - buffering message")
                try:
                    # Buffer the message
                    buffer = self._message_buffer[connector_id]
                    if len(buffer) < self._buffer_max_size:
                        buffer.append(parsed)
                    else:
                        # Remove oldest message
                        buffer.pop(0)
                        buffer.append(parsed)
                    logger.info(
                        f"Buffered message for {connector_id}, buffer size now: {len(buffer)}"
                    )

                    # Also call the callback if provided
                    if handler.callback:
                        handler.callback(parsed)
                except Exception as e:
                    logger.error(f"Error in syslog handler for {connector_id}: {e}")
            else:
                logger.info(f"Handler {connector_id} did NOT match")

    def _parse_message(self, raw: str, source_ip: str, source_port: int) -> SyslogMessage | None:
        """Parse a raw syslog message."""
        raw = raw.strip()

        # Try UniFi CEF format first (most specific)
        match = self._unifi_cef_pattern.match(raw)
        if match:
            return SyslogMessage(
                timestamp=self._parse_timestamp(match.group(2)),  # ISO timestamp
                facility=1,  # user
                severity=6,  # info (will be overridden by CEF severity if present)
                hostname=match.group(3),  # e.g., "DK Dream Machine Pro"
                app_name=match.group(6),  # Product (e.g., "UniFi OS")
                process_id=None,
                message=f"CEF:{match.group(4)}|{match.group(5)}|{match.group(6)}|{match.group(7)}|{match.group(8)}|{match.group(9)}",
                raw=raw,
                source_ip=source_ip,
                source_port=source_port,
            )

        # Try RFC 5424 format
        match = self._rfc5424_pattern.match(raw)
        if match:
            pri = int(match.group(1))
            return SyslogMessage(
                timestamp=self._parse_timestamp(match.group(3)),
                facility=pri >> 3,
                severity=pri & 0x07,
                hostname=match.group(4),
                app_name=match.group(5),
                process_id=match.group(6) if match.group(6) != "-" else None,
                message=match.group(8),
                raw=raw,
                source_ip=source_ip,
                source_port=source_port,
            )

        # Try RFC 3164
        match = self._rfc3164_pattern.match(raw)
        if match:
            pri = int(match.group(1))
            return SyslogMessage(
                timestamp=self._parse_timestamp(match.group(2)),
                facility=pri >> 3,
                severity=pri & 0x07,
                hostname=match.group(3),
                app_name=match.group(4),
                process_id=match.group(5),
                message=match.group(6),
                raw=raw,
                source_ip=source_ip,
                source_port=source_port,
            )

        # Fallback: minimal parsing for standard syslog
        if raw.startswith("<"):
            try:
                end_pri = raw.index(">")
                pri = int(raw[1:end_pri])
                message = raw[end_pri + 1 :].strip()
                return SyslogMessage(
                    timestamp=utcnow(),
                    facility=pri >> 3,
                    severity=pri & 0x07,
                    hostname="unknown",
                    app_name="unknown",
                    process_id=None,
                    message=message,
                    raw=raw,
                    source_ip=source_ip,
                    source_port=source_port,
                )
            except (ValueError, IndexError):
                pass

        # Last resort: accept any message
        if raw and len(raw) > 5:
            return SyslogMessage(
                timestamp=utcnow(),
                facility=1,
                severity=6,
                hostname="unknown",
                app_name="unknown",
                process_id=None,
                message=raw,
                raw=raw,
                source_ip=source_ip,
                source_port=source_port,
            )

        return None

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse various timestamp formats to datetime."""
        # RFC 3164 format: "Jan  5 12:34:56"
        try:
            # Add current year
            current_year = utcnow().year
            parsed = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
            return parsed
        except ValueError:
            pass

        # RFC 5424 format: "2024-01-15T12:34:56.123Z" or similar
        try:
            # Handle various ISO formats
            ts_str = ts_str.replace("Z", "+00:00")
            if "." in ts_str:
                return datetime.fromisoformat(ts_str[:26])  # Truncate microseconds
            return datetime.fromisoformat(ts_str)
        except ValueError:
            pass

        return utcnow()

    def _matches_handler(self, message: SyslogMessage, handler: SyslogHandler) -> bool:
        """Check if a message matches a handler's filters."""
        # Check source IP
        if handler.source_ips and message.source_ip not in handler.source_ips:
            return False

        # Check hostname patterns
        if handler.hostname_patterns:
            if not any(p.search(message.hostname) for p in handler.hostname_patterns):
                return False

        # Check app name patterns
        if handler.app_name_patterns:
            if not any(p.search(message.app_name) for p in handler.app_name_patterns):
                return False

        return True


# Global instance accessor
def get_syslog_receiver() -> SyslogReceiverService:
    """Get the global syslog receiver instance."""
    return SyslogReceiverService()
