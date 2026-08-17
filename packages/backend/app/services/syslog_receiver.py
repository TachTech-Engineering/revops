"""
Syslog Receiver Service

A singleton service that listens for syslog messages over UDP/TCP
and routes them to registered handlers based on source IP or message patterns.
"""

import asyncio
import contextlib
import logging
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional
from uuid import UUID

from app.core.time_utils import utcnow

logger = logging.getLogger(__name__)

# Fractional seconds in an ISO-8601 timestamp, e.g. the ".123" in
# "2024-01-15T12:34:56.123Z". Anchored on HH:MM:SS so a dotted date or a
# dotted timezone name can never be mistaken for it.
_ISO_FRACTION_RE = re.compile(r"(?<=\d{2}:\d{2}:\d{2})\.(\d+)")

# "Jan  5 12:34:56" (RFC 3164, no year).
_RFC3164_TS_FORMAT = "%Y %b %d %H:%M:%S"


def parse_syslog_timestamp(ts_str: str | None) -> datetime:
    """Parse a syslog timestamp into a **naive UTC** datetime.

    Naive UTC is the app-wide convention (see ``app.core.time_utils.utcnow``):
    every ``DateTime`` column is ``TIMESTAMP WITHOUT TIME ZONE`` and consumers
    compare these values against naive datetimes. Returning a tz-aware value
    raises ``TypeError: can't compare offset-naive and offset-aware datetimes``
    in the consumer, which compares against ``since`` only after the messages
    have already been claimed -- so the raise silently destroys them.

    ``datetime.fromisoformat(ts_str[:26])`` used to do this job and was width
    dependent: ".123456789Z" truncated to a naive value, ".123Z" kept the
    offset and came back tz-aware, and other widths could slice mid-offset and
    raise. Every fractional width (0-9+ digits), an explicit offset, a "Z"
    suffix, an absent timestamp and unparseable junk all resolve to naive UTC
    here.
    """
    ts_str = (ts_str or "").strip()
    if not ts_str:
        return utcnow()

    # RFC 3164: "Jan  5 12:34:56" -- no year, so assume the current one.
    try:
        return datetime.strptime(f"{utcnow().year} {ts_str}", _RFC3164_TS_FORMAT)
    except ValueError:
        pass

    parsed = _parse_iso8601(ts_str)
    if parsed is not None:
        return parsed

    logger.debug("Unparseable syslog timestamp %r; falling back to now", ts_str)
    return utcnow()


def _parse_iso8601(ts_str: str) -> datetime | None:
    """Parse an ISO-8601 timestamp to naive UTC, or None if it isn't one."""
    candidate = ts_str
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"

    # fromisoformat only accepts 3- or 6-digit fractions; normalise any width
    # (and drop sub-microsecond precision, which datetime cannot represent).
    candidate = _ISO_FRACTION_RE.sub(
        lambda m: "." + m.group(1)[:6].ljust(6, "0"),
        candidate,
        count=1,
    )

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


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
    # The wall clock the device put in an RFC 3164 line. That format carries no
    # timezone (RFC 3164 sec 4.1.2), so it cannot be converted to UTC without
    # knowing the sender's zone -- `timestamp` is receipt time for those
    # messages and this keeps the device's claim rather than discarding it.
    device_timestamp: str | None = None

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
            logger.debug(
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
        # Depth of the hand-off queue below. Not a message store -- messages
        # live in Postgres; this only covers the gap between receipt and the
        # next flush.
        self._buffer_max_size = 10000
        self._lock = asyncio.Lock()

        # Hand-off to the flusher that writes messages to Postgres.
        #
        # Datagrams are delivered on the event loop and must not wait on a
        # database round trip, so _process_message only enqueues; _flush_loop
        # does the I/O. The queue is bounded: a flood that outruns the database
        # is dropped here with a warning rather than growing until the pod is
        # OOM-killed, which would lose everything already queued as well.
        self._persist_queue: asyncio.Queue[tuple[UUID, SyslogMessage]] = asyncio.Queue(
            maxsize=self._buffer_max_size
        )
        self._flush_task: asyncio.Task | None = None
        # connector_id -> organization_id, so the flusher does not re-query per
        # message. Connectors do not change organization.
        self._org_ids: dict[UUID, UUID] = {}
        self._dropped_since_warning = 0

        # Syslog parsing patterns
        # RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        #
        # Two departures from a naive reading of the RFC, both taken from real
        # UniFi traffic:
        #
        # * The hostname is often sent twice ("... DK-Lab DK-Lab earlyoom[801]:").
        #   A relay that inserts the hostname in front of a line the origin
        #   already stamped produces this. The repeat is matched by backreference
        #   so only an exact duplicate is absorbed -- two genuinely different
        #   tokens are left alone rather than one being silently swallowed.
        # * The tag can contain '/' ("/usr/bin/unifi-mq-broker[2460]:"). The tag
        #   is therefore "everything up to the PID bracket or the colon", not
        #   \S+? -- which could never match at all here, because it cannot span
        #   the space introduced by the duplicated hostname. That failure is why
        #   every one of these lines fell through to the unparsed fallback and
        #   was recorded with hostname "unknown".
        self._rfc3164_pattern = re.compile(
            r"<(\d+)>"  # Priority
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp
            r"(\S+)\s+"  # Hostname
            r"(?:\3\s+)?"  # Same hostname repeated by a relay
            r"([^\s:\[]+)"  # Tag
            r"(?:\[(\d+)\])?:\s*"  # Optional PID
            r"(.*)"  # Message
        )

        # Same shape with no "tag:" at all. Without this a tagless line loses
        # its hostname to the fallback, and the host filter goes blind for the
        # device -- which is the whole point of parsing this format.
        self._rfc3164_no_tag_pattern = re.compile(
            r"<(\d+)>"  # Priority
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp
            r"(\S+)\s+"  # Hostname
            r"(?:\3\s+)?"  # Same hostname repeated by a relay
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
        # [<PRI>]TIMESTAMP TIMESTAMP HOSTNAME CEF:0|Vendor|Product|Version|EventID|Name|...
        #
        # The priority prefix is optional because some senders include it. It
        # has to be tolerated *here*, ahead of the RFC 3164 patterns: with a
        # <PRI> in front, a CEF line otherwise falls through to those, where
        # the ISO timestamp sits in the hostname position and would be stored
        # as the hostname. A plainly wrong host is worse than a missing one --
        # it reads as real in a filter.
        self._unifi_cef_pattern = re.compile(
            r"(?:<\d+>)?"  # Optional priority
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

        # Nothing received is durable until this is running.
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_loop())
            logger.info("Syslog persistence flusher started")

    async def stop(self) -> None:
        """Stop the syslog receiver."""
        # Stop accepting first, then cancel the flusher -- cancellation makes a
        # final flush pass, so anything already queued is written rather than
        # dropped on a graceful shutdown.
        self._running = False

        if self._flush_task is not None:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
            self._flush_task = None

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

    # NOTE: there is deliberately no get_buffered_messages()/get_buffer_size()
    # here any more. Received messages go to the syslog_ingest_events staging
    # table, and connectors claim them from there. A process-local buffer is
    # exactly what caused messages to be dropped: datagrams land on whichever
    # replica the Service picks, the sync runs on whichever replica reaches the
    # connector first, and the two are rarely the same one. Use
    # syslog_event_buffer.claim_events / count_pending instead.

    @staticmethod
    def to_payload(message: SyslogMessage) -> dict:
        """Serialize a parsed message for the staging table.

        Field for field rather than the raw line alone, so a drain rebuilds
        what this replica actually parsed instead of re-parsing with whatever
        parser version happens to be running then.
        """
        return {
            "timestamp": message.timestamp.isoformat(),
            "facility": message.facility,
            "severity": message.severity,
            "hostname": message.hostname,
            "app_name": message.app_name,
            "process_id": message.process_id,
            "message": message.message,
            "raw": message.raw,
            "source_ip": message.source_ip,
            "source_port": message.source_port,
            "device_timestamp": message.device_timestamp,
        }

    @staticmethod
    def from_payload(payload: dict) -> SyslogMessage:
        """Rebuild a message claimed from the staging table."""
        raw_ts = payload.get("timestamp")
        try:
            timestamp = datetime.fromisoformat(raw_ts) if raw_ts else utcnow()
        except (TypeError, ValueError):
            timestamp = utcnow()

        return SyslogMessage(
            timestamp=timestamp,
            facility=int(payload.get("facility") or 1),
            severity=int(payload.get("severity") or 6),
            hostname=payload.get("hostname") or "unknown",
            app_name=payload.get("app_name") or "unknown",
            process_id=payload.get("process_id"),
            message=payload.get("message") or "",
            raw=payload.get("raw") or "",
            source_ip=payload.get("source_ip") or "",
            source_port=int(payload.get("source_port") or 0),
            device_timestamp=payload.get("device_timestamp"),
        )

    def _enqueue_for_persist(self, connector_id: UUID, message: SyslogMessage) -> None:
        """Hand a matched message to the flusher without blocking the listener."""
        try:
            self._persist_queue.put_nowait((connector_id, message))
        except asyncio.QueueFull:
            # Dropping the newest is the wrong end to drop from, but evicting
            # the oldest means a message already accepted is discarded to make
            # room -- and at this depth the database is not keeping up either
            # way. Counted rather than logged per message so a flood does not
            # turn into a log flood.
            self._dropped_since_warning += 1
            if self._dropped_since_warning % 1000 == 1:
                logger.warning(
                    "Syslog persist queue is full (%s deep); dropped %s message(s) so far",
                    self._persist_queue.qsize(),
                    self._dropped_since_warning,
                )

    async def _flush_loop(self, interval: float = 1.0, batch_size: int = 500) -> None:
        """Write queued messages to the staging table.

        Runs for the life of the receiver. Never lets an exception end it: a
        dead flusher is a silent listener, which is the failure this whole
        change exists to remove.
        """
        while self._running:
            try:
                await asyncio.sleep(interval)
                await self._flush_once(batch_size)
            except asyncio.CancelledError:
                # Shutting down: make a final attempt so a graceful stop does
                # not discard what is already queued.
                with contextlib.suppress(Exception):
                    await self._flush_once(batch_size)
                raise
            except Exception:
                logger.exception("Syslog flush failed; messages stay queued for the next pass")

    async def _flush_once(self, batch_size: int = 500) -> int:
        """Drain the queue into Postgres. Returns the number persisted."""
        batch: list[tuple[UUID, SyslogMessage]] = []
        while len(batch) < batch_size:
            try:
                batch.append(self._persist_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not batch:
            return 0

        from app.db.session import AsyncSessionLocal
        from app.services import syslog_event_buffer

        by_connector: dict[UUID, list[dict]] = defaultdict(list)
        for connector_id, message in batch:
            by_connector[connector_id].append(self.to_payload(message))

        persisted = 0
        try:
            async with AsyncSessionLocal() as db:
                for connector_id, payloads in by_connector.items():
                    org_id = await self._organization_for(db, connector_id)
                    if org_id is None:
                        # The connector was deleted between registration and
                        # now. Its handler is stale; drop rather than retry
                        # forever against a row that will never exist.
                        logger.warning(
                            "No organization for syslog connector %s; dropping %s message(s)",
                            connector_id,
                            len(payloads),
                        )
                        continue
                    persisted += await syslog_event_buffer.push_events(
                        db, connector_id, org_id, payloads
                    )
                await db.commit()
        except Exception:
            # Put them back so the next pass retries. Order within a connector
            # is re-established by received_at, which was stamped at receipt.
            for item in batch:
                with contextlib.suppress(asyncio.QueueFull):
                    self._persist_queue.put_nowait(item)
            raise

        if persisted:
            logger.debug("Persisted %s syslog message(s)", persisted)
        return persisted

    async def _organization_for(self, db, connector_id: UUID) -> UUID | None:
        """Cached connector -> organization lookup."""
        if connector_id in self._org_ids:
            return self._org_ids[connector_id]

        from sqlalchemy import text

        org_id = (
            await db.execute(
                text("SELECT organization_id FROM connectors WHERE id = :cid"),
                {"cid": connector_id},
            )
        ).scalar()
        if org_id is not None:
            self._org_ids[connector_id] = org_id
        return org_id

    def _process_message(self, raw_message: str, source_ip: str, source_port: int) -> None:
        """Parse and route a syslog message to registered handlers."""
        # Per-message logging is debug: this runs on every datagram, and at
        # real syslog volume INFO here costs more than the messages do.
        logger.debug(f"Processing syslog message from {source_ip}: {raw_message[:80]}")
        parsed = self._parse_message(raw_message, source_ip, source_port)
        if not parsed:
            logger.warning(f"Failed to parse syslog message: {raw_message[:100]}")
            return
        logger.debug(
            f"Parsed syslog: hostname={parsed.hostname}, app={parsed.app_name}, "
            f"handlers={len(self._handlers)}"
        )

        # Route to matching handlers
        for connector_id, handler in self._handlers.items():
            logger.debug(
                f"Checking handler {connector_id}: source_ips={handler.source_ips}, "
                f"patterns={[p.pattern for p in handler.hostname_patterns]}"
            )
            if self._matches_handler(parsed, handler):
                logger.debug(f"Handler {connector_id} MATCHED - queueing message")
                try:
                    # Queue for the flusher rather than buffering in this
                    # process: the replica that receives a datagram is usually
                    # not the one that runs the connector's sync, so a
                    # process-local buffer is drained by nobody.
                    self._enqueue_for_persist(connector_id, parsed)

                    # Also call the callback if provided
                    if handler.callback:
                        handler.callback(parsed)
                except Exception as e:
                    logger.error(f"Error in syslog handler for {connector_id}: {e}")
            else:
                logger.debug(f"Handler {connector_id} did NOT match")

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

        # Try RFC 3164.
        #
        # `timestamp` is receipt time, NOT the parsed one. RFC 3164 timestamps
        # carry no timezone, so a device on local time reads as its UTC offset
        # in the past -- this network's sender is five hours behind. Those
        # messages would then all sort older than `since` in
        # UniFiSyslogConnector.fetch_alerts and be filtered out, silently
        # ending alert generation. Receipt time is what this receiver can
        # actually know; the device's claim is kept in device_timestamp.
        # Formats that DO carry a zone (RFC 5424, UniFi CEF) still use their
        # own timestamp above -- those are unambiguous.
        match = self._rfc3164_pattern.match(raw)
        if match:
            pri = int(match.group(1))
            return SyslogMessage(
                timestamp=utcnow(),
                facility=pri >> 3,
                severity=pri & 0x07,
                hostname=match.group(3),
                app_name=match.group(4),
                process_id=match.group(5),
                message=match.group(6),
                raw=raw,
                source_ip=source_ip,
                source_port=source_port,
                device_timestamp=match.group(2),
            )

        match = self._rfc3164_no_tag_pattern.match(raw)
        if match:
            pri = int(match.group(1))
            return SyslogMessage(
                timestamp=utcnow(),
                facility=pri >> 3,
                severity=pri & 0x07,
                hostname=match.group(3),
                app_name="unknown",
                process_id=None,
                message=match.group(4),
                raw=raw,
                source_ip=source_ip,
                source_port=source_port,
                device_timestamp=match.group(2),
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
        """Parse various timestamp formats to a naive UTC datetime."""
        return parse_syslog_timestamp(ts_str)

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
