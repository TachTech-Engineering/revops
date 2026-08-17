"""
Falco Event Buffer

In-memory buffer for Falco alerts pushed to the ingest webhook
(POST /api/v1/ingest/falco/{connector_id}). The Falco connector drains the
buffer on its normal sync cycle, so persistence, dedup, and correlation all
reuse the standard connector sync path — same design as the syslog receiver
buffer used by the UniFi connector.
"""

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.time_utils import utcnow

logger = logging.getLogger(__name__)

# Cap per connector; oldest events are dropped when full. Sized so a burst
# between two sync ticks (default 60s scheduler interval) is not lost.
MAX_EVENTS_PER_CONNECTOR = 10_000


@dataclass
class FalcoEvent:
    """A single Falco alert as received on the webhook."""

    payload: dict[str, Any]
    received_at: datetime = field(default_factory=utcnow)


class FalcoEventBuffer:
    """Thread-safe per-connector buffer of pushed Falco events."""

    def __init__(self, max_events: int = MAX_EVENTS_PER_CONNECTOR):
        self._max_events = max_events
        self._buffers: dict[UUID, deque[FalcoEvent]] = {}
        self._lock = threading.Lock()

    def push(self, connector_id: UUID, events: list[dict[str, Any]]) -> int:
        """Buffer events for a connector. Returns the number accepted."""
        with self._lock:
            buffer = self._buffers.setdefault(
                connector_id, deque(maxlen=self._max_events)
            )
            before_overflow = len(buffer) + len(events) - self._max_events
            for event in events:
                buffer.append(FalcoEvent(payload=event))
            if before_overflow > 0:
                logger.warning(
                    f"Falco buffer for connector {connector_id} overflowed; "
                    f"dropped {before_overflow} oldest events"
                )
            return len(events)

    def drain(self, connector_id: UUID, limit: int = 100) -> list[FalcoEvent]:
        """Remove and return up to `limit` buffered events for a connector."""
        with self._lock:
            buffer = self._buffers.get(connector_id)
            if not buffer:
                return []
            drained = []
            while buffer and len(drained) < limit:
                drained.append(buffer.popleft())
            return drained

    def size(self, connector_id: UUID) -> int:
        """Number of buffered events for a connector."""
        with self._lock:
            buffer = self._buffers.get(connector_id)
            return len(buffer) if buffer else 0


_buffer: FalcoEventBuffer | None = None


def get_falco_event_buffer() -> FalcoEventBuffer:
    """Get the global Falco event buffer singleton."""
    global _buffer
    if _buffer is None:
        _buffer = FalcoEventBuffer()
    return _buffer
