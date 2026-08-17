"""
The receipt side of durable syslog: enqueue, flush, and what happens when the
database is unavailable.

Datagrams arrive on the event loop and must not wait on a database round trip,
so `_process_message` only enqueues and `_flush_loop` does the I/O. The
properties worth pinning down are the failure ones: a listener that blocks, a
queue that grows without bound, or a flush that loses its batch on a transient
error would each reintroduce the loss this change exists to remove.
"""

import asyncio

import pytest

from app.services.syslog_receiver import SyslogReceiverService

LINE = "<30>Aug 17 14:10:33 DK-Lab DK-Lab earlyoom[801]: mem avail"


@pytest.fixture
def receiver():
    r = SyslogReceiverService()
    # The service is a singleton, so handlers and the queue survive between
    # tests -- a message would otherwise be enqueued once per handler left
    # registered by an earlier test.
    r._handlers = {}
    r._persist_queue = asyncio.Queue(maxsize=5)
    r._dropped_since_warning = 0
    r._org_ids = {}
    r._running = True
    return r


def test_a_matched_message_is_queued_for_persistence(receiver):
    import uuid

    connector_id = uuid.uuid4()
    receiver.register_handler(connector_id=connector_id, callback=None)

    receiver._process_message(LINE, "203.0.113.5", 514)

    assert receiver._persist_queue.qsize() == 1
    queued_connector, message = receiver._persist_queue.get_nowait()
    assert queued_connector == connector_id
    assert message.hostname == "DK-Lab"


def test_the_receiver_keeps_no_process_local_message_store(receiver):
    """The bug was a buffer only one replica could see. It must stay gone."""
    assert not hasattr(receiver, "_message_buffer")
    assert not hasattr(receiver, "get_buffered_messages")


def test_a_full_queue_drops_rather_than_blocking_the_listener(receiver):
    """A datagram handler that blocks stops the listener for every connector."""
    import uuid

    connector_id = uuid.uuid4()
    receiver.register_handler(connector_id=connector_id, callback=None)

    for _ in range(20):  # queue maxsize is 5
        receiver._process_message(LINE, "203.0.113.5", 514)

    assert receiver._persist_queue.qsize() == 5
    assert receiver._dropped_since_warning == 15


@pytest.mark.asyncio
async def test_a_failed_flush_puts_the_batch_back(receiver, monkeypatch):
    """A transient database error must not consume the messages."""
    import uuid

    connector_id = uuid.uuid4()
    receiver.register_handler(connector_id=connector_id, callback=None)
    receiver._process_message(LINE, "203.0.113.5", 514)
    receiver._process_message(LINE, "203.0.113.5", 514)
    assert receiver._persist_queue.qsize() == 2

    class _Boom:
        async def __aenter__(self):
            raise RuntimeError("database is down")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", lambda: _Boom())

    with pytest.raises(RuntimeError):
        await receiver._flush_once()

    assert receiver._persist_queue.qsize() == 2, "the batch must be retried, not dropped"


@pytest.mark.asyncio
async def test_an_empty_queue_flushes_to_nothing(receiver):
    assert await receiver._flush_once() == 0


@pytest.mark.asyncio
async def test_the_flush_loop_survives_a_failing_pass(receiver, monkeypatch):
    """A dead flusher is a silent listener, so the loop must not exit on error."""
    passes = {"n": 0}

    async def sometimes_fails(batch_size=500):
        passes["n"] += 1
        if passes["n"] == 1:
            raise RuntimeError("transient")
        if passes["n"] >= 3:
            receiver._running = False
        return 0

    monkeypatch.setattr(receiver, "_flush_once", sometimes_fails)

    await receiver._flush_loop(interval=0)

    assert passes["n"] >= 3, "the loop kept running after a failing pass"
