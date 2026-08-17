# UniFi syslog messages are buffered on one pod and drained on another

**Status: fixed 2026-08-17.** Found while verifying raw log storage. Not
introduced by that work — it predated it and affected UniFi *alerts* as much
as logs. Received messages are now staged in `syslog_ingest_events` and
claimed by whichever replica runs the sync; see "The fix" at the bottom.

## What happens

`syslog_receiver` holds received messages in a process-local dict
(`_message_buffer`). The backend runs three replicas, and the `syslog-ingress`
Service load-balances UDP across all three, so the buffer for one connector is
split across pods.

The drain happens in `ConnectorSyncScheduler`, which also runs on every pod.
Whichever replica reaches the connector first calls `fetch_alerts`, drains
*its own* buffer, and writes `last_sync_at`. Every other replica then sees the
connector as not due and skips — including the replica actually holding the
messages.

## Measured in production, 2026-08-17 ~19:35 UTC

Over a 10-minute window, with a device sending steadily:

| pod | messages buffered | drains run |
|---|---|---|
| `backend-…-prqdw` | 172 | 0 |
| `backend-…-kj84s` | 2 | 0 |
| `backend-…-ssj8w` | 0 | 4 |

`ssj8w` ran four of the five syncs and logged `fetching from buffer, got 0
messages` each time. A concurrent buffer-size log line read `buffer size now:
247` on a different pod. In the same period `raw_log_events` gained no rows.

## Why it matters

Buffered messages are never persisted. They sit in memory until the per-
connector cap (`_buffer_max_size = 10000`) evicts the oldest, or the pod
restarts and drops all of them. Anything that would have become a UniFi alert
in that window is lost, silently — the sync reports success, having found
nothing.

## The fix

The Falco path had the same shape and was already solved, so this reuses it
rather than inventing a second mechanism. `SyslogIngestEvent` +
`syslog_event_buffer` stage received messages in Postgres with at-least-once
claim semantics, so any replica can drain what any other replica received.

- **Receipt.** `_process_message` puts the parsed message on a bounded
  in-process queue and returns. Datagrams are handled on the event loop and
  must not wait on a database round trip. A flusher task writes batches to
  `syslog_ingest_events` about once a second; a failed write returns the batch
  to the queue, and the loop survives its own exceptions because a dead
  flusher is a silent listener.
- **Drain.** Both UniFi connectors claim from the table (`SKIP LOCKED`, so
  concurrent syncs take disjoint rows) instead of reading process memory. A
  claim older than `CLAIM_STALE_MINUTES` is re-takeable, so a sync that dies
  mid-drain recovers rather than losing the batch. Re-processing is harmless:
  `external_id` is a content fingerprint, so a repeat collides with
  `uq_normalized_alerts_org_connector_external`.
- **The old buffer is gone.** `get_buffered_messages`/`get_buffer_size` were
  removed rather than left in place — a process-local message store is exactly
  what caused this, and leaving one available invites its return.
  `test_connection` now reports staged rows, which is a number every replica
  agrees on.
- **Reaping.** Claimed rows are kept 24h for debugging and then purged by the
  existing hourly maintenance sweep.

Rejected stopgaps: scaling the backend to one replica (loses availability, and
the PDB assumes more than one), and pinning syslog to a dedicated
Deployment/Service (splits one connector's runtime across two workloads).
