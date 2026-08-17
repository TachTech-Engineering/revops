# UniFi syslog messages are buffered on one pod and drained on another

**Status: open.** Found 2026-08-17 while verifying raw log storage. Not
introduced by that work — this predates it and affects UniFi *alerts* as much
as it affects logs.

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

## Fix direction

The Falco path had the same shape and was already solved: `FalcoIngestEvent`
plus `falco_event_buffer` stage accepted events in Postgres with at-least-once
claim semantics, so any replica can drain what any other replica received. The
syslog receiver wants the same treatment — write to a staging table on receipt
instead of a process-local dict.

Cheaper stopgaps, both with real downsides:

- Scale the backend to one replica (loses availability, and the PDB assumes
  more than one).
- Pin syslog to a single pod via a dedicated Deployment/Service (splits the
  connector's runtime across two workloads).

The staging-table fix is the one that matches how this codebase already
handles the identical problem elsewhere.
