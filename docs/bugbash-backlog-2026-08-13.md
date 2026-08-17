# Bug bash backlog — 2026-08-13

**Status: cleared.** Everything found in the 2026-08-13 bug bash has been fixed
and deployed across three passes. This file is kept as the record of what was
found and, at the bottom, the handful of things deliberately left alone.

## Pass 1 — `1d1b77b`

Password-reset token returned in the API response (anonymous account
takeover); SSO + SAML open redirect leaking access/refresh tokens;
`rules.py`/`queries.py` reachable unauthenticated (detection-rule CRUD plus
SSRF via `X-Panther-Host`); `playbooks.py` and `correlation_rules.py` with zero
org filtering; `UserRoleType(role.upper())` always raising so role changes were
impossible; four models built without their NOT NULL `organization_id`.

## Pass 2 — `a451ab1`

LLM-generated SQL executed with no enforced tenant filter, and a validator that
accepted `org_id` and never used it (now `app/core/sql_guard.py`); IOC search
interpolating a raw indicator into Snowflake SQL; stored XSS in `NotesPanel`
and `AIChatWidget`; RTK Query cache never reset on logout; `enrichment_service`
running every org's pipelines; 16 service methods rejecting the
`organization_id` their callers passed; the alert poller that had never
delivered an alert; `process_pending_escalations` with zero callers; route
shadowing hiding three endpoints behind `/{uuid}`; `presence.py` calling
`UUID()` on a UUID; `ai.py` referencing three columns that do not exist;
`MigrationPage` fabricating validation results and a compatibility score.

## Pass 3 — `84ff5ee`

Schema (migration `c1d4e7f20a83`): `password_reset_tokens` (hash-only,
single-use), `organization_telephony_config` (per-org, encrypted), and the
unique index on `normalized_alerts (organization_id, connector_id,
external_id)` with a dedupe step for pre-existing duplicates.

Auth/session: reset tokens off the module-level dict; compare-and-revoke
refresh rotation with reuse detection; login enumeration closed including the
timing oracle; websocket re-validation every 60s; atomic registration;
malformed `ENCRYPTION_KEY` fails loudly at startup.

Tenancy: per-org telephony on every call path;
`/notifications/internal/create` admin-gated; escalation step deletion scoped
to its policy.

Reliability: `rule_filter` no longer bypassed by an empty rule name; bounded
retry before an escalation step advances; zero-step policies terminate;
correlation evaluates every rule; feed retry/backoff; connector-sync in-flight
guard and per-row duplicate tolerance; per-org, numerically-sorted case
numbers; Redis listener reconnects; syslog timestamps normalise to naive UTC.

Frontend: demo-mode fake session removed; dead links repointed plus a catch-all
404; bulk actions report failure; toast mechanism wired into escalation and
incident mutations; Export disabled rather than fake; orphaned page and five
mock-only widgets deleted.

---

## Deliberately not changed

1. ~~UniFi syslog cannot be deduped by the new unique index.~~ **Fixed
   2026-08-17** (`768f69c`): all four UniFi `external_id` schemes are now
   content-derived via `content_external_id()`. Fixing it also uncovered the
   opposite bug on another path — `f"unifi-{hostname}-{ts}"` carried no message
   content, so two different events from one device in the same second
   collided and the second was silently dropped once the unique index existed.
   Accepted limit: byte-identical messages from one host with the same
   timestamp still collapse, which syslog gives no way to distinguish from a
   re-delivery.

2. **The connector-sync in-flight guard is per-process.** Two replicas can
   still start a sync for the same connector at the same time; the unique index
   is what prevents duplicate rows in that case. A cross-replica guard would
   need an advisory lock like the one in `escalation_service.py`.

3. **Nine extended dashboard widget types remain unselectable.** Four are
   backed by real endpoints and were kept; the backend `WidgetType` enum in
   `app/api/v1/dashboards.py` needs entries before they can be chosen, and a
   saved dashboard carrying one would 422. Documented at
   `widgets/index.tsx:18-33`.

4. **`app/services/syslog_server.py` is dead code** with a cross-org catch-all
   connector match. Nothing imports it (`main.py` starts `syslog_receiver`).
   Worth deleting rather than fixing.

5. **`correlation_cleanup_job.py` exposes an APScheduler `JOB_CONFIG` that
   nothing constructs** — the job never runs. The two schedulers that do run
   use the loop pattern in `connector_sync.py`.

---

## Worth adding to CI

Two mechanical scans would have caught most of the pass-2 damage:

- API call sites passing `organization_id=` versus the target service
  signature.
- Model constructions omitting a `nullable=False` `organization_id`.

Caveat learned the hard way: the signature scan only sees
`service_obj.method(...)` calls. `enrichment_service` exposes bare module-level
functions, so its three mismatches were invisible to it and it reported a clean
run. Widen the scan to plain-name calls before trusting a green result.
