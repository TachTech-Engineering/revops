# Bug bash backlog — 2026-08-13

## Fixed and deployed

**`1d1b77b`** (first pass): password-reset token returned in the API response
(anonymous account takeover); SSO + SAML open redirect leaking access/refresh
tokens; `rules.py`/`queries.py` reachable unauthenticated (detection-rule CRUD
+ SSRF via `X-Panther-Host`); `playbooks.py` and `correlation_rules.py` with
zero org filtering (cross-tenant read/mutate/execute); `UserRoleType(role.upper())`
always raising so role changes were impossible; four models built without their
NOT NULL `organization_id`.

**`a451ab1`** (second pass — the list below):

- LLM-generated SQL executed with no enforced tenant filter (`/ai/ask`), and
  `nl_queries.validate_sql_safety` accepting `org_id` and never using it. Both
  now go through `app/core/sql_guard.py`: single SELECT, no set operations, and
  every `organization_id` literal must equal the caller's org.
- `ioc_search` interpolating a raw indicator into Snowflake SQL.
- Stored XSS in `NotesPanel` (note bodies) and `AIChatWidget` (LLM output +
  unfiltered link href).
- RTK Query cache never reset on logout → next tenant saw cached data.
- `enrichment_service.enrich_alert` running every org's pipelines;
  `rule_recommendation` accept/dismiss/dedupe unscoped; `attack_simulation`
  `get_run` id-only.
- 16 service methods rejecting the `organization_id` their callers passed
  (TypeError 500 across simulations, recommendations, enrichment, AI summaries).
- `alert_poller` calling `list_alerts` with the wrong kwarg and treating a tuple
  as a dict — it had never delivered an alert.
- `process_pending_escalations` with zero callers (multi-step escalation never
  advanced); now scheduled, under a Postgres advisory lock so 3 replicas don't
  page on-call three times.
- Route shadowing hiding `/workflows/node-types`,
  `/workflows/executions/recent`, `/scheduled-reports/types` behind `/{uuid}`
  (422). `list_report_types` also gained the auth dep it never had.
- `presence.py` calling `UUID()` on an already-UUID value (3 endpoints 500'd).
- `ai.py` chat referencing `NormalizedAlert.timestamp`, `.source_system`,
  `Incident.alert_count` — none of which exist.
- `MigrationPage` fabricating validation results, rule inventory and a
  compatibility score when its endpoints 404'd.
- Alert websocket never sending `?token=`, so real-time alerting was dead.

---

## Still open

Ordered by severity. None of these are verified-and-trivial; each needs a
judgment call or a schema/infra change.

### Security / correctness

1. **Password reset tokens live in a module-level dict**
   (`auth_service.py:252`). We run 3 replicas, so a reset minted on one pod is
   rejected by the others; tokens are also lost on restart and never bounded.
   Needs a DB table (or Redis) with an index on the token hash and a TTL.
   *Note:* the reset flow is now safe but still effectively broken in prod —
   worth doing before advertising password reset to users.

2. **Fonoster config is a process-global singleton** (`fonoster.py:64-83`).
   One tenant's carrier credentials overwrite another's; escalation calls can
   dial out under the wrong account. Needs per-org storage like every other
   connector credential.

3. **Websocket authorizes once and never re-checks** — token expiry,
   `is_active`, and org membership are all snapshotted at connect. A disabled
   or moved user keeps receiving their old org's broadcasts until they
   disconnect.

4. **Refresh-token rotation is non-atomic and has no reuse detection**
   (`auth.py:211-225`). Concurrent refreshes both succeed; a stolen token is
   never detected. Needs a compare-and-revoke plus token-family invalidation.

5. **Login reveals whether an account exists** — SSO orgs get a distinct 403
   naming the provider, non-existent emails get a generic 401.

6. **`encryption_service` silently derives the Fernet key from `SECRET_KEY`**
   when `ENCRYPTION_KEY` is missing *or malformed* (`except Exception: pass`).
   A typo'd key encrypts under the wrong key with no error, and rotating
   `SECRET_KEY` makes stored SSO/connector credentials undecryptable. Should
   fail loudly instead.

7. **`notifications.py:271`** — `/notifications/internal/create` is not
   role-gated; any viewer can forge notifications attributed to arbitrary
   `user_email` within their org.

8. **`escalation.py:353-367`** — `remove_escalation_step` never constrains the
   step to the `{policy_id}` in the path, so any step in the org can be deleted
   through any policy's URL.

### Reliability

9. **Escalation `rule_filter` bypassed when `rule_name` is empty**
   (`escalation_service.py:147`) — an unrelated alert can trigger a policy
   scoped to one rule. The request schema defaults `rule_name` to `""`.

10. **UniFi syslog alerts lost every cycle** (`syslog_receiver.py:451`) —
    3-digit fractional timestamps parse tz-aware, then compare against a naive
    datetime and raise. The buffer is already drained at that point, so the
    messages are gone.

11. **One matching single-alert correlation rule starves the rest**
    (`correlation_service.py:276`) — returns on first match with no ordering,
    and a seeded `min_alerts: 1` rule exists for every org, so threshold rules
    never accumulate a window.

12. **A transient error takes a feed permanently offline**
    (`feed_service.py:375`) — status is set to ERROR and auto-sync only selects
    ACTIVE. Needs a retry/backoff rather than a terminal state.

13. **Connector sync can double-run and duplicate alerts**
    (`connector_sync.py:75`) — unreferenced `asyncio.create_task`, no
    in-flight guard, and no unique constraint on
    `(organization_id, connector_id, external_id)`. The constraint is the real
    fix and needs a migration.

14. **Case numbers come from a global cross-tenant counter**
    (`case_service.py:9-32`) — leaks platform-wide volume, races to duplicate
    key, and string-sorts (breaks past 9999).

15. **Registration orphans an organization** when user creation fails after the
    org is committed, permanently burning the unique slug.

16. **Failed escalation notifications are never retried** and the step advances
    anyway (`escalation_service.py:182-229`).

17. **One Redis hiccup silences live alerts for every connected dashboard**
    (`notification_service.py:170`) — the listen loop exits and only restarts on
    a new `subscribe()`.

18. **Zero-step escalation policies re-select forever**
    (`_send_step_notification` returns without clearing `next_escalation_at`) —
    a no-op every 60s, but noisy.

### Frontend

19. **`LoginPage.tsx:218-223` grants a fake authenticated session** on any
    network error ("demo mode") — user lands in the shell with no token, then
    gets bounced by the first 401.

20. **Dead routes render blank** — `/rules`, `/playbooks`, `/incidents/new` are
    linked from MobileNav/Layout/AlertCorrelationInsights but not in `App.tsx`,
    and there is no `path="*"` fallback.

21. **Bulk alert actions report success when every item failed** — the
    `{success, failed}` response is discarded.

22. **Mutations fail silently across the app** (escalation policies, exec
    export) — `console.error` only; there is no toast infrastructure.

23. **`AlertsPage.tsx` is orphaned** (322 lines, never imported) and nine
    dashboard widget types are unreachable because the backend `WidgetType`
    enum doesn't contain them.

---

## Worth adding to CI

Two mechanical scans would have caught most of the Tier-2 damage:

- API call sites passing `organization_id=` vs. the target service signature.
- Model constructions omitting a `nullable=False` `organization_id`.

Caveat learned the hard way: the signature scan only sees
`service_obj.method(...)` calls. `enrichment_service` exposes bare module-level
functions, so its three mismatches were invisible to it — widen the scan to
plain-name calls before trusting a green result.
