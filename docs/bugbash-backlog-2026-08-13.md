# Bug bash backlog — verified-but-unfixed (2026-08-13)

Fixed and deployed in `1d1b77b`: reset-token leak, SSO/SAML open redirect,
rules/queries unauthenticated, playbooks + correlation_rules IDOR, role enum,
llm_service signature + cache scoping.

Everything below was reported by a finder agent. Items marked **[verified]**
I confirmed myself; the rest are agent-reported and still need confirmation
before acting.

## Tier 1 — security, fix next

1. **[verified] `ai.py:913-1007` — LLM-generated SQL executed via raw `text()`**
   with no post-generation check that the org filter is present. Only guard is
   a keyword blocklist that permits any SELECT. Fix: parameterize + enforce
   `organization_id = :org` server-side, or drop the feature.
2. **[verified] `nl_queries.py:118-144` — `validate_sql_safety` accepts `org_id`
   and never uses it**; only checks the literal substring "organization_id"
   appears. Also `UNION` absent from DANGEROUS_KEYWORDS, and `title ILIKE
   '%{term}%'` interpolates raw user input.
3. `ioc_search.py:71-124` — `request.indicator` f-string-interpolated into
   Snowflake SQL, no escaping.
4. `auth_service.py:252` — password reset tokens in a module-level dict:
   broken across replicas (we run 3), lost on restart, unbounded growth.
5. `fonoster.py:64-83` — per-org Fonoster config written to a process-global
   singleton; one tenant's carrier credentials overwrite another's.
6. Frontend `NotesPanel.tsx:113-115,328` — `dangerouslySetInnerHTML` on
   unescaped note bodies = stored XSS; tokens are in localStorage.
7. Frontend `AIChatWidget.tsx:561-577` — same sink on LLM output.
8. Frontend `authSlice.ts:161` — no `revopsApi.util.resetApiState()` on logout;
   next tenant on the same browser sees cached prior-tenant data.

## Tier 2 — broken functionality (features that cannot work today)

9. **[verified] 14 remaining service signature mismatches** — callers pass
   `organization_id=`, signatures don't accept it → TypeError 500.
   `attack_simulation_service` (8 methods), `rule_recommendation_service`
   (6 methods). Fix = add the param AND use it to scope; note
   `rule_recommendation_service.accept/dismiss_recommendation` currently load
   by id with no org filter (latent IDOR that goes live once signatures work).
10. **[verified] `alert_poller.py:63`** — calls `list_alerts(created_at_after=)`
    but the signature is `created_after`; also treats a tuple return as a dict.
    Poller has never delivered an alert; exception swallowed.
11. **[verified] `escalation_service.py:713` `process_pending_escalations` has
    zero callers** — multi-step escalation never advances past step 1. No phone
    call after the Slack message.
12. `case_service.py:46` / `playbook_service.py:55` / `enrichment_service.py:80`
    — build rows omitting NOT NULL `organization_id` → IntegrityError.
13. `users.py`-style FastAPI route ordering: `workflows.py:240 vs 757`
    (`/node-types`), `:656 vs 717` (`/executions/recent`),
    `scheduled_reports.py:101 vs 290` (`/types`) — shadowed by `/{uuid}` → 422.
14. `presence.py:108,120,145` — `UUID(user.id)` on an already-UUID value →
    AttributeError 500 on 3 of 4 presence endpoints.
15. `ai.py:1026,1039,1075,1136` — references nonexistent model attrs
    (`NormalizedAlert.timestamp`, `.source_system`, `Incident.alert_count`);
    all three advertised chat capabilities 500.
16. Frontend `MigrationPage.tsx:900-935` — `POST /migrate/validate` doesn't
    exist; both branches hardcode `valid: true`. Every migrated rule shows a
    green "validated" badge without validation running. Also `:797-822`
    fabricates a 5-rule inventory on 404, and `:749-790` a fake 85%
    compatibility score.
17. Frontend `useWebSocket.ts:146-164` — alert socket omits `?token=`; backend
    closes 4401, client retries 10x then gives up. Real-time alerting dead.
18. Frontend `LoginPage.tsx:218-223` — network error grants a fake authenticated
    session with no tokens ("demo mode").

## Tier 3 — correctness / robustness

19. `escalation_service.py:147` — empty `rule_name` bypasses a policy's
    `rule_filter` (unrelated alert triggers a scoped policy).
20. `syslog_receiver.py:451` — 3-digit fractional timestamps parse tz-aware and
    later compare against naive → TypeError after the buffer was already
    drained; UniFi syslog alerts lost every cycle.
21. `correlation_service.py:276` — returns on first matching rule; a seeded
    `min_alerts: 1` rule starves all threshold rules.
22. `feed_service.py:375` — one transient error sets feed status ERROR forever
    (auto-sync only selects ACTIVE).
23. `connector_sync.py:75` — unreferenced `asyncio.create_task` + no in-flight
    guard + no unique constraint on
    `(organization_id, connector_id, external_id)` → duplicate alerts.
24. `case_service.py:9-32` — case numbers from a global cross-tenant counter;
    also string-sorts (breaks past 9999) and races to duplicate-key.
25. `auth.py` registration — org committed before user creation; failure
    orphans the org and burns the unique slug.
26. Login returns a distinct 403 for SSO orgs → user enumeration.
27. Websocket authorizes once; token expiry / is_active / org membership never
    re-checked for the life of the connection.
28. Refresh-token rotation is non-atomic, no reuse detection.
29. `encryption_service.py:20-40` — silently derives the Fernet key from
    SECRET_KEY when ENCRYPTION_KEY is missing *or malformed*; couples JWT key
    rotation to stored-credential decryptability.
30. Frontend: dead routes `/rules`, `/playbooks`, `/incidents/new` render blank
    (no catch-all); bulk alert actions report success when all items failed;
    escalation mutations fail silently (no toast infra).

## Mechanical checks worth adding to CI
- signature scan: API call sites passing `organization_id=` vs service params.
- AST scan: model constructions omitting a `nullable=False` `organization_id`.
Both classes accounted for most of the Tier-2 damage.
