"""
Regressions for the escalation + telephony fixes (bug bash 2026-08-13,
still-open items 2, 7, 8, 9, 16, 18).

All DB-free: the matching/retry logic is exercised through pure helpers, and
_send_step_notification is driven with a stub session (its zero-step and
retry paths only ever call db.commit()).
"""

import inspect
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.time_utils import utcnow
from app.db import EscalationNotificationType, EscalationStatus
from app.services.escalation_service import (
    MAX_STEP_ATTEMPTS,
    EscalationService,
    next_step_index,
    policy_matches_alert,
    step_attempt_number,
)
from app.services.fonoster import (
    TelephonyConfig,
    get_fonoster_service,
    send_escalation_call,
)

# ---------------------------------------------------------------------------
# 9. rule_filter must not be bypassed by an empty rule_name.
# ---------------------------------------------------------------------------


def test_rule_filter_does_not_match_alert_without_rule_name():
    """The API schema defaults rule_name to "", which used to skip the filter
    entirely and fire a rule-scoped policy for unrelated alerts."""
    assert not policy_matches_alert([], ["AWS.Root.Login"], "HIGH", "")
    assert not policy_matches_alert([], ["AWS.Root.Login"], "HIGH", None or "")


def test_rule_filter_matches_only_listed_rules():
    assert policy_matches_alert([], ["AWS.Root.Login"], "HIGH", "AWS.Root.Login")
    assert not policy_matches_alert([], ["AWS.Root.Login"], "HIGH", "Okta.Suspicious")


def test_empty_filters_match_everything():
    assert policy_matches_alert([], [], "HIGH", "")
    assert policy_matches_alert(None, None, "low", "Anything")


def test_severity_filter_is_case_insensitive_and_still_enforced():
    assert policy_matches_alert(["critical"], [], "CRITICAL", "")
    assert not policy_matches_alert(["critical"], [], "LOW", "")


def test_both_filters_must_match():
    assert not policy_matches_alert(["critical"], ["R1"], "CRITICAL", "")
    assert policy_matches_alert(["critical"], ["R1"], "critical", "R1")


# ---------------------------------------------------------------------------
# 16. A failed step is retried before the escalation advances.
# ---------------------------------------------------------------------------


def test_next_step_index_retries_a_failed_step():
    history = [{"step_index": 0, "success": False, "attempt": 1}]
    assert next_step_index(0, history) == 0


def test_next_step_index_advances_after_success():
    history = [{"step_index": 0, "success": True, "attempt": 1}]
    assert next_step_index(0, history) == 1


def test_next_step_index_advances_once_retries_are_exhausted():
    history = [{"step_index": 0, "success": False, "attempt": MAX_STEP_ATTEMPTS}]
    assert next_step_index(0, history) == 1


def test_next_step_index_on_empty_history():
    assert next_step_index(0, []) == 1
    assert next_step_index(0, None) == 1


def test_step_attempt_number_counts_consecutive_failures():
    assert step_attempt_number(0, []) == 1
    assert step_attempt_number(0, [{"step_index": 0, "success": False, "attempt": 1}]) == 2
    # A success resets the counter, and a different step is a fresh attempt.
    assert step_attempt_number(1, [{"step_index": 0, "success": False, "attempt": 2}]) == 1
    assert step_attempt_number(0, [{"step_index": 0, "success": True, "attempt": 1}]) == 1


class _StubSession:
    """Minimal AsyncSession stand-in: the paths under test only commit."""

    def __init__(self):
        self.commits = 0

    async def commit(self):
        self.commits += 1


def _make_escalation():
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        alert_id="alert-1",
        status=EscalationStatus.ACTIVE,
        current_step=0,
        next_escalation_at=utcnow(),
        notification_history=[],
    )


def _make_step(order=1, delay=5):
    return SimpleNamespace(
        step_order=order,
        delay_minutes=delay,
        notification_type=EscalationNotificationType.EMAIL,
        targets=["oncall@example.com"],
    )


def _make_policy(steps):
    return SimpleNamespace(
        steps=steps,
        call_message_template=None,
        sms_message_template=None,
        webhook_headers=None,
        webhook_secret=None,
    )


@pytest.mark.asyncio
async def test_failed_step_is_retried_before_advancing(monkeypatch):
    """Email delivery fails (service unconfigured) -> the step is re-armed at the
    same index instead of the primary on-call being silently skipped."""
    from app.services import escalation_service as mod

    monkeypatch.setattr(mod.email_service, "is_configured", lambda: False)

    service = EscalationService(_StubSession())
    escalation = _make_escalation()
    policy = _make_policy([_make_step(order=1), _make_step(order=2, delay=15)])

    for expected_attempt in range(1, MAX_STEP_ATTEMPTS):
        ok = await service._send_step_notification(
            escalation=escalation,
            policy=policy,
            step_index=0,
            alert_title="t",
            alert_severity="HIGH",
        )
        assert ok is False
        assert escalation.current_step == 0, "must not advance while retries remain"
        assert escalation.next_escalation_at is not None
        assert escalation.next_escalation_at > utcnow()
        last = escalation.notification_history[-1]
        assert last["attempt"] == expected_attempt
        assert last["success"] is False
        # The pre-existing record shape is preserved.
        assert {"step", "type", "sent_at", "targets", "success"} <= set(last)
        # And the sweep would re-send the same step.
        assert next_step_index(escalation.current_step, escalation.notification_history) == 0

    # Final attempt: retries exhausted, escalation moves on to step 2.
    await service._send_step_notification(
        escalation=escalation,
        policy=policy,
        step_index=0,
        alert_title="t",
        alert_severity="HIGH",
    )
    assert escalation.notification_history[-1]["attempt"] == MAX_STEP_ATTEMPTS
    assert len(escalation.notification_history) == MAX_STEP_ATTEMPTS
    assert next_step_index(escalation.current_step, escalation.notification_history) == 1


# ---------------------------------------------------------------------------
# 18. A zero-step policy must terminate, not be re-selected every 60s.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zero_step_policy_clears_next_escalation_at():
    service = EscalationService(_StubSession())
    escalation = _make_escalation()

    result = await service._send_step_notification(
        escalation=escalation,
        policy=_make_policy([]),
        step_index=0,
        alert_title="t",
        alert_severity="HIGH",
    )

    assert result is False
    assert escalation.next_escalation_at is None, (
        "a zero-step policy would otherwise be re-selected by the sweep forever"
    )
    assert escalation.status == EscalationStatus.COMPLETED


@pytest.mark.asyncio
async def test_running_past_the_last_step_terminates():
    service = EscalationService(_StubSession())
    escalation = _make_escalation()

    await service._send_step_notification(
        escalation=escalation,
        policy=_make_policy([_make_step()]),
        step_index=5,
        alert_title="t",
        alert_severity="HIGH",
    )

    assert escalation.next_escalation_at is None
    assert escalation.status == EscalationStatus.COMPLETED


def test_terminal_statuses_used_by_the_service_exist():
    """EscalationStatus has no ESCALATED/EXPIRED member; referencing them raised
    AttributeError inside the sweep."""
    assert EscalationStatus.COMPLETED
    assert EscalationStatus.CANCELLED
    for missing in ("ESCALATED", "EXPIRED"):
        assert not hasattr(EscalationStatus, missing)
    src = inspect.getsource(EscalationService)
    assert "EscalationStatus.ESCALATED" not in src
    assert "EscalationStatus.EXPIRED" not in src


# ---------------------------------------------------------------------------
# 2. Telephony config must be per organization, never a shared mutable global.
# ---------------------------------------------------------------------------


def test_telephony_service_is_not_a_shared_mutable_singleton():
    a = get_fonoster_service()
    b = get_fonoster_service()
    assert a is not b, "a shared instance lets one tenant's config leak into another's calls"

    a.config.default_caller_id = "+15550000001"
    assert b.config.default_caller_id != "+15550000001"


def test_module_has_no_global_service_instance():
    import app.services.fonoster as fono

    assert not hasattr(fono, "_telephony_service")


@pytest.mark.asyncio
async def test_escalation_call_uses_the_supplied_org_config(monkeypatch):
    captured = {}

    async def fake_make_call(self, **kwargs):
        captured["caller_id"] = self.config.default_caller_id
        captured["account_sid"] = self.config.account_sid
        return {"success": True}

    monkeypatch.setattr("app.services.fonoster.TelephonyService.make_call", fake_make_call)

    org_b = TelephonyConfig(
        provider="mock",
        api_endpoint="http://mock",
        account_sid="ORG-B-SID",
        auth_token="secret",
        default_caller_id="+15551234567",
        enabled=True,
    )

    await send_escalation_call(
        phone_number="+15559999999",
        alert_title="t",
        alert_severity="HIGH",
        alert_id="a1",
        config=org_b,
    )

    assert captured == {"caller_id": "+15551234567", "account_sid": "ORG-B-SID"}


def test_escalation_notifications_accept_a_per_org_config():
    from app.services.fonoster import send_escalation_sms

    for fn in (send_escalation_call, send_escalation_sms):
        assert "config" in inspect.signature(fn).parameters


def test_config_endpoints_never_return_the_secret():
    import app.api.v1.fonoster as api

    assert "access_key_secret" not in api.FonosterConfigResponse.model_fields
    src = inspect.getsource(api.get_fonoster_config)
    assert "access_key_secret" not in src


# ---------------------------------------------------------------------------
# 7 / 8. Role gating and path scoping.
# ---------------------------------------------------------------------------


def test_internal_notification_create_is_admin_gated():
    from app.api.v1.deps import OrgAdminDep
    from app.api.v1.notifications import create_notification_internal

    params = inspect.signature(create_notification_internal).parameters
    assert "user" in params, "endpoint must authenticate the caller"
    assert params["user"].annotation is OrgAdminDep


def test_internal_notification_create_does_not_trust_caller_identity():
    from app.api.v1.notifications import create_notification_internal

    src = inspect.getsource(create_notification_internal)
    assert "user_email=data.user_email" not in src, (
        "recipient must be validated against the caller's org, not taken verbatim"
    )
    assert "created_by=user.email" in src


def test_remove_escalation_step_is_scoped_to_the_policy_in_the_path():
    from app.api.v1.escalation import remove_escalation_step

    src = inspect.getsource(remove_escalation_step)
    assert "EscalationStep.policy_id == UUID(policy_id)" in src
    assert "EscalationPolicy.organization_id == org_id" in src
