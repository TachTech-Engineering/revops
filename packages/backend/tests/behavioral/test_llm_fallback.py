"""
LLM honesty labeling for threat-hunting hypothesis generation.

generate_hypothesis must report HOW the result was produced:
- when the LLM returns a valid completion -> generated_by == "llm"
- when the LLM call raises -> the endpoint degrades to the keyword heuristic,
  returns 200 (never a 500), and labels the result generated_by == "fallback".

The LLM is mocked at llm_service.generate_completion (the single entry point the
router uses) so the test makes no real network/model call and is deterministic.
"""

import json

import pytest

from app.db.models import UserRoleType
from app.services.llm_service import llm_service

ENDPOINT = "/api/v1/threat-hunting/generate-hypothesis"


@pytest.mark.asyncio
async def test_hypothesis_labeled_llm_on_success(app_client, make_user, monkeypatch):
    org = await make_user("hyp-llm", role=UserRoleType.VIEWER)

    valid_completion = json.dumps(
        {
            "title": "Credential Dumping Hunt",
            "hypothesis": "If lsass is accessed, credential theft is observable.",
            "rationale": "Attackers dump credentials from lsass.",
            "mitre_techniques": [
                {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"}
            ],
            "data_sources": ["EDR Telemetry"],
            "indicators_to_look_for": ["lsass access"],
            "priority": "high",
            "suggested_queries": [],
        }
    )

    async def fake_generate_completion(*args, **kwargs):
        return valid_completion

    monkeypatch.setattr(llm_service, "generate_completion", fake_generate_completion)

    resp = await app_client.post(
        ENDPOINT,
        json={"description": "Hunt for credential dumping via lsass access"},
        headers=org.headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["generated_by"] == "llm"
    assert body["title"] == "Credential Dumping Hunt"


@pytest.mark.asyncio
async def test_hypothesis_labeled_fallback_when_llm_raises(app_client, make_user, monkeypatch):
    org = await make_user("hyp-fallback", role=UserRoleType.VIEWER)

    async def boom(*args, **kwargs):
        raise RuntimeError("LLM provider unavailable")

    monkeypatch.setattr(llm_service, "generate_completion", boom)

    resp = await app_client.post(
        ENDPOINT,
        json={"description": "Hunt for lateral movement across the network"},
        headers=org.headers,
    )
    # Must degrade gracefully: 200 with a heuristic result, never a 500.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["generated_by"] == "fallback"
    # The heuristic still produces a usable hypothesis.
    assert body["hypothesis"]
    assert isinstance(body["mitre_techniques"], list)
