"""
Rule converter behavioral suite (SPL / YARA-L / AQL).

Each corpus entry is converted and then verified on three axes:
  1. the generated code is valid Python;
  2. metadata expectations hold (threshold, scheduled recommendation, honest
     TODOs for unsupported/remapped constructs, inert rules fail closed);
  3. where behavioral cases are given, the generated rule(event) is EXECUTED
     and must reproduce the source rule's match semantics.

The corpus doubles as regression coverage for bugs found in the 2026-08-13
converter audit: missing IN support, alert-storm `return True` stubs,
tstats/datamodel recommended as streaming, YARA-L != inversion and silent
UDM field remapping, PCRE named groups in rex patterns, and inconsistent
severity/recommendedType casing across engines.
"""

# ruff: noqa: E501  -- corpus entries are verbatim source-format rules
import ast
import sys
from pathlib import Path

import pytest

# Generated code imports `panther_sdk` -- the vendored copy lives in app/lib.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "lib"))

from app.services.converter_service import ConverterService, SourceFormat  # noqa: E402

CORPUS = [
    # --- SPL: core filter semantics ---
    {
        "name": "spl_simple_and",
        "fmt": "spl",
        "src": 'index=okta eventType="user.session.start" outcome.result=FAILURE',
        "events": [
            ({"eventType": "user.session.start", "outcome": {"result": "FAILURE"}}, True),
            ({"eventType": "user.session.start", "outcome": {"result": "SUCCESS"}}, False),
            ({"eventType": "user.logout", "outcome": {"result": "FAILURE"}}, False),
        ],
    },
    {
        "name": "spl_wildcard",
        "fmt": "spl",
        "src": "index=aws sourcetype=aws:cloudtrail eventName=Delete*",
        "events": [
            ({"eventName": "DeleteBucket"}, True),
            ({"eventName": "CreateBucket"}, False),
        ],
    },
    {
        "name": "spl_or_not",
        "fmt": "spl",
        "src": "index=wineventlog (EventCode=4625 OR EventCode=4624) NOT user=admin*",
        "events": [
            ({"EventCode": 4625, "user": "bob"}, True),
            ({"EventCode": 4624, "user": "alice"}, True),
            ({"EventCode": 4625, "user": "admin1"}, False),
            ({"EventCode": 1102, "user": "bob"}, False),
        ],
    },
    {
        "name": "spl_in_list",
        "fmt": "spl",
        "src": 'index=aws eventName IN ("ConsoleLogin", "AssumeRole")',
        "events": [
            ({"eventName": "ConsoleLogin"}, True),
            ({"eventName": "AssumeRole"}, True),
            ({"eventName": "PutObject"}, False),
        ],
    },
    {
        "name": "spl_numeric_compare",
        "fmt": "spl",
        "src": "index=web sourcetype=access_combined status>=500",
        "events": [
            ({"status": 500}, True),
            ({"status": 503}, True),
            ({"status": 404}, False),
        ],
    },
    {
        "name": "spl_quoted_phrase",
        "fmt": "spl",
        "src": 'index=linux "Failed password" user=root',
        "events": None,  # raw-text search semantics; just require valid python
    },
    {
        "name": "spl_stats_threshold",
        "fmt": "spl",
        "src": "index=okta eventType=user.session.start outcome.result=FAILURE\n"
        "| stats count by actor.alternateId\n| where count > 5",
        "events": [
            ({"eventType": "user.session.start", "outcome": {"result": "FAILURE"}}, True),
        ],
        "expect_threshold": 5,
    },
    {
        "name": "spl_eval_lower_where",
        "fmt": "spl",
        "src": 'index=aws | eval u=lower(userIdentity.userName) | where u="root"',
        "events": None,
    },
    {
        "name": "spl_regex_filter",
        "fmt": "spl",
        "src": 'index=win | regex user="^svc_"',
        "events": None,
    },
    {
        "name": "spl_cidrmatch",
        "fmt": "spl",
        "src": 'index=fw | where cidrmatch("10.0.0.0/8", src_ip)',
        "events": None,
    },
    {
        "name": "spl_rex_extract",
        "fmt": "spl",
        "src": 'index=linux | rex field=_raw "user=(?<user>\\w+)" | search user=root',
        "events": None,
    },
    {
        "name": "spl_lookup",
        "fmt": "spl",
        "src": "index=proxy | lookup threat_intel domain AS dest_domain OUTPUT is_threat | search is_threat=true",
        "events": None,
        "expect_todo": True,
        "expect_scheduled": True,
    },
    {
        "name": "spl_tstats_datamodel",
        "fmt": "spl",
        "src": "| tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.src",
        "events": None,
        "expect_scheduled": True,
    },
    {
        "name": "spl_dedup_table",
        "fmt": "spl",
        "src": "index=aws eventName=ConsoleLogin errorMessage=* | dedup userIdentity.arn | table userIdentity.arn, sourceIPAddress",
        "events": None,
    },
    {
        "name": "spl_not_equal",
        "fmt": "spl",
        "src": "index=aws eventName=ConsoleLogin responseElements.ConsoleLogin!=Success",
        "events": [
            ({"eventName": "ConsoleLogin", "responseElements": {"ConsoleLogin": "Failure"}}, True),
            ({"eventName": "ConsoleLogin", "responseElements": {"ConsoleLogin": "Success"}}, False),
        ],
    },
    {
        "name": "spl_in_wildcard",
        "fmt": "spl",
        "src": 'index=aws eventName IN ("Delete*", "StopInstances")',
        "events": [
            ({"eventName": "DeleteBucket"}, True),
            ({"eventName": "StopInstances"}, True),
            ({"eventName": "RunInstances"}, False),
        ],
    },
    # --- YARA-L ---
    {
        "name": "yaral_basic",
        "fmt": "yaral",
        "src": """rule failed_login_block {
  meta:
    author = "secops"
    description = "Blocked login"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
  condition:
    $e
}""",
        "events": [
            ({"eventType": "USER_LOGIN", "action": "BLOCK"}, True),
            ({"eventType": "USER_LOGIN", "action": "ALLOW"}, False),
        ],
        "expect_remap_todo": True,
    },
    {
        "name": "yaral_neq_inversion",
        "fmt": "yaral",
        "src": """rule login_from_untrusted {
  meta:
    severity = "LOW"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.hostname != "trusted-host"
  condition:
    $e
}""",
        "events": [
            ({"eventType": "USER_LOGIN", "hostname": "evil-host"}, True),
            ({"eventType": "USER_LOGIN", "hostname": "trusted-host"}, False),
        ],
    },
    {
        "name": "yaral_regex_or",
        "fmt": "yaral",
        "src": """rule suspicious_process {
  meta:
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.command_line = /powershell.*-enc/ or $e.target.process.command_line = /certutil.*-decode/
  condition:
    $e
}""",
        "events": None,
    },
    # --- AQL (python target) ---
    {
        "name": "aql_basic",
        "fmt": "aql",
        "src": "SELECT sourceip, username FROM events WHERE eventid=4625 AND username LIKE '%admin%' LAST 60 MINUTES",
        "events": None,
    },
    {
        "name": "aql_groupby",
        "fmt": "aql",
        "src": "SELECT sourceip, COUNT(*) FROM events WHERE logsourceid=43 GROUP BY sourceip HAVING COUNT(*) > 10 LAST 1 HOURS",
        "events": None,
    },
]


class ShimEvent(dict):
    """Panther-style event with deep_get, for module-level generated rules."""

    def deep_get(self, path, default=None):
        cur = self
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur


def _install_enhanced_dialect_shim():
    """The enhanced converter emits `from panther_sdk import detection, PantherEvent`
    and `from panther_sdk.helpers import deep_get` (official-SDK style). Provide
    stub modules so that dialect can be executed and behaviorally tested."""
    import types

    import panther_sdk

    if hasattr(panther_sdk, "detection"):
        return

    class _Severity:
        def __getattr__(self, name):
            return name

    class _Rule:
        pass

    det = types.ModuleType("panther_sdk.detection")
    det.Rule = _Rule
    det.Severity = _Severity()
    helpers = types.ModuleType("panther_sdk.helpers")

    def deep_get(event, path, default=None):
        cur = event
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    helpers.deep_get = deep_get
    panther_sdk.detection = det
    panther_sdk.PantherEvent = dict
    panther_sdk.helpers = helpers
    sys.modules["panther_sdk.detection"] = det
    sys.modules["panther_sdk.helpers"] = helpers


def exec_rule_module(source_code: str):
    """Exec generated code; return a callable rule(event) -> bool."""
    _install_enhanced_dialect_shim()
    mod: dict = {}
    exec(compile(source_code, "<generated>", "exec"), mod)
    from panther_sdk.detection import Rule as EnhancedRule
    from panther_sdk.detections import Rule

    classes = [
        v
        for v in mod.values()
        if isinstance(v, type)
        and issubclass(v, (Rule, EnhancedRule))
        and v not in (Rule, EnhancedRule)
    ]
    if classes:
        assert len(classes) == 1, f"expected 1 Rule subclass, got {len(classes)}"
        inst = classes[0]()
        return lambda ev: inst.rule(ev)
    if "rule" in mod and callable(mod["rule"]):
        return lambda ev: mod["rule"](ShimEvent(ev))
    raise AssertionError("no Rule subclass or module-level rule() found")


@pytest.fixture(scope="module")
def service():
    return ConverterService()


@pytest.mark.parametrize("entry", CORPUS, ids=[e["name"] for e in CORPUS])
@pytest.mark.asyncio
async def test_converter_corpus(service, entry):
    r = await service.convert(
        spl=entry["src"],
        rule_id=f"Custom.Test.{entry['name']}",
        class_name=None,
        severity=None,
        source_format=SourceFormat(entry["fmt"]),
    )

    code = r["sourceCode"]
    todos = r["todos"]

    # 1. valid python
    ast.parse(code)

    # 2. metadata expectations
    assert r["recommendedType"] in ("streaming", "scheduled"), "normalized casing"
    assert r["severity"] == r["severity"].upper(), "normalized severity casing"
    if entry.get("expect_todo"):
        assert todos, "expected TODOs for unsupported feature"
    if entry.get("expect_scheduled"):
        assert r["recommendedType"] == "scheduled"
    if "expect_threshold" in entry:
        assert r["threshold"] == entry["expect_threshold"]
    if entry.get("expect_remap_todo"):
        assert any("remapped" in t for t in todos), "field remapping must be surfaced"

    # Inert rules (nothing converted) must FAIL CLOSED, never alert-on-everything.
    if any("inert" in t.lower() for t in todos):
        assert exec_rule_module(code)({"any": "event"}) is False

    # 3. behavioral cases
    if entry.get("events"):
        rule_fn = exec_rule_module(code)
        for i, (event, expected) in enumerate(entry["events"]):
            got = rule_fn(event)
            assert bool(got) == expected, f"case {i}: event={event} expected {expected}, got {got}"
