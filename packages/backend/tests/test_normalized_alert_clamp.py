"""
NormalizedAlert string clamping — cheap, DB-free guard for connector syncs.

Connector normalize() methods feed unbounded external SIEM strings straight
into VARCHAR columns (Panther titles embed full command lines and are reused
as rule_name), and one over-long value aborts the whole sync batch with
StringDataRightTruncationError. The @validates hook on NormalizedAlert clamps
each bounded string field to its column width; raw_data keeps the original.
"""

import uuid

from app.db.models import NormalizedAlert


def _make_alert(**overrides) -> NormalizedAlert:
    fields = {
        "id": uuid.uuid4(),
        "connector_id": uuid.uuid4(),
        "source_type": "panther",
        "external_id": "abc123",
        "title": "some alert",
        "severity": "high",
        "status": "open",
    }
    fields.update(overrides)
    return NormalizedAlert(**fields)


def test_overlong_title_and_rule_name_are_clamped_to_column_width():
    long_title = "Crowdstrike: LOLBAS execution - " + "x" * 2000
    alert = _make_alert(title=long_title, rule_name=long_title)
    assert len(alert.title) == 1000
    assert len(alert.rule_name) == 500
    assert alert.title == long_title[:1000]
    assert alert.rule_name == long_title[:500]


def test_values_within_limits_pass_through_unchanged():
    alert = _make_alert(rule_name="Short rule")
    assert alert.title == "some alert"
    assert alert.rule_name == "Short rule"


def test_none_rule_name_is_preserved():
    assert _make_alert(rule_name=None).rule_name is None


def test_unbounded_text_column_is_not_clamped():
    # description is Text (no length) and is not in the validates list;
    # this documents that only bounded VARCHAR fields are clamped.
    alert = _make_alert(description="y" * 5000)
    assert len(alert.description) == 5000
