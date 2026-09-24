"""Cross-source alert grouping: what counts as the same event.

These cover app.services.alert_grouping, which is pure -- no database, so the
suite can run against it directly. The DB half (app.services.alert_grouping_service)
is exercised by the connector sync path.

The property under test throughout is symmetric: two reports of one event must
produce at least one fingerprint in common, and two reports of *different*
events must produce none. Over-grouping is the worse failure of the two -- a
missed grouping costs an analyst a duplicate, a false grouping hides an alert
inside somebody else's incident.
"""

from datetime import datetime

from app.db.models import NormalizedAlert
from app.services.alert_grouping import (
    alert_signature,
    candidate_keys,
    extract_entities,
    normalize_title,
)


def make_alert(
    title="Suspicious activity",
    description=None,
    tags=None,
    raw_data=None,
    mitre_techniques=None,
    source_type="test",
    rule_id=None,
) -> NormalizedAlert:
    return NormalizedAlert(
        source_type=source_type,
        external_id="x",
        title=title,
        description=description,
        severity="high",
        status="open",
        created_at_source=datetime(2026, 9, 24, 12, 0, 0),
        rule_id=rule_id,
        tags=tags or [],
        mitre_tactics=[],
        mitre_techniques=mitre_techniques or [],
        raw_data=raw_data or {},
    )


def fingerprints(alert) -> set[str]:
    return {digest for _, _, digest in candidate_keys(alert)}


# ---------------------------------------------------------------- entities


def test_entities_come_from_connector_tags():
    alert = make_alert(tags=["ip:10.0.0.5", "host:web-01", "severity:high", "event:login"])
    assert set(extract_entities(alert)) == {("ip", "10.0.0.5"), ("host", "web-01")}


def test_entities_come_from_nested_raw_data():
    alert = make_alert(raw_data={"client": {"ipAddress": "203.0.113.9"}, "actor": {"user": "bob"}})
    assert ("ip", "203.0.113.9") in extract_entities(alert)
    assert ("user", "bob") in extract_entities(alert)


def test_user_identifiers_normalize_to_one_person():
    """An analyst pivots on the account, not on the directory's spelling."""
    forms = ["alice@corp.com", "CORP\\alice", "Alice", "alice@other.example"]
    for form in forms:
        assert ("user", "alice") in extract_entities(make_alert(tags=[f"user:{form}"]))


def test_hostnames_normalize_past_the_domain():
    short = extract_entities(make_alert(tags=["host:WEB-01"]))
    fqdn = extract_entities(make_alert(tags=["hostname:web-01.corp.local"]))
    assert ("host", "web-01") in short
    assert ("host", "web-01") in fqdn


def test_ip_in_a_hostname_field_is_treated_as_an_ip():
    """Vendors put an address in the host field constantly; if that produced a
    "host" entity it would never match the same address reported as an IP."""
    assert ("ip", "10.0.0.5") in extract_entities(make_alert(tags=["hostname:10.0.0.5"]))


def test_non_identifying_values_are_not_entities():
    """These name a category, not a thing. Clustering on them would sweep
    unrelated alerts into one group, which is worse than not grouping."""
    for value in ["unknown", "N/A", "-", "system", "null"]:
        assert extract_entities(make_alert(tags=[f"user:{value}"])) == []


def test_loopback_and_unspecified_addresses_are_not_entities():
    for value in ["127.0.0.1", "0.0.0.0", "::1"]:
        assert extract_entities(make_alert(tags=[f"ip:{value}"])) == []


def test_truncated_hashes_are_rejected_but_complete_ones_are_kept():
    """Connectors emit ``sha256:abc123...`` for display. A prefix cannot match
    another vendor's full digest, so keying on it is false confidence."""
    assert extract_entities(make_alert(tags=["sha256:a1b2c3d4e5f60718..."])) == []
    full = "a" * 64
    assert ("hash", full) in extract_entities(make_alert(tags=[f"sha256:{full}"]))


def test_free_text_is_only_scraped_when_nothing_structured_exists():
    scraped = make_alert(title="Blocked traffic from 198.51.100.7")
    assert ("ip", "198.51.100.7") in extract_entities(scraped)

    # The title mentions a second address, but the structured tag is the
    # alert's actual subject -- free text mixes in remediation hosts, examples
    # and whatever else the vendor chose to print.
    structured = make_alert(title="Blocked traffic from 198.51.100.7", tags=["ip:10.0.0.5"])
    assert extract_entities(structured) == [("ip", "10.0.0.5")]


def test_entities_are_ordered_most_specific_first():
    alert = make_alert(tags=["ip:10.0.0.5", "user:alice", "host:web-01"])
    assert [kind for kind, _ in extract_entities(alert)] == ["user", "host", "ip"]


# --------------------------------------------------------------- signature


def test_title_normalization_ignores_wording_and_embedded_values():
    assert normalize_title("Brute force detected from 10.0.0.5") == normalize_title(
        "Detected brute-force from 192.168.1.1"
    )
    assert normalize_title("Failed login (attempt 14)") == normalize_title("Login failed")


def test_mitre_techniques_win_over_the_title():
    """The one taxonomy vendors share. Two products describing a brute force in
    completely different words still agree on T1110."""
    crowdstrike = make_alert(
        title="Credential access via password guessing", mitre_techniques=["T1110"]
    )
    sentinel = make_alert(title="Multiple failed sign-in attempts", mitre_techniques=["T1110.001"])

    assert alert_signature(crowdstrike) == "mitre:T1110"
    assert alert_signature(sentinel) == "mitre:T1110.001"
    assert alert_signature(make_alert(title="whatever", mitre_techniques=[])).startswith("title:")


def test_signature_falls_back_to_the_rule_when_there_is_no_usable_title():
    alert = make_alert(title="!!! ???", rule_id="rule-7")
    assert alert_signature(alert) == "rule:rule-7"


# ------------------------------------------------------------- fingerprints


def test_two_sources_reporting_one_event_share_a_fingerprint():
    """The whole point: same host, same technique, two products, one cluster."""
    crowdstrike = make_alert(
        source_type="crowdstrike",
        title="Password guessing against WEB-01",
        tags=["host:WEB-01"],
        mitre_techniques=["T1110"],
    )
    sentinel = make_alert(
        source_type="sentinel",
        title="Brute force attempt observed",
        raw_data={"device": {"hostname": "web-01.corp.local"}},
        mitre_techniques=["T1110"],
    )
    assert fingerprints(crowdstrike) & fingerprints(sentinel)


def test_a_richer_report_still_matches_a_sparser_one():
    """Sentinel knows the user and the address; Okta only the address. Keying
    each alert on a single "primary" entity would split these whenever the
    richer source happened to sync first -- which is why every entity gets a key."""
    sentinel = make_alert(tags=["user:alice", "ip:203.0.113.9"], mitre_techniques=["T1110"])
    okta = make_alert(tags=["ip:203.0.113.9"], mitre_techniques=["T1110"])
    assert fingerprints(sentinel) & fingerprints(okta)


def test_same_technique_on_different_hosts_does_not_group():
    a = make_alert(tags=["host:web-01"], mitre_techniques=["T1110"])
    b = make_alert(tags=["host:db-02"], mitre_techniques=["T1110"])
    assert not (fingerprints(a) & fingerprints(b))


def test_different_activity_on_one_host_does_not_group():
    a = make_alert(title="Brute force detected", tags=["host:web-01"])
    b = make_alert(title="Ransomware file encryption", tags=["host:web-01"])
    assert not (fingerprints(a) & fingerprints(b))


def test_alerts_with_entities_get_no_signature_only_key():
    """A signature-only key ignores which machine was hit, so letting an alert
    hold one alongside its entity keys would collapse every brute force in the
    org into a single cluster."""
    alert = make_alert(tags=["host:web-01"], mitre_techniques=["T1110"])
    assert all(kind != "signature" for kind, _, _ in candidate_keys(alert))


def test_alerts_without_entities_fall_back_to_the_signature_alone():
    alert = make_alert(title="Scheduled backup failed")
    keys = candidate_keys(alert)
    assert [kind for kind, _, _ in keys] == ["signature"]
    assert fingerprints(alert) == fingerprints(make_alert(title="Failed scheduled backup"))
    # ...but only where the words actually agree: dropping "scheduled" is a
    # different event, not a rewording of this one.
    assert fingerprints(alert) != fingerprints(make_alert(title="Backup failed"))


def test_fingerprints_are_stable_across_calls():
    """Re-syncing an alert must land it in the cluster it is already in, and
    two analysts looking at one estate must see one grouping."""
    alert = make_alert(tags=["user:alice", "ip:10.0.0.5"], mitre_techniques=["T1110"])
    assert candidate_keys(alert) == candidate_keys(alert)


def test_tag_order_does_not_change_the_fingerprints():
    a = make_alert(tags=["ip:10.0.0.5", "user:alice"], mitre_techniques=["T1110"])
    b = make_alert(tags=["user:alice", "ip:10.0.0.5"], mitre_techniques=["T1110"])
    assert candidate_keys(a) == candidate_keys(b)
