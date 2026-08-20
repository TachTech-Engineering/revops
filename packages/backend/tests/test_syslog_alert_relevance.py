"""
Only security-relevant syslog lines become alerts.

Every line used to become one. Measured in production 2026-08-20, a single
drain produced 1,939 "low" alerts and 1 "critical", all named "UniFi Syslog
Event", while the pending queue was topped by 3,803 coredns retries, 1,718
WiFi station-tracker dumps and 764 "sysstat-collect.service: Succeeded". A
real detection buried under two thousand pieces of telemetry is a detection
nobody sees.

Nothing is discarded: every line is written to raw_log_events and searchable
from Log Search. That store did not exist when this connector was written.
"""

import uuid

import pytest

from app.services.connectors.data_sources.unifi_syslog import (
    ALERT_WORTHY_CATEGORIES,
    UniFiSyslogConnector,
)
from app.services.syslog_receiver import SyslogReceiverService

# Verbatim shapes taken from the production backlog.
NOISE = [
    "<30>Aug 20 14:10:33 DK-Lab DK-Lab unifi[1]: Failed to send request to coredns: Post http://x",
    "<30>Aug 20 14:10:33 DK-Lab DK-Lab systemd[1]: sysstat-collect.service: Succeeded.",
    "<30>Aug 20 14:10:33 DK-Lab DK-Lab systemd[1]: Finished system activity accounting tool.",
    '<30>Aug 20 14:10:33 DK-Lab DK-Lab stahtd[7222]: [STA-TRACKER].stahtd_dump_event(): {"op":1}',
    "<30>Aug 20 14:10:33 DK-Lab DK-Lab dnsmasq[1]: read /run/dnsmasq.dns.conf.d/hosts.d//leases",
    "<30>Aug 20 14:10:33 DK-Lab DK-Lab earlyoom[801]: mem avail: 1606 of 3946 MiB (40.71%)",
]

SECURITY = [
    (
        "<30>Aug 20 14:10:33 DK-Lab DK-Lab suricata[1]: [1:2010935:3] ET POLICY Suspicious "
        "[Classification: Misc Attack] [Priority: 2] {TCP} 10.0.0.5:443 -> 10.0.0.9:51234",
        "ids_alert",
        "high",
    ),
    (
        "<30>Aug 20 14:10:33 DK-Lab DK-Lab ubnt-systemmgr[1]: admin failed login from 203.0.113.9",
        "admin_login",
        "medium",
    ),
    (
        "<30>Aug 20 14:10:33 DK-Lab DK-Lab kernel[1]: [WAN_IN-block] IN=eth0 OUT=eth1 "
        "SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=22",
        "firewall_block",
        "info",
    ),
]


@pytest.fixture
def connector():
    return UniFiSyslogConnector(connector_id=uuid.uuid4(), config={}, credentials={})


def _parse(line):
    return SyslogReceiverService()._parse_message(line, "203.0.113.5", 514)


@pytest.mark.parametrize("line", NOISE)
def test_operational_telemetry_does_not_become_an_alert(connector, line):
    assert connector._normalize_syslog_message(_parse(line)) is None


@pytest.mark.parametrize(("line", "category", "severity"), SECURITY)
def test_security_events_still_alert(connector, line, category, severity):
    alert = connector._normalize_syslog_message(_parse(line))

    assert alert is not None, f"{category} must still raise an alert"
    assert alert.rule_id == category
    assert alert.severity == severity
    # Named for what it is. Every alert used to read "UniFi Syslog Event",
    # so a list of them was indistinguishable.
    assert alert.rule_name != "UniFi Syslog Event"


def test_ids_hits_survive_tag_stripping(connector):
    """The regression that nearly shipped.

    The parser strips the program tag, and the IDS pattern anchors on
    "suricata"/"snort". Classifying the stripped message missed every IDS hit
    -- the single most important category -- so classification runs against
    the raw line.
    """
    alert = connector._normalize_syslog_message(_parse(SECURITY[0][0]))
    assert alert is not None and alert.rule_id == "ids_alert"


def test_a_connector_can_widen_its_categories():
    """Deployments differ; the default is a floor, not a ceiling."""
    noisy = UniFiSyslogConnector(
        connector_id=uuid.uuid4(),
        config={"alert_categories": ["system_event"]},
        credentials={},
    )
    alert = noisy._normalize_syslog_message(_parse(NOISE[1]))
    assert alert is not None, "an operator who asks for system_event should get it"


def test_the_defaults_are_security_categories():
    assert "ids_alert" in ALERT_WORTHY_CATEGORIES
    assert "threat_detection" in ALERT_WORTHY_CATEGORIES
    # Routine telemetry must not be in the default set.
    assert "system_event" not in ALERT_WORTHY_CATEGORIES
    assert "dhcp_event" not in ALERT_WORTHY_CATEGORIES


def _cef(name: str, event_id: str, severity: str = "3") -> str:
    return (
        f"Jan  5 12:34:56 2026-08-20T14:10:33.123Z DK-Lab "
        f"CEF:0|Ubiquiti|UniFi Network|4.0|{event_id}|{name}|{severity}|src=10.0.0.5"
    )


# Volumes measured in production on 2026-08-20.
ROUTINE_CEF = [
    ("WiFi Client Roamed", "402"),  # 1,434
    ("WiFi Client Connected", "400"),  # 726
    ("WiFi Client Disconnected", "401"),  # 684
    ("Wired Client Connected", "403"),  # 65
    ("Wired Client Disconnected", "404"),  # 63
]


@pytest.mark.parametrize(("name", "event_id"), ROUTINE_CEF)
def test_routine_cef_telemetry_does_not_alert(connector, name, event_id):
    """UniFi's CEF stream is 96% client association churn.

    The first version of this filter exempted CEF entirely, on the assumption
    that a structured vendor event was inherently security-relevant. Production
    said otherwise: 2,972 connect/disconnect/roam events against 109 threat
    detections.
    """
    assert connector._normalize_syslog_message(_parse(_cef(name, event_id))) is None


@pytest.mark.parametrize(
    ("name", "event_id"), [("Threat Detected", "200"), ("Network Accessed", "544")]
)
def test_meaningful_cef_events_still_alert(connector, name, event_id):
    alert = connector._normalize_syslog_message(_parse(_cef(name, event_id)))

    assert alert is not None
    # Named for what happened. These used to be called "200" and "544".
    assert alert.rule_name == name


def test_an_unrecognised_cef_event_still_alerts(connector):
    """The filter is a denylist on purpose.

    Silently dropping a detection nobody anticipated is far worse than one
    extra low-value alert, so anything unrecognised comes through.
    """
    alert = connector._normalize_syslog_message(_parse(_cef("Rogue AP Detected", "999")))

    assert alert is not None
    assert alert.rule_name == "Rogue AP Detected"
