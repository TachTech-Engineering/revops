"""
RFC 3164 hostname extraction, and the timestamp trap that comes with it.

Every line this network's UniFi device sends used to land in the unparsed
fallback with hostname "unknown", which made the log-search host filter useless
for the only device feeding it. Two things in the real traffic broke the
pattern: the hostname is sent twice ("... DK-Lab DK-Lab earlyoom[801]:"), and
tags contain slashes ("/usr/bin/unifi-mq-broker[2460]:").

Making the pattern match is only half of it. RFC 3164 timestamps carry no
timezone, and this sender is five hours behind UTC. Had the newly-matching
branch adopted the parsed timestamp, every message would have sorted older than
`since` in UniFiSyslogConnector.fetch_alerts and been filtered out -- silently
ending UniFi alert generation. Those messages therefore keep receipt time, and
that is asserted here so it cannot be "tidied up" later.
"""

from datetime import datetime

import pytest

from app.core.time_utils import utcnow
from app.services.connectors.data_sources.unifi_syslog import UniFiSyslogConnector
from app.services.syslog_receiver import SyslogReceiverService

# Verbatim from production (packages/backend raw_log_events, 2026-08-17).
REAL_LINES = [
    (
        "<30>Aug 17 14:10:33 DK-Lab DK-Lab earlyoom[801]: mem avail:  1606 of  3946 MiB (40.71%)",
        "DK-Lab",
        "earlyoom",
        "801",
    ),
    (
        "<30>Aug 17 14:10:00 DK-Lab DK-Lab systemd[1]: Finished system activity accounting tool.",
        "DK-Lab",
        "systemd",
        "1",
    ),
    (
        "<30>Aug 17 14:07:55 DK-Lab DK-Lab /usr/bin/unifi-mq-broker[2460]: MEM usage flows=595",
        "DK-Lab",
        "/usr/bin/unifi-mq-broker",
        "2460",
    ),
]


@pytest.fixture
def receiver():
    return SyslogReceiverService()


@pytest.mark.parametrize(("raw", "host", "tag", "pid"), REAL_LINES)
def test_real_unifi_lines_yield_a_hostname(receiver, raw, host, tag, pid):
    parsed = receiver._parse_message(raw, "46.110.82.112", 514)

    assert parsed is not None
    assert parsed.hostname == host, "the host filter is only as good as this"
    assert parsed.app_name == tag
    assert parsed.process_id == pid


def test_classic_single_hostname_rfc3164_still_parses(receiver):
    """The textbook form must not regress while accommodating the duplicate."""
    parsed = receiver._parse_message(
        "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick", "1.2.3.4", 514
    )

    assert parsed.hostname == "mymachine"
    assert parsed.app_name == "su"
    assert parsed.process_id is None
    assert parsed.message == "'su root' failed for lonvick"


def test_line_with_no_tag_still_yields_a_hostname(receiver):
    parsed = receiver._parse_message(
        "<30>Aug 17 14:10:33 DK-Lab a message with no tag at all", "1.2.3.4", 514
    )

    assert parsed.hostname == "DK-Lab"
    assert parsed.message == "a message with no tag at all"


def test_two_different_tokens_are_not_collapsed(receiver):
    """Only an exact repeat is absorbed, so a real second field is not eaten."""
    parsed = receiver._parse_message(
        "<30>Aug 17 14:10:33 hostA hostB sshd[9]: accepted", "1.2.3.4", 514
    )

    assert parsed.hostname == "hostA"
    assert "hostB" in parsed.message


def test_rfc3164_uses_receipt_time_not_the_devices_local_clock(receiver):
    """The regression guard.

    RFC 3164 has no timezone. Adopting the device's wall clock would put every
    message from a non-UTC device hours in the past, where fetch_alerts drops
    it as older than `since`.
    """
    before = utcnow()
    parsed = receiver._parse_message(
        "<30>Aug 17 14:10:33 DK-Lab DK-Lab earlyoom[801]: mem avail", "1.2.3.4", 514
    )
    after = utcnow()

    assert before <= parsed.timestamp <= after
    # The device's claim is kept rather than discarded.
    assert parsed.device_timestamp == "Aug 17 14:10:33"


def test_a_local_clock_device_still_produces_alerts(receiver):
    """The failure this would have caused, stated directly.

    A device five hours behind UTC, polled for anything since the last sync a
    few minutes ago: its messages must not all sort as too old.
    """
    from datetime import timedelta

    since = utcnow() - timedelta(minutes=5)
    parsed = receiver._parse_message(
        "<30>Aug 17 14:10:33 DK-Lab DK-Lab earlyoom[801]: mem avail", "1.2.3.4", 514
    )

    assert parsed.timestamp >= since, "fetch_alerts would have filtered this out"


def test_zoned_formats_keep_their_own_timestamp(receiver):
    """RFC 5424 and UniFi CEF carry an explicit zone, so they are unambiguous."""
    rfc5424 = receiver._parse_message(
        "<34>1 2024-01-15T12:34:56.123Z myhost app 42 ID - the message", "1.2.3.4", 514
    )
    assert rfc5424.timestamp == datetime(2024, 1, 15, 12, 34, 56, 123000)
    assert rfc5424.hostname == "myhost"

    cef = receiver._parse_message(
        "Jan  5 12:34:56 2024-01-15T12:34:56.123Z DK Dream Machine Pro "
        "CEF:0|Ubiquiti|UniFi OS|4.0|1001|Threat Detected|",
        "1.2.3.4",
        514,
    )
    assert cef.timestamp == datetime(2024, 1, 15, 12, 34, 56, 123000)
    assert cef.hostname == "DK Dream Machine Pro"


@pytest.mark.parametrize("sentinel", ["unknown", "UNKNOWN", "", "   ", None])
def test_unknown_sentinel_is_stored_as_null(sentinel):
    """ "unknown" must not reach the store, where it reads as a real hostname."""
    assert UniFiSyslogConnector._known(sentinel) is None


def test_a_real_hostname_survives():
    assert UniFiSyslogConnector._known("DK-Lab") == "DK-Lab"
