"""Ingest-time grouping of the same real-world event seen by several sources.

Two SIEMs watching the same estate report the same thing twice: CrowdStrike and
Sentinel both flag the brute force against web-01, Okta and Entra both flag the
same impossible-travel sign-in. Each arrives on its own connector with its own
``external_id``, so ``uq_normalized_alerts_org_connector_external`` -- which is
scoped to one connector -- cannot see the duplication, and the analyst gets one
alert per vendor for one event.

This module computes a deterministic fingerprint for an incoming alert and uses
it to attach that alert to a shared :class:`AlertCluster`. Nothing is dropped:
every source's ``NormalizedAlert`` row is still written, because that row is the
handle ``alert_status_sync`` uses to push a resolution back to the SIEM the
alert came from. Suppressing rows would silently strip that ability from every
source but the first one to report. The cluster is what collapses in the UI.

The fingerprint deliberately does not call an LLM. Grouping runs on the sync
path for every alert, and it has to be reproducible: the same alert must land
in the same cluster on a re-sync, and two analysts looking at the same estate
must see the same grouping.

Matching is ``entity + signature``, time-windowed:

* **entity** -- an IP, hostname, user, workload, MAC or file hash, read from the
  normalized ``tags`` the connectors already emit (``ip:``, ``src_ip:``,
  ``host:``, ``user:``, ...), then from well-known ``raw_data`` keys, and only
  as a last resort scraped out of the title.
* **signature** -- MITRE technique IDs when the source supplies them, since that
  is the one taxonomy every vendor maps onto and the only thing that survives
  the wording changing between vendors. Otherwise a normalized bag of title
  tokens, which is all that is left to go on.

An alert yields one candidate fingerprint *per entity*, not one overall, and a
cluster owns every fingerprint of every alert in it. That matters: Sentinel may
report ``(user=alice, ip=1.2.3.4)`` where Okta reports only ``(ip=1.2.3.4)``. A
single primary-entity key would put those in different clusters whenever the
richer source happened to arrive first; matching on any shared key does not.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

# Tag prefixes the connectors already emit that name a *thing*, mapped to the
# entity kind they name. Deliberately conservative: only tags whose value
# identifies one specific entity are listed. Okta's ``device:`` tag, for one,
# carries a device *class* ("Computer"), which would merge every Okta alert in
# the org into a single cluster.
_TAG_ENTITY_KINDS: dict[str, str] = {
    "ip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "client_ip": "ip",
    "host": "host",
    "hostname": "host",
    "ap": "host",
    "gateway": "host",
    "pod": "workload",
    "container": "workload",
    "mac": "mac",
    "client_mac": "mac",
    "user": "user",
    "email": "user",
    "account": "user",
    "actor": "user",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "hash": "hash",
}

# ``raw_data`` keys carrying the same entities, matched case-insensitively at
# any depth. Vendors nest these inconsistently (``client.ipAddress``,
# ``actor.alternateId``, ``device.hostname``), so the walk looks at leaf keys
# rather than trying to know every vendor's envelope shape.
_RAW_ENTITY_KINDS: dict[str, str] = {
    "ip": "ip",
    "ipaddress": "ip",
    "clientip": "ip",
    "sourceip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "destinationip": "ip",
    "remoteip": "ip",
    "hostname": "host",
    "host": "host",
    "computername": "host",
    "devicename": "host",
    "devicednsname": "host",
    "machinename": "host",
    "user": "user",
    "username": "user",
    "user_name": "user",
    "userprincipalname": "user",
    "upn": "user",
    "email": "user",
    "emailaddress": "user",
    "accountname": "user",
    "mac": "mac",
    "macaddress": "mac",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
}

# Entity values that name a category rather than a thing. Clustering on these
# would pull unrelated alerts together, which is worse than not clustering.
_ENTITY_STOPWORDS = frozenset(
    {
        "",
        "-",
        "--",
        "n/a",
        "na",
        "none",
        "null",
        "nil",
        "unknown",
        "unspecified",
        "system",
        "localhost",
        "anonymous",
        "not available",
        "notavailable",
        "0",
        "false",
        "true",
    }
)

# Title tokens that carry no discriminating signal. Dropping them lets one
# vendor's "Detected brute force attempt" match another's "Brute force".
_TITLE_STOPWORDS = frozenset(
    {
        "alert",
        "alerts",
        "and",
        "attempt",
        "attempted",
        "been",
        "detect",
        "detected",
        "detection",
        "event",
        "events",
        "for",
        "from",
        "has",
        "have",
        "incident",
        "into",
        "new",
        "observed",
        "onto",
        "possible",
        "potential",
        "rule",
        "seen",
        "suspected",
        "that",
        "the",
        "triggered",
        "via",
        "was",
        "were",
        "with",
    }
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_LONG_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)
_COMPLETE_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)

# How deep to walk raw_data looking for entities. Vendor envelopes bury the
# interesting fields two or three levels down; past that it is list-of-evidence
# noise that produces entities belonging to other events.
_RAW_MAX_DEPTH = 3

# An alert with no usable entity at all falls back to grouping on its signature
# alone. That is the existing behaviour of the manual clusterer (it groups on
# bare title), and it is only reached when nothing identifying was found.
_SIGNATURE_ONLY_KIND = "signature"

# Priority order for choosing which entity names the cluster. A user is the most
# specific thing an analyst pivots on, a file hash the least.
_ENTITY_PRIORITY = ("user", "host", "workload", "ip", "mac", "hash", _SIGNATURE_ONLY_KIND)


def _normalize_entity(kind: str, value: Any) -> tuple[str, str] | None:
    """Canonicalize one candidate entity, or return None if it is not usable.

    Normalization has to be total: ``10.0.0.5`` from one vendor and
    ``10.000.000.005`` from another are the same host, and ``ALICE@Corp.com``
    and ``alice@corp.com`` are the same user, but only if both sides of a
    comparison agree on the spelling.
    """
    if isinstance(value, bool) or not isinstance(value, str | int):
        return None

    text = str(value).strip().strip("\"'").lower()
    if text in _ENTITY_STOPWORDS or len(text) > 255:
        return None

    if kind == "ip":
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return None
        # Loopback and 0.0.0.0 identify the reporter, not a participant, and
        # every source emits them; clustering on them merges the whole estate.
        if addr.is_loopback or addr.is_unspecified:
            return None
        return ("ip", addr.compressed)

    if kind == "mac":
        if not _MAC_RE.match(text):
            return None
        return ("mac", text.replace("-", ":"))

    if kind == "hash":
        # Connectors truncate hashes for display (``sha256:abc123...``). A
        # prefix cannot be matched against another vendor's full digest, so a
        # partial hash is not an entity worth keying on.
        if not _COMPLETE_HASH_RE.match(text):
            return None
        return ("hash", text)

    if kind == "user":
        # ``CORP\alice``, ``alice@corp.com`` and ``alice`` are one person to an
        # analyst. Reducing to the local part is what makes a cross-directory
        # match possible at all; the cost is that two different alices in two
        # different domains collide, which the time window bounds.
        local = text.split("@", 1)[0].rsplit("\\", 1)[-1].strip()
        if local in _ENTITY_STOPWORDS or len(local) < 2:
            return None
        return ("user", local)

    if kind in ("host", "workload"):
        # Strip the domain: ``web-01`` and ``web-01.corp.local`` are one host.
        short = text.split(".", 1)[0].strip()
        if short in _ENTITY_STOPWORDS or len(short) < 2:
            return None
        # A bare IP arriving in a hostname field is an IP, not a hostname.
        try:
            return ("ip", ipaddress.ip_address(text).compressed)
        except ValueError:
            pass
        return (kind, short)

    return None


def _entities_from_tags(tags: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if not isinstance(tags, list):
        return found
    for tag in tags:
        if not isinstance(tag, str) or ":" not in tag:
            continue
        prefix, _, value = tag.partition(":")
        kind = _TAG_ENTITY_KINDS.get(prefix.strip().lower())
        if kind is None:
            continue
        # Connectors append an ellipsis to truncated values; a truncated
        # identifier is not the identifier.
        if value.endswith("..."):
            continue
        entity = _normalize_entity(kind, value)
        if entity is not None:
            found.append(entity)
    return found


def _entities_from_raw(raw: Any, depth: int = 0) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if depth > _RAW_MAX_DEPTH:
        return found
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict | list):
                found.extend(_entities_from_raw(value, depth + 1))
                continue
            kind = _RAW_ENTITY_KINDS.get(str(key).strip().lower().replace("-", "_"))
            if kind is None:
                continue
            entity = _normalize_entity(kind, value)
            if entity is not None:
                found.append(entity)
    elif isinstance(raw, list):
        for item in raw[:10]:
            found.extend(_entities_from_raw(item, depth + 1))
    return found


def _entities_from_text(text: str) -> list[tuple[str, str]]:
    """Last resort: scrape IPs and emails out of free text.

    Only consulted when the structured fields yielded nothing, because free
    text mixes the alert's subject with whatever else the vendor chose to
    mention -- a remediation URL, an example, the analyst's own console host.
    """
    found: list[tuple[str, str]] = []
    for raw_ip in _IP_RE.findall(text):
        entity = _normalize_entity("ip", raw_ip)
        if entity is not None:
            found.append(entity)
    for raw_email in _EMAIL_RE.findall(text):
        entity = _normalize_entity("user", raw_email)
        if entity is not None:
            found.append(entity)
    return found


def extract_entities(alert: Any) -> list[tuple[str, str]]:
    """Return the distinct ``(kind, value)`` entities an alert is about.

    Ordered by :data:`_ENTITY_PRIORITY` so the caller can take the first as the
    cluster's headline entity without re-sorting.
    """
    seen: dict[tuple[str, str], None] = {}

    for entity in _entities_from_tags(getattr(alert, "tags", None)):
        seen.setdefault(entity, None)
    for entity in _entities_from_raw(getattr(alert, "raw_data", None)):
        seen.setdefault(entity, None)

    if not seen:
        text = f"{getattr(alert, 'title', '') or ''} {getattr(alert, 'description', '') or ''}"
        for entity in _entities_from_text(text):
            seen.setdefault(entity, None)

    return sorted(
        seen,
        key=lambda e: (_ENTITY_PRIORITY.index(e[0]) if e[0] in _ENTITY_PRIORITY else 99, e[1]),
    )


def normalize_title(title: str | None) -> str:
    """Reduce a title to a vendor-independent bag of tokens.

    Everything variable is stripped first -- IPs, emails, UUIDs, hex ids and
    bare numbers are the parts that differ between two reports of the *same*
    event, so leaving them in would defeat the match. The surviving tokens are
    sorted because vendors order the same words differently ("Brute force
    detected" / "Detected brute-force"), and word order is not worth a missed
    grouping.
    """
    text = (title or "").lower()
    text = _EMAIL_RE.sub(" ", text)
    text = _IP_RE.sub(" ", text)
    text = _UUID_RE.sub(" ", text)
    text = _LONG_HEX_RE.sub(" ", text)
    text = re.sub(r"[^a-z\s]+", " ", text)
    tokens = {t for t in text.split() if len(t) > 2 and t not in _TITLE_STOPWORDS}
    return " ".join(sorted(tokens))


def alert_signature(alert: Any) -> str:
    """Return the vendor-independent "what happened" half of the fingerprint.

    MITRE technique IDs win when present: they are the only classification the
    vendors genuinely share, so they match across products where the prose
    never will. Titles are the fallback, and are much weaker -- two vendors
    describing one event rarely choose the same words.
    """
    techniques = getattr(alert, "mitre_techniques", None)
    if isinstance(techniques, list):
        ids = {
            match.group(0).upper()
            for item in techniques
            if isinstance(item, str)
            for match in [_TECHNIQUE_RE.search(item)]
            if match
        }
        if ids:
            return "mitre:" + ",".join(sorted(ids))

    normalized = normalize_title(getattr(alert, "title", None))
    if normalized:
        return "title:" + normalized

    # Nothing to go on. Key on the rule so these at least group per detection
    # instead of collapsing every unclassifiable alert into one cluster.
    return "rule:" + str(getattr(alert, "rule_id", None) or getattr(alert, "source_type", ""))


def fingerprint(entity_kind: str, entity_value: str, signature: str) -> str:
    """Hash one (entity, signature) pair into the key clusters are looked up by."""
    return hashlib.sha256(f"{entity_kind}|{entity_value}|{signature}".encode()).hexdigest()


def candidate_keys(alert: Any) -> list[tuple[str, str, str]]:
    """Return ``(entity_kind, entity_value, fingerprint)`` for every way this
    alert could join an existing cluster, headline entity first.

    An alert with entities does *not* also get a signature-only key. That key
    ignores which machine or account was involved, so adding it would let every
    brute-force alert in the org collapse into one cluster regardless of target.
    """
    signature = alert_signature(alert)
    entities = extract_entities(alert)

    if not entities:
        return [(_SIGNATURE_ONLY_KIND, "", fingerprint(_SIGNATURE_ONLY_KIND, "", signature))]

    return [(kind, value, fingerprint(kind, value, signature)) for kind, value in entities]
