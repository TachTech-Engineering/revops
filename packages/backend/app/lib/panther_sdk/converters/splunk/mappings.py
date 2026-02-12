"""Log type and severity mappings for Splunk to Panther conversion."""

from __future__ import annotations

# Splunk sourcetype to Panther LogType mapping
SOURCETYPE_MAP: dict[str, str] = {
    # AWS
    "aws:cloudtrail": "AWS.CloudTrail",
    "aws:s3:accesslogs": "AWS.S3ServerAccess",
    "aws:cloudwatchlogs:vpcflow": "AWS.VPCFlow",
    "aws:guardduty": "AWS.GuardDuty",
    "aws:elb:accesslogs": "AWS.ALB",
    "aws:config:rule": "AWS.Config",
    "aws:securityhub": "AWS.SecurityHub",
    "aws:waf": "AWS.WAF",
    # Okta
    "okta:im:log": "Okta.SystemLog",
    "OktaIM2:log": "Okta.SystemLog",
    # OneLogin
    "onelogin:events": "OneLogin.Events",
    # Google
    "gsuite:reports": "GSuite.Reports",
    "google:gcp:pubsub:message": "GCP.AuditLog",
    "gcp:pubsub:audit": "GCP.AuditLog",
    # GitHub
    "github:audit": "GitHub.Audit",
    "github:enterprise:audit": "GitHub.Audit",
    # Slack
    "slack:audit": "Slack.AuditLogs",
    # Zoom
    "zoom:activity": "Zoom.Activity",
    # Box
    "box:events": "Box.Event",
    # Microsoft
    "ms:o365:management:activity": "Microsoft365.Audit",
    "ms:aad:signin": "Azure.SignInLogs",
    "ms:aad:audit": "Azure.AuditLogs",
    "azure:monitor:aad": "Azure.AuditLogs",
    "azure:activity": "Azure.Activity",
    # CrowdStrike
    "crowdstrike:events": "CrowdStrike.FDREvent",
    "crowdstrike:events:sensor": "CrowdStrike.FDREvent",
    "crowdstrike:falcon:endpoint": "CrowdStrike.FDREvent",
    "crowdstrike:detection": "CrowdStrike.Detection",
    # Carbon Black
    "carbonblack:audit": "CarbonBlack.Audit",
    "carbonblack:events": "CarbonBlack.Audit",
    # SentinelOne
    "sentinelone:activity": "SentinelOne.Activity",
    "sentinelone:threats": "SentinelOne.Threat",
    # Palo Alto
    "pan:traffic": "PaloAlto.Traffic",
    "pan:threat": "PaloAlto.Threat",
    "pan:system": "PaloAlto.System",
    "pan:globalprotect": "PaloAlto.GlobalProtect",
    # Cisco
    "cisco:asa": "Cisco.ASA",
    "cisco:umbrella:dns": "Cisco.Umbrella",
    "cisco:meraki": "Cisco.Meraki",
    # Network
    "zeek:dns": "Zeek.DNS",
    "zeek:http": "Zeek.HTTP",
    "zeek:conn": "Zeek.Conn",
    "suricata:alert": "Suricata.Alert",
    "suricata:dns": "Suricata.DNS",
    # Linux/Unix
    "linux:audit": "Linux.Audit",
    "syslog": "Syslog.RFC5424",
    # Windows
    "WinEventLog:Security": "Windows.EventLog",
    "WinEventLog:System": "Windows.EventLog",
    "XmlWinEventLog:Security": "Windows.EventLog",
    # Generic
    "json": "Custom.Logs",
    "csv": "Custom.Logs",
}

# Splunk index to Panther LogType mapping (less precise, used as fallback)
INDEX_MAP: dict[str, str] = {
    "aws": "AWS.CloudTrail",
    "cloudtrail": "AWS.CloudTrail",
    "okta": "Okta.SystemLog",
    "github": "GitHub.Audit",
    "gsuite": "GSuite.Reports",
    "crowdstrike": "CrowdStrike.FDREvent",
    "carbon_black": "CarbonBlack.Audit",
    "paloalto": "PaloAlto.Traffic",
    "zeek": "Zeek.DNS",
    "suricata": "Suricata.Alert",
    "windows": "Windows.EventLog",
    "linux": "Linux.Audit",
    "main": "Custom.Logs",
}

# Splunk severity (1-6 scale) to Panther severity mapping
SEVERITY_MAP: dict[int, str] = {
    1: "INFO",
    2: "INFO",
    3: "LOW",
    4: "MEDIUM",
    5: "HIGH",
    6: "CRITICAL",
}

# Default severity when none is specified
DEFAULT_SEVERITY = "MEDIUM"

# Default dedup period in minutes
DEFAULT_DEDUP_PERIOD_MINUTES = 60

# Eval function to Python function mapping
EVAL_FUNCTION_MAP: dict[str, str] = {
    # String functions
    "len": "len",
    "lower": "str.lower",
    "upper": "str.upper",
    "trim": "str.strip",
    "ltrim": "str.lstrip",
    "rtrim": "str.rstrip",
    "substr": "slice",  # Special handling
    "replace": "str.replace",
    "split": "str.split",
    "mvindex": "list_index",  # Special handling
    "mvjoin": "str.join",  # Special handling
    "mvcount": "len",
    "mvfind": "find_in_list",  # Special handling
    # Math functions
    "abs": "abs",
    "ceil": "math.ceil",
    "floor": "math.floor",
    "round": "round",
    "sqrt": "math.sqrt",
    "pow": "pow",
    "log": "math.log",
    "exp": "math.exp",
    # Date/time functions
    "now": "time.time",
    "time": "time.time",
    "strftime": "datetime.strftime",  # Special handling
    "strptime": "datetime.strptime",  # Special handling
    "relative_time": "relative_time",  # Special handling
    # Type conversion
    "tonumber": "float_or_int",  # Special handling
    "tostring": "str",
    "isnull": "is_none",  # Special handling
    "isnotnull": "is_not_none",  # Special handling
    "coalesce": "coalesce",  # Special handling
    "null": "None",
    # Cryptographic
    "md5": "hashlib.md5",  # Special handling
    "sha1": "hashlib.sha1",  # Special handling
    "sha256": "hashlib.sha256",  # Special handling
    "sha512": "hashlib.sha512",  # Special handling
    # Comparison
    "if": "if_else",  # Special handling
    "case": "case",  # Special handling
    "match": "re.search",  # Special handling
    "like": "pattern_match",  # Special handling
    "cidrmatch": "is_ip_in_network",  # Special handling
    # JSON functions
    "json_extract": "deep_get",  # Special handling
    "spath": "deep_get",  # Special handling
}

# Commands that can be fully converted
SUPPORTED_COMMANDS = {
    "search",
    "stats",
    "eval",
    "where",
    "rex",
    "table",
    "fields",
    "sort",
    "head",
    "tail",
    "dedup",
    "rename",
    "regex",
}

# Commands that generate TODO comments
UNSUPPORTED_COMMANDS = {
    "join": "Consider using scheduled queries with correlation or multiple rules",
    "lookup": "Use Panther lookup tables with p_lookup() helper",
    "append": "Consider using multiple rules or correlation rules",
    "appendcols": "Consider using multiple rules or correlation rules",
    "transaction": "Consider using correlation rules or scheduled queries",
    "eventstats": "Use global functions or scheduled queries for cross-event statistics",
    "streamstats": "Consider using scheduled queries for running calculations",
    "inputlookup": "Use Panther lookup tables",
    "outputlookup": "N/A - Panther handles output differently",
    "tstats": "Use standard search with appropriate log types",
    "map": "Consider using multiple rules or Python loops",
    "foreach": "Consider using Python loops",
    "convert": "Use Python type conversion functions",
    "fillnull": "Use coalesce() or default values in Python",
    "bin": "Use Python datetime binning or math operations",
    "bucket": "Use Python datetime binning or math operations",
    "timechart": "Use Panther scheduled queries for time-based aggregations",
    "chart": "Use Panther scheduled queries for aggregations",
    "collect": "N/A - Panther handles output differently",
    "sendemail": "Use Panther alert destinations",
    "alert": "N/A - Panther generates alerts automatically",
}

# Common field name mappings from Splunk to common event schemas
FIELD_NAME_MAP: dict[str, dict[str, str]] = {
    "AWS.CloudTrail": {
        "user": "userIdentity.arn",
        "src_ip": "sourceIPAddress",
        "source_ip": "sourceIPAddress",
        "action": "eventName",
        "event_type": "eventType",
        "account_id": "recipientAccountId",
        "region": "awsRegion",
    },
    "Okta.SystemLog": {
        "user": "actor.alternateId",
        "src_ip": "client.ipAddress",
        "source_ip": "client.ipAddress",
        "action": "eventType",
        "result": "outcome.result",
        "reason": "outcome.reason",
    },
    "CrowdStrike.FDREvent": {
        "user": "UserName",
        "hostname": "ComputerName",
        "process_name": "FileName",
        "command_line": "CommandLine",
        "parent_process": "ParentImageFileName",
    },
    "GitHub.Audit": {
        "user": "actor",
        "action": "action",
        "org": "org",
        "repo": "repo",
    },
}


def get_log_type(sourcetype: str | None, index: str | None) -> str | None:
    """
    Get the Panther log type from Splunk sourcetype or index.

    Args:
        sourcetype: Splunk sourcetype value
        index: Splunk index name

    Returns:
        Panther log type string or None if not found
    """
    if sourcetype:
        # Try exact match first
        if sourcetype.lower() in SOURCETYPE_MAP:
            return SOURCETYPE_MAP[sourcetype.lower()]
        # Try partial match
        for key, value in SOURCETYPE_MAP.items():
            if key in sourcetype.lower() or sourcetype.lower() in key:
                return value

    if index:
        # Try exact match first
        if index.lower() in INDEX_MAP:
            return INDEX_MAP[index.lower()]
        # Try partial match
        for key, value in INDEX_MAP.items():
            if key in index.lower():
                return value

    return None


def get_severity(splunk_severity: int | str | None) -> str:
    """
    Convert Splunk severity to Panther severity.

    Args:
        splunk_severity: Splunk severity (1-6 or string)

    Returns:
        Panther severity string
    """
    if splunk_severity is None:
        return DEFAULT_SEVERITY

    if isinstance(splunk_severity, str):
        # Handle string severities
        severity_str = splunk_severity.upper()
        if severity_str in ("INFO", "INFORMATIONAL"):
            return "INFO"
        elif severity_str == "LOW":
            return "LOW"
        elif severity_str in ("MEDIUM", "MED"):
            return "MEDIUM"
        elif severity_str == "HIGH":
            return "HIGH"
        elif severity_str in ("CRITICAL", "CRIT"):
            return "CRITICAL"
        else:
            return DEFAULT_SEVERITY

    if isinstance(splunk_severity, int):
        return SEVERITY_MAP.get(splunk_severity, DEFAULT_SEVERITY)

    return DEFAULT_SEVERITY


def get_field_mapping(log_type: str, field_name: str) -> str | None:
    """
    Get the mapped field name for a specific log type.

    Args:
        log_type: Panther log type
        field_name: Splunk field name

    Returns:
        Mapped field name or None if no mapping exists
    """
    if log_type in FIELD_NAME_MAP:
        return FIELD_NAME_MAP[log_type].get(field_name)
    return None


def is_command_supported(command_name: str) -> bool:
    """Check if an SPL command is supported for conversion."""
    return command_name.lower() in SUPPORTED_COMMANDS


def get_command_suggestion(command_name: str) -> str | None:
    """Get a suggestion for an unsupported command."""
    return UNSUPPORTED_COMMANDS.get(command_name.lower())
