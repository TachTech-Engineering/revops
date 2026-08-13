"""Enhanced Splunk SPL to Panther converter with comprehensive SPL command support.

SPL (Search Processing Language) is Splunk's query language for searching,
filtering, and transforming machine data.

Supports all common Splunk SPL commands including:
- Search: index, sourcetype, search, where, fields, regex
- Eval: eval, where, case, coalesce, if, match, like, nullif
- Stats: stats, eventstats, streamstats, chart, timechart, top, rare
- Time: bin/bucket, timewrap, reltime, earliest, latest
- Transform: rex, spath, xpath, extract, kvform, multikv
- Lookup: lookup, inputlookup, outputlookup
- Join: join, selfjoin, append, appendcols, union, multisearch
- Transaction: transaction, concurrency
- Subsearch: subsearches [search ...]
- Output: table, fields, rename, sort, head, tail, dedup, uniq
- Math: addtotals, eventstats, streamstats, autoregress, trendline, predict
- Multivalue: mvexpand, makemv, mvcombine, mvzip, mvcount, mvindex, mvfilter
- Format: fillnull, replace, convert, fieldformat, reltime
- Geo: iplocation, geostats, geom
- Other: makeresults, gentimes, map, foreach, return, format
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleType(Enum):
    STREAMING = "STREAMING"
    SCHEDULED = "SCHEDULED"


@dataclass
class SPLCommand:
    """Represents a parsed SPL command."""

    name: str
    raw: str
    args: dict[str, Any] = field(default_factory=dict)
    can_stream: bool = True  # Can this be a streaming rule?
    needs_aggregation: bool = False  # Requires scheduled query?


@dataclass
class SPLParseResult:
    """Result of parsing an SPL query."""

    index: str = ""
    sourcetype: str = ""
    timerange: str = ""
    earliest: str = ""
    latest: str = ""
    base_search: str = ""
    commands: list[SPLCommand] = field(default_factory=list)
    eval_fields: list[dict] = field(default_factory=list)
    stats_aggregations: list[dict] = field(default_factory=list)
    where_conditions: list[str] = field(default_factory=list)
    other_commands: list[dict] = field(default_factory=list)
    is_threshold_rule: bool = False
    recommended_type: RuleType = RuleType.STREAMING
    has_subsearch: bool = False
    fields_selected: list[str] = field(default_factory=list)
    fields_removed: list[str] = field(default_factory=list)


@dataclass
class EnhancedConversionResult:
    """Result of enhanced SPL conversion."""

    source_code: str
    rule_id: str
    class_name: str
    log_types: list[str]
    severity: str
    todos: list[str]
    is_threshold_rule: bool
    threshold: int | None = None
    recommended_type: RuleType = RuleType.STREAMING
    recommendation_reasons: list[str] = field(default_factory=list)
    test_code: str = ""
    parse_details: SPLParseResult | None = None


# SPL commands that require aggregation (must be scheduled)
AGGREGATION_COMMANDS = {
    "stats",
    "eventstats",
    "streamstats",
    "chart",
    "timechart",
    "top",
    "rare",
    "bin",
    "bucket",
    "cluster",
    "kmeans",
    "transaction",
    "concurrency",
    "sistats",
    "sichart",
    "sitop",
    "sitimechart",
    "sirare",
    "geostats",
    "tstats",
    "mstats",
    "addtotals",
    "autoregress",
    "trendline",
    "predict",
    "x11",
    "contingency",
    "correlate",
    "diff",
    "outlier",
    "anomalydetection",
}

# SPL commands that can work in streaming mode
STREAMING_COMMANDS = {
    "search",
    "where",
    "eval",
    "rex",
    "spath",
    "xpath",
    "extract",
    "fields",
    "rename",
    "replace",
    "fillnull",
    "convert",
    "fieldformat",
    "lookup",
    "regex",
    "case",
    "validate",
    "tags",
    "typer",
    "reltime",
    "iplocation",
    "geom",
    "iconify",
    "highlight",
    "rangemap",
    "makemv",
    "nomv",
    "mvexpand",
    "split",
}

# SPL commands for output/display (can be ignored or simplified)
OUTPUT_COMMANDS = {
    "table",
    "sort",
    "head",
    "tail",
    "reverse",
    "dedup",
    "uniq",
    "outputcsv",
    "outputtext",
    "sendemail",
    "collect",
    "tscollect",
    "format",
    "return",
    "addinfo",
}


class EnhancedSPLConverter:
    """Enhanced Splunk SPL to Panther converter with comprehensive command support."""

    # Map common Splunk indexes/sourcetypes to Panther log types
    LOG_TYPE_MAPPING = {
        # EDR
        "edr": "CrowdStrike.FDREvent",
        "crowdstrike": "CrowdStrike.FDREvent",
        "cs": "CrowdStrike.FDREvent",
        "falcon": "CrowdStrike.FDREvent",
        "sentinelone": "SentinelOne.DeepVisibility",
        "s1": "SentinelOne.DeepVisibility",
        "carbonblack": "CarbonBlack.EndpointEvent",
        "cb": "CarbonBlack.EndpointEvent",
        "defender": "Microsoft.Defender.ATP",
        "mde": "Microsoft.Defender.ATP",
        # Identity
        "okta": "Okta.SystemLog",
        "duo": "Duo.Authentication",
        "auth0": "Auth0.Events",
        "ping": "PingIdentity.Events",
        "onelogin": "OneLogin.Events",
        # Cloud - AWS
        "aws": "AWS.CloudTrail",
        "cloudtrail": "AWS.CloudTrail",
        "guardduty": "AWS.GuardDuty",
        "securityhub": "AWS.SecurityHub",
        "vpc": "AWS.VPCFlow",
        "vpcflow": "AWS.VPCFlow",
        "s3": "AWS.S3ServerAccess",
        "alb": "AWS.ALB",
        "elb": "AWS.ELB",
        "waf": "AWS.WAF",
        "route53": "AWS.Route53",
        # Cloud - GCP
        "gcp": "GCP.AuditLog",
        "gcloud": "GCP.AuditLog",
        "stackdriver": "GCP.AuditLog",
        # Cloud - Azure
        "azure": "Azure.AuditLog",
        "azuread": "Azure.AuditLog",
        "o365": "Microsoft365.Audit.AzureActiveDirectory",
        "office365": "Microsoft365.Audit.AzureActiveDirectory",
        "microsoft365": "Microsoft365.Audit.AzureActiveDirectory",
        "m365": "Microsoft365.Audit.AzureActiveDirectory",
        # Firewall/Network
        "firewall": "PaloAltoNetworks.Firewall",
        "palo": "PaloAltoNetworks.Firewall",
        "pan": "PaloAltoNetworks.Firewall",
        "fortinet": "Fortinet.Firewall",
        "fortigate": "Fortinet.Firewall",
        "cisco": "Cisco.ASA",
        "asa": "Cisco.ASA",
        "meraki": "Cisco.Meraki",
        "checkpoint": "CheckPoint.Firewall",
        "zscaler": "Zscaler.ZIA",
        "netskope": "Netskope.Events",
        # Proxy/Web
        "proxy": "Custom.Proxy",
        "squid": "Squid.AccessLog",
        "bluecoat": "Symantec.ProxySG",
        "zscaler_web": "Zscaler.ZIA",
        # Windows
        "windows": "Windows.EventLogs",
        "winevent": "Windows.EventLogs",
        "wineventlog": "Windows.EventLogs",
        "sysmon": "Windows.Sysmon",
        "powershell": "Windows.PowerShell",
        "security": "Windows.Security",
        # Linux
        "linux": "Linux.Syslog",
        "syslog": "Linux.Syslog",
        "auditd": "Linux.Auditd",
        "osquery": "Osquery.Results",
        # Email
        "email": "Custom.Email",
        "exchange": "Microsoft.Exchange",
        "proofpoint": "Proofpoint.Events",
        "mimecast": "Mimecast.Events",
        # SIEM
        "notable": "Splunk.Notable",
        # VPN
        "vpn": "Custom.VPN",
        "globalprotect": "PaloAltoNetworks.GlobalProtect",
        "anyconnect": "Cisco.AnyConnect",
        # DNS
        "dns": "Custom.DNS",
        "infoblox": "Infoblox.DNS",
        # Database
        "database": "Custom.Database",
        "oracle": "Oracle.Audit",
        "mssql": "MSSQL.Audit",
        "mysql": "MySQL.Audit",
        "postgres": "PostgreSQL.Audit",
        # Container/K8s
        "kubernetes": "Kubernetes.AuditLog",
        "k8s": "Kubernetes.AuditLog",
        "docker": "Docker.Events",
        "container": "Custom.Container",
    }

    # All SPL commands with their properties
    SPL_COMMANDS = {
        # Search commands
        "search": {"streaming": True, "aggregation": False},
        "where": {"streaming": True, "aggregation": False},
        "regex": {"streaming": True, "aggregation": False},
        "case": {"streaming": True, "aggregation": False},
        # Eval/Transform
        "eval": {"streaming": True, "aggregation": False},
        "rex": {"streaming": True, "aggregation": False},
        "spath": {"streaming": True, "aggregation": False},
        "xpath": {"streaming": True, "aggregation": False},
        "extract": {"streaming": True, "aggregation": False},
        "kv": {"streaming": True, "aggregation": False},
        "kvform": {"streaming": True, "aggregation": False},
        "multikv": {"streaming": True, "aggregation": False},
        "xmlkv": {"streaming": True, "aggregation": False},
        "xmlunescape": {"streaming": True, "aggregation": False},
        # Stats/Aggregation
        "stats": {"streaming": False, "aggregation": True},
        "eventstats": {"streaming": False, "aggregation": True},
        "streamstats": {"streaming": False, "aggregation": True},
        "chart": {"streaming": False, "aggregation": True},
        "timechart": {"streaming": False, "aggregation": True},
        "top": {"streaming": False, "aggregation": True},
        "rare": {"streaming": False, "aggregation": True},
        "sistats": {"streaming": False, "aggregation": True},
        "sichart": {"streaming": False, "aggregation": True},
        "sitop": {"streaming": False, "aggregation": True},
        "sitimechart": {"streaming": False, "aggregation": True},
        "sirare": {"streaming": False, "aggregation": True},
        "tstats": {"streaming": False, "aggregation": True},
        "mstats": {"streaming": False, "aggregation": True},
        "geostats": {"streaming": False, "aggregation": True},
        # Time
        "bin": {"streaming": False, "aggregation": True},
        "bucket": {"streaming": False, "aggregation": True},
        "timewrap": {"streaming": False, "aggregation": True},
        "reltime": {"streaming": True, "aggregation": False},
        # Lookup
        "lookup": {"streaming": True, "aggregation": False},
        "inputlookup": {"streaming": True, "aggregation": False},
        "outputlookup": {"streaming": True, "aggregation": False},
        # Join/Combine
        "join": {"streaming": False, "aggregation": True},
        "selfjoin": {"streaming": False, "aggregation": True},
        "append": {"streaming": False, "aggregation": True},
        "appendcols": {"streaming": False, "aggregation": True},
        "appendpipe": {"streaming": False, "aggregation": True},
        "union": {"streaming": False, "aggregation": True},
        "multisearch": {"streaming": False, "aggregation": True},
        "set": {"streaming": False, "aggregation": True},
        # Transaction
        "transaction": {"streaming": False, "aggregation": True},
        "concurrency": {"streaming": False, "aggregation": True},
        # Output/Format
        "table": {"streaming": True, "aggregation": False},
        "fields": {"streaming": True, "aggregation": False},
        "rename": {"streaming": True, "aggregation": False},
        "sort": {"streaming": True, "aggregation": False},
        "head": {"streaming": True, "aggregation": False},
        "tail": {"streaming": True, "aggregation": False},
        "reverse": {"streaming": True, "aggregation": False},
        "dedup": {"streaming": False, "aggregation": True},
        "uniq": {"streaming": False, "aggregation": True},
        "format": {"streaming": True, "aggregation": False},
        "return": {"streaming": True, "aggregation": False},
        "outputcsv": {"streaming": True, "aggregation": False},
        "outputtext": {"streaming": True, "aggregation": False},
        # Fill/Replace
        "fillnull": {"streaming": True, "aggregation": False},
        "filldown": {"streaming": False, "aggregation": True},
        "replace": {"streaming": True, "aggregation": False},
        "convert": {"streaming": True, "aggregation": False},
        "fieldformat": {"streaming": True, "aggregation": False},
        # Multivalue
        "mvexpand": {"streaming": True, "aggregation": False},
        "makemv": {"streaming": True, "aggregation": False},
        "mvcombine": {"streaming": False, "aggregation": True},
        "mvzip": {"streaming": True, "aggregation": False},
        "nomv": {"streaming": True, "aggregation": False},
        "split": {"streaming": True, "aggregation": False},
        # Math/Analytics
        "addtotals": {"streaming": False, "aggregation": True},
        "autoregress": {"streaming": False, "aggregation": True},
        "trendline": {"streaming": False, "aggregation": True},
        "predict": {"streaming": False, "aggregation": True},
        "x11": {"streaming": False, "aggregation": True},
        "anomalydetection": {"streaming": False, "aggregation": True},
        "cluster": {"streaming": False, "aggregation": True},
        "kmeans": {"streaming": False, "aggregation": True},
        "outlier": {"streaming": False, "aggregation": True},
        "contingency": {"streaming": False, "aggregation": True},
        "correlate": {"streaming": False, "aggregation": True},
        "diff": {"streaming": False, "aggregation": True},
        # Geo
        "iplocation": {"streaming": True, "aggregation": False},
        "geom": {"streaming": True, "aggregation": False},
        # Other transforms
        "transpose": {"streaming": False, "aggregation": True},
        "untable": {"streaming": False, "aggregation": True},
        "xyseries": {"streaming": False, "aggregation": True},
        "gauge": {"streaming": True, "aggregation": False},
        "rangemap": {"streaming": True, "aggregation": False},
        "iconify": {"streaming": True, "aggregation": False},
        "highlight": {"streaming": True, "aggregation": False},
        "tags": {"streaming": True, "aggregation": False},
        "typer": {"streaming": True, "aggregation": False},
        "typelearner": {"streaming": True, "aggregation": False},
        "findtypes": {"streaming": True, "aggregation": False},
        # Subsearch/Map
        "map": {"streaming": False, "aggregation": True},
        "foreach": {"streaming": True, "aggregation": False},
        # Generate
        "makeresults": {"streaming": True, "aggregation": False},
        "gentimes": {"streaming": True, "aggregation": False},
        "inputcsv": {"streaming": True, "aggregation": False},
        # System/Admin
        "history": {"streaming": True, "aggregation": False},
        "metadata": {"streaming": True, "aggregation": False},
        "metasearch": {"streaming": True, "aggregation": False},
        "dbinspect": {"streaming": True, "aggregation": False},
        "rest": {"streaming": True, "aggregation": False},
        "savedsearch": {"streaming": False, "aggregation": True},
        "loadjob": {"streaming": False, "aggregation": True},
        "sendemail": {"streaming": True, "aggregation": False},
        "collect": {"streaming": True, "aggregation": False},
        "tscollect": {"streaming": True, "aggregation": False},
        "delete": {"streaming": True, "aggregation": False},
        # Misc
        "addinfo": {"streaming": True, "aggregation": False},
        "delta": {"streaming": False, "aggregation": True},
        "accum": {"streaming": False, "aggregation": True},
        "localop": {"streaming": True, "aggregation": False},
        "localize": {"streaming": True, "aggregation": False},
        "redistribute": {"streaming": True, "aggregation": False},
        "require": {"streaming": True, "aggregation": False},
        "script": {"streaming": True, "aggregation": False},
        "run": {"streaming": True, "aggregation": False},
        "pivot": {"streaming": False, "aggregation": True},
        "datamodel": {"streaming": False, "aggregation": True},
        "from": {"streaming": True, "aggregation": False},
        "abstract": {"streaming": True, "aggregation": False},
        "erex": {"streaming": True, "aggregation": False},
        "scrub": {"streaming": True, "aggregation": False},
        "searchtxn": {"streaming": False, "aggregation": True},
        "walklex": {"streaming": True, "aggregation": False},
        "typeahead": {"streaming": True, "aggregation": False},
        "makecontinuous": {"streaming": False, "aggregation": True},
        "folderize": {"streaming": True, "aggregation": False},
        "cofilter": {"streaming": False, "aggregation": True},
        "relevancy": {"streaming": True, "aggregation": False},
        "rtorder": {"streaming": False, "aggregation": True},
        "setfields": {"streaming": True, "aggregation": False},
        "strcat": {"streaming": True, "aggregation": False},
        "fieldsummary": {"streaming": False, "aggregation": True},
        "eventcount": {"streaming": False, "aggregation": True},
        "validate": {"streaming": True, "aggregation": False},
    }

    def parse_spl(self, spl: str) -> SPLParseResult:
        """Parse SPL query into components."""
        result = SPLParseResult()

        # Normalize SPL (handle line continuations)
        spl = re.sub(r"\\\n", " ", spl)
        spl = re.sub(r"\s+", " ", spl).strip()

        # Check for subsearches
        if "[" in spl and "]" in spl:
            result.has_subsearch = True
            result.is_threshold_rule = True
            result.recommended_type = RuleType.SCHEDULED

        # Split by pipe (but not inside brackets or quotes)
        parts = self._split_by_pipe(spl)

        for i, part in enumerate(parts):
            part = part.strip()
            if not part:
                continue

            # First part is usually index/search
            if i == 0:
                result.base_search = part
                self._parse_base_search(part, result)
                continue

            # Parse the command
            cmd = self._parse_command(part)
            result.commands.append(cmd)

            # Check if this command requires aggregation
            if cmd.needs_aggregation:
                result.is_threshold_rule = True
                result.recommended_type = RuleType.SCHEDULED

            # Store in legacy format for compatibility
            self._store_legacy_format(cmd, result)

        return result

    def _split_by_pipe(self, spl: str) -> list[str]:
        """Split SPL by pipe, respecting brackets and quotes."""
        parts = []
        current = ""
        depth = 0
        in_quote = False
        quote_char = None

        for char in spl:
            if char in "\"'":
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif char == quote_char:
                    in_quote = False
                    quote_char = None
            elif char == "[" and not in_quote:
                depth += 1
            elif char == "]" and not in_quote:
                depth -= 1
            elif char == "|" and depth == 0 and not in_quote:
                parts.append(current.strip())
                current = ""
                continue
            current += char

        if current.strip():
            parts.append(current.strip())

        return parts

    def _parse_base_search(self, part: str, result: SPLParseResult):
        """Parse the base search portion of SPL."""
        # Extract index
        idx_match = re.search(r'index\s*=\s*("[^"]+"|\'[^\']+\'|\S+)', part, re.IGNORECASE)
        if idx_match:
            result.index = idx_match.group(1).strip("\"'")

        # Extract sourcetype
        st_match = re.search(r'sourcetype\s*=\s*("[^"]+"|\'[^\']+\'|\S+)', part, re.IGNORECASE)
        if st_match:
            result.sourcetype = st_match.group(1).strip("\"'")

        # Extract source
        src_match = re.search(r'source\s*=\s*("[^"]+"|\'[^\']+\'|\S+)', part, re.IGNORECASE)
        if src_match:
            pass  # Could store if needed

        # Extract earliest
        earliest_match = re.search(r"earliest\s*=\s*(\S+)", part, re.IGNORECASE)
        if earliest_match:
            result.earliest = earliest_match.group(1)
            result.timerange = earliest_match.group(1)

        # Extract latest
        latest_match = re.search(r"latest\s*=\s*(\S+)", part, re.IGNORECASE)
        if latest_match:
            result.latest = latest_match.group(1)

    def _parse_command(self, part: str) -> SPLCommand:
        """Parse a single SPL command."""
        # Get the command name
        cmd_match = re.match(r"^(\w+)\s*(.*)", part, re.DOTALL)
        if not cmd_match:
            return SPLCommand(name="unknown", raw=part)

        cmd_name = cmd_match.group(1).lower()
        cmd_args = cmd_match.group(2).strip()

        # Get command properties
        cmd_props = self.SPL_COMMANDS.get(cmd_name, {"streaming": True, "aggregation": False})

        cmd = SPLCommand(
            name=cmd_name,
            raw=part,
            can_stream=cmd_props["streaming"],
            needs_aggregation=cmd_props["aggregation"],
        )

        # Parse command-specific arguments
        cmd.args = self._parse_command_args(cmd_name, cmd_args)

        return cmd

    def _parse_command_args(self, cmd_name: str, args: str) -> dict[str, Any]:
        """Parse arguments for specific commands."""
        result = {"raw": args}

        if cmd_name == "eval":
            result.update(self._parse_eval(args))
        elif cmd_name == "stats":
            result.update(self._parse_stats(args))
        elif cmd_name in ("bin", "bucket"):
            result.update(self._parse_bin(args))
        elif cmd_name == "rex":
            result.update(self._parse_rex(args))
        elif cmd_name == "spath":
            result.update(self._parse_spath(args))
        elif cmd_name == "where":
            result["condition"] = args
        elif cmd_name == "search":
            result["filter"] = args
        elif cmd_name == "fields":
            result.update(self._parse_fields(args))
        elif cmd_name == "table":
            result["fields"] = [f.strip() for f in args.split(",")]
        elif cmd_name == "rename":
            result.update(self._parse_rename(args))
        elif cmd_name == "sort":
            result.update(self._parse_sort(args))
        elif cmd_name in ("head", "tail"):
            result["limit"] = int(args) if args.isdigit() else 10
        elif cmd_name == "dedup":
            result.update(self._parse_dedup(args))
        elif cmd_name == "top":
            result.update(self._parse_top(args))
        elif cmd_name == "rare":
            result.update(self._parse_top(args))  # Same format as top
        elif cmd_name in ("chart", "timechart"):
            result.update(self._parse_chart(args))
        elif cmd_name == "lookup":
            result.update(self._parse_lookup(args))
        elif cmd_name == "join":
            result.update(self._parse_join(args))
        elif cmd_name == "transaction":
            result.update(self._parse_transaction(args))
        elif cmd_name == "fillnull":
            result.update(self._parse_fillnull(args))
        elif cmd_name == "replace":
            result.update(self._parse_replace(args))
        elif cmd_name == "mvexpand":
            result["field"] = args.strip()
        elif cmd_name in ("eventstats", "streamstats"):
            result.update(self._parse_stats(args))
        elif cmd_name == "iplocation":
            result.update(self._parse_iplocation(args))
        elif cmd_name == "convert":
            result.update(self._parse_convert(args))
        elif cmd_name == "makemv":
            result.update(self._parse_makemv(args))

        return result

    def _parse_eval(self, content: str) -> dict:
        """Parse an eval command."""
        result = {"assignments": []}

        # Handle multiple assignments
        # Look for field=expression patterns
        assignments = re.findall(r"(\w+)\s*=\s*(.+?)(?=,\s*\w+\s*=|$)", content, re.DOTALL)

        for field_name, expr in assignments:
            parsed = {
                "field": field_name.strip(),
                "expression": expr.strip(),
                "functions": self._detect_functions(expr),
            }
            result["assignments"].append(parsed)

        # If no assignments found, try single assignment
        if not result["assignments"]:
            match = re.match(r"(\w+)\s*=\s*(.+)", content)
            if match:
                result["assignments"].append(
                    {
                        "field": match.group(1),
                        "expression": match.group(2),
                        "functions": self._detect_functions(match.group(2)),
                    }
                )

        return result

    def _detect_functions(self, expr: str) -> list[str]:
        """Detect SPL functions used in an expression."""
        functions = []
        expr_lower = expr.lower()

        spl_functions = [
            "coalesce",
            "if",
            "case",
            "match",
            "like",
            "cidrmatch",
            "lower",
            "upper",
            "len",
            "substr",
            "replace",
            "trim",
            "ltrim",
            "rtrim",
            "split",
            "mvcount",
            "mvindex",
            "mvfilter",
            "mvjoin",
            "mvsort",
            "mvzip",
            "now",
            "time",
            "strftime",
            "strptime",
            "relative_time",
            "tonumber",
            "tostring",
            "typeof",
            "abs",
            "ceil",
            "floor",
            "round",
            "sqrt",
            "pow",
            "log",
            "ln",
            "exp",
            "min",
            "max",
            "sum",
            "avg",
            "count",
            "dc",
            "values",
            "list",
            "isnull",
            "isnotnull",
            "nullif",
            "null",
            "true",
            "false",
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "urldecode",
            "urlencode",
            "base64decode",
            "base64encode",
            "json_extract",
            "json_array",
            "json_object",
            "json_valid",
            "spath",
            "mvexpand",
            "mvappend",
            "mvdedup",
            "mvrange",
            "searchmatch",
            "commands",
            "typeof",
            "validate",
        ]

        for func in spl_functions:
            if f"{func}(" in expr_lower:
                functions.append(func)

        return functions

    def _parse_stats(self, content: str) -> dict:
        """Parse a stats command."""
        result = {"aggregations": [], "by_fields": []}

        # Extract "by" clause
        by_match = re.search(r"\bby\s+(.+?)$", content, re.IGNORECASE)
        if by_match:
            by_content = by_match.group(1).strip()
            # Handle both comma-separated and space-separated fields
            if "," in by_content:
                result["by_fields"] = [f.strip() for f in by_content.split(",")]
            else:
                result["by_fields"] = [f.strip() for f in by_content.split()]
            content = content[: by_match.start()].strip()

        # Parse aggregations
        agg_patterns = [
            (r"count(?:\s*\(([^)]*)\))?\s+as\s+(\w+)", "count"),
            (r"count(?:\s*\(([^)]*)\))?(?!\s+as)", "count"),
            (r"dc\s*\(([^)]+)\)\s+as\s+(\w+)", "distinct_count"),
            (r"dc\s*\(([^)]+)\)(?!\s+as)", "distinct_count"),
            (r"sum\s*\(([^)]+)\)\s+as\s+(\w+)", "sum"),
            (r"sum\s*\(([^)]+)\)(?!\s+as)", "sum"),
            (r"avg\s*\(([^)]+)\)\s+as\s+(\w+)", "avg"),
            (r"avg\s*\(([^)]+)\)(?!\s+as)", "avg"),
            (r"max\s*\(([^)]+)\)\s+as\s+(\w+)", "max"),
            (r"max\s*\(([^)]+)\)(?!\s+as)", "max"),
            (r"min\s*\(([^)]+)\)\s+as\s+(\w+)", "min"),
            (r"min\s*\(([^)]+)\)(?!\s+as)", "min"),
            (r"values\s*\(([^)]+)\)\s+as\s+(\w+)", "values"),
            (r"values\s*\(([^)]+)\)(?!\s+as)", "values"),
            (r"list\s*\(([^)]+)\)\s+as\s+(\w+)", "list"),
            (r"list\s*\(([^)]+)\)(?!\s+as)", "list"),
            (r"first\s*\(([^)]+)\)\s+as\s+(\w+)", "first"),
            (r"last\s*\(([^)]+)\)\s+as\s+(\w+)", "last"),
            (r"earliest\s*\(([^)]+)\)\s+as\s+(\w+)", "earliest"),
            (r"latest\s*\(([^)]+)\)\s+as\s+(\w+)", "latest"),
            (r"stdev\s*\(([^)]+)\)\s+as\s+(\w+)", "stdev"),
            (r"var\s*\(([^)]+)\)\s+as\s+(\w+)", "var"),
            (r"range\s*\(([^)]+)\)\s+as\s+(\w+)", "range"),
            (r"median\s*\(([^)]+)\)\s+as\s+(\w+)", "median"),
            (r"mode\s*\(([^)]+)\)\s+as\s+(\w+)", "mode"),
            (r"perc\d+\s*\(([^)]+)\)\s+as\s+(\w+)", "percentile"),
            (r"exactperc\d+\s*\(([^)]+)\)\s+as\s+(\w+)", "percentile"),
            (r"upperperc\d+\s*\(([^)]+)\)\s+as\s+(\w+)", "percentile"),
        ]

        for pattern, agg_type in agg_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                groups = match.groups()
                if len(groups) >= 2:
                    field = groups[0] if groups[0] else "*"
                    alias = groups[1]
                else:
                    field = groups[0] if groups[0] else "*"
                    alias = agg_type
                result["aggregations"].append(
                    {
                        "type": agg_type,
                        "field": field.strip() if field else "*",
                        "alias": alias.strip() if alias else agg_type,
                    }
                )

        return result

    def _parse_bin(self, content: str) -> dict:
        """Parse a bin/bucket command."""
        result = {"field": "_time", "span": None, "bins": None, "minspan": None, "aligntime": None}

        parts = content.split()
        for i, part in enumerate(parts):
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.lower()
                if key == "span":
                    result["span"] = value
                elif key == "bins":
                    result["bins"] = int(value) if value.isdigit() else value
                elif key == "minspan":
                    result["minspan"] = value
                elif key == "aligntime":
                    result["aligntime"] = value
            elif i == 0 and not any(x in part for x in ["=", "span", "bins"]):
                result["field"] = part

        return result

    def _parse_rex(self, content: str) -> dict:
        """Parse a rex command."""
        result = {"field": "_raw", "pattern": "", "mode": "extract", "max_match": 1}

        # Extract field
        field_match = re.search(r"field\s*=\s*(\S+)", content, re.IGNORECASE)
        if field_match:
            result["field"] = field_match.group(1).strip("\"'")

        # Extract mode
        if "mode=sed" in content.lower():
            result["mode"] = "sed"
        elif "mode=s" in content.lower():
            result["mode"] = "sed"

        # Extract max_match
        max_match = re.search(r"max_match\s*=\s*(\d+)", content, re.IGNORECASE)
        if max_match:
            result["max_match"] = int(max_match.group(1))

        # Extract pattern (in quotes)
        pattern_match = re.search(r'"([^"]+)"', content)
        if pattern_match:
            result["pattern"] = pattern_match.group(1)
        else:
            pattern_match = re.search(r"'([^']+)'", content)
            if pattern_match:
                result["pattern"] = pattern_match.group(1)

        # Extract named groups from pattern
        if result["pattern"]:
            named_groups = re.findall(r"\?<(\w+)>", result["pattern"])
            result["extracted_fields"] = named_groups

        return result

    def _parse_spath(self, content: str) -> dict:
        """Parse an spath command."""
        result = {"input": "_raw", "output": None, "path": None}

        # Extract input field
        input_match = re.search(r"input\s*=\s*(\S+)", content, re.IGNORECASE)
        if input_match:
            result["input"] = input_match.group(1).strip("\"'")

        # Extract output field
        output_match = re.search(r"output\s*=\s*(\S+)", content, re.IGNORECASE)
        if output_match:
            result["output"] = output_match.group(1).strip("\"'")

        # Extract path
        path_match = re.search(r"path\s*=\s*(\S+)", content, re.IGNORECASE)
        if path_match:
            result["path"] = path_match.group(1).strip("\"'")
        else:
            # Path might be the only argument
            parts = content.split()
            if parts and not any("=" in p for p in parts[:1]):
                result["path"] = parts[0].strip("\"'")

        return result

    def _parse_fields(self, content: str) -> dict:
        """Parse a fields command."""
        result = {"include": [], "exclude": []}

        content = content.strip()
        if content.startswith("-"):
            # Excluding fields
            fields_str = content[1:].strip()
            result["exclude"] = [f.strip() for f in fields_str.split(",")]
        elif content.startswith("+"):
            # Including fields
            fields_str = content[1:].strip()
            result["include"] = [f.strip() for f in fields_str.split(",")]
        else:
            # Default is include
            result["include"] = [f.strip() for f in content.split(",")]

        return result

    def _parse_rename(self, content: str) -> dict:
        """Parse a rename command."""
        result = {"renames": []}

        # Pattern: field1 AS newname1, field2 AS newname2
        # or: field1 as newname1 field2 as newname2
        renames = re.findall(r"(\S+)\s+[Aa][Ss]\s+(\S+)", content)
        for old, new in renames:
            result["renames"].append({"from": old.strip("\"'"), "to": new.strip("\"'")})

        return result

    def _parse_sort(self, content: str) -> dict:
        """Parse a sort command."""
        result = {"fields": [], "limit": None}

        # Extract limit
        limit_match = re.search(r"limit\s*=\s*(\d+)", content, re.IGNORECASE)
        if limit_match:
            result["limit"] = int(limit_match.group(1))
            content = content[: limit_match.start()] + content[limit_match.end() :]

        # Extract count (limit alias)
        count_match = re.search(r"^\s*(\d+)\s+", content)
        if count_match:
            result["limit"] = int(count_match.group(1))
            content = content[count_match.end() :]

        # Parse fields with optional +/- prefix
        for field_name in content.split(","):
            field_name = field_name.strip()
            if not field_name:
                continue
            if field_name.startswith("-"):
                result["fields"].append({"field": field_name[1:].strip(), "order": "desc"})
            elif field_name.startswith("+"):
                result["fields"].append({"field": field_name[1:].strip(), "order": "asc"})
            else:
                result["fields"].append({"field": field_name, "order": "asc"})

        return result

    def _parse_dedup(self, content: str) -> dict:
        """Parse a dedup command."""
        result = {
            "fields": [],
            "keepevents": False,
            "keepempty": False,
            "consecutive": False,
            "sortby": None,
        }

        # Extract options
        if "keepevents=true" in content.lower():
            result["keepevents"] = True
            content = re.sub(r"keepevents\s*=\s*\w+", "", content, flags=re.IGNORECASE)
        if "keepempty=true" in content.lower():
            result["keepempty"] = True
            content = re.sub(r"keepempty\s*=\s*\w+", "", content, flags=re.IGNORECASE)
        if "consecutive=true" in content.lower():
            result["consecutive"] = True
            content = re.sub(r"consecutive\s*=\s*\w+", "", content, flags=re.IGNORECASE)

        # Extract sortby
        sortby_match = re.search(r"sortby\s+([+-]?\w+)", content, re.IGNORECASE)
        if sortby_match:
            result["sortby"] = sortby_match.group(1)
            content = content[: sortby_match.start()] + content[sortby_match.end() :]

        # Extract count
        count_match = re.search(r"^\s*(\d+)\s+", content)
        if count_match:
            result["count"] = int(count_match.group(1))
            content = content[count_match.end() :]

        # Remaining is fields
        result["fields"] = [f.strip() for f in content.split(",") if f.strip()]

        return result

    def _parse_top(self, content: str) -> dict:
        """Parse top/rare command."""
        result = {
            "limit": 10,
            "fields": [],
            "by_fields": [],
            "countfield": "count",
            "percentfield": "percent",
        }

        # Extract limit
        limit_match = re.search(r"limit\s*=\s*(\d+)", content, re.IGNORECASE)
        if limit_match:
            result["limit"] = int(limit_match.group(1))
            content = content[: limit_match.start()] + content[limit_match.end() :]

        # Extract count (limit)
        count_match = re.search(r"^\s*(\d+)\s+", content)
        if count_match:
            result["limit"] = int(count_match.group(1))
            content = content[count_match.end() :]

        # Extract by clause
        by_match = re.search(r"\bby\s+(.+?)$", content, re.IGNORECASE)
        if by_match:
            result["by_fields"] = [f.strip() for f in by_match.group(1).split(",")]
            content = content[: by_match.start()].strip()

        # Remaining is fields
        result["fields"] = [f.strip() for f in content.split() if f.strip()]

        return result

    def _parse_chart(self, content: str) -> dict:
        """Parse chart/timechart command."""
        result = {"aggregations": [], "by_fields": [], "over_field": None, "span": None}

        # Extract span
        span_match = re.search(r"span\s*=\s*(\S+)", content, re.IGNORECASE)
        if span_match:
            result["span"] = span_match.group(1)
            content = content[: span_match.start()] + content[span_match.end() :]

        # Extract over clause
        over_match = re.search(r"\bover\s+(\w+)", content, re.IGNORECASE)
        if over_match:
            result["over_field"] = over_match.group(1)
            content = content[: over_match.start()] + content[over_match.end() :]

        # Extract by clause
        by_match = re.search(r"\bby\s+(.+?)$", content, re.IGNORECASE)
        if by_match:
            result["by_fields"] = [f.strip() for f in by_match.group(1).split(",")]
            content = content[: by_match.start()].strip()

        # Parse aggregations (same as stats)
        stats_result = self._parse_stats(content)
        result["aggregations"] = stats_result.get("aggregations", [])

        return result

    def _parse_lookup(self, content: str) -> dict:
        """Parse lookup command."""
        result = {"lookup_name": "", "input_fields": [], "output_fields": []}

        parts = content.split()
        if parts:
            result["lookup_name"] = parts[0]

        # Extract OUTPUT fields
        output_match = re.search(r"\bOUTPUT\s+(.+?)(?:\bAS\b|$)", content, re.IGNORECASE)
        if output_match:
            result["output_fields"] = [f.strip() for f in output_match.group(1).split(",")]
            content = content[: output_match.start()].strip()

        # Extract OUTPUTNEW fields
        outputnew_match = re.search(r"\bOUTPUTNEW\s+(.+?)(?:\bAS\b|$)", content, re.IGNORECASE)
        if outputnew_match:
            result["output_fields"] = [f.strip() for f in outputnew_match.group(1).split(",")]

        return result

    def _parse_join(self, content: str) -> dict:
        """Parse join command."""
        result = {"type": "inner", "fields": [], "subsearch": "", "max": 1, "usetime": False}

        # Extract type
        if content.lower().startswith("type="):
            type_match = re.match(r"type\s*=\s*(\w+)", content, re.IGNORECASE)
            if type_match:
                result["type"] = type_match.group(1).lower()
                content = content[type_match.end() :].strip()

        # Extract usetime
        if "usetime=true" in content.lower():
            result["usetime"] = True
            content = re.sub(r"usetime\s*=\s*\w+", "", content, flags=re.IGNORECASE)

        # Extract max
        max_match = re.search(r"max\s*=\s*(\d+)", content, re.IGNORECASE)
        if max_match:
            result["max"] = int(max_match.group(1))
            content = content[: max_match.start()] + content[max_match.end() :]

        # Extract fields (before subsearch)
        if "[" in content:
            fields_part = content[: content.index("[")].strip()
            result["fields"] = [
                f.strip() for f in fields_part.split(",") if f.strip() and "=" not in f
            ]
            result["subsearch"] = content[content.index("[") :]
        else:
            result["fields"] = [f.strip() for f in content.split() if f.strip() and "=" not in f]

        return result

    def _parse_transaction(self, content: str) -> dict:
        """Parse transaction command."""
        result = {
            "fields": [],
            "startswith": None,
            "endswith": None,
            "maxspan": None,
            "maxpause": None,
            "keepevicted": False,
        }

        # Extract startswith
        startswith_match = re.search(
            r'startswith\s*=\s*("([^"]+)"|\'([^\']+)\'|(\S+))', content, re.IGNORECASE
        )
        if startswith_match:
            result["startswith"] = (
                startswith_match.group(2) or startswith_match.group(3) or startswith_match.group(4)
            )
            content = content[: startswith_match.start()] + content[startswith_match.end() :]

        # Extract endswith
        endswith_match = re.search(
            r'endswith\s*=\s*("([^"]+)"|\'([^\']+)\'|(\S+))', content, re.IGNORECASE
        )
        if endswith_match:
            result["endswith"] = (
                endswith_match.group(2) or endswith_match.group(3) or endswith_match.group(4)
            )
            content = content[: endswith_match.start()] + content[endswith_match.end() :]

        # Extract maxspan
        maxspan_match = re.search(r"maxspan\s*=\s*(\S+)", content, re.IGNORECASE)
        if maxspan_match:
            result["maxspan"] = maxspan_match.group(1)
            content = content[: maxspan_match.start()] + content[maxspan_match.end() :]

        # Extract maxpause
        maxpause_match = re.search(r"maxpause\s*=\s*(\S+)", content, re.IGNORECASE)
        if maxpause_match:
            result["maxpause"] = maxpause_match.group(1)
            content = content[: maxpause_match.start()] + content[maxpause_match.end() :]

        # Remaining is fields
        result["fields"] = [f.strip() for f in content.split() if f.strip() and "=" not in f]

        return result

    def _parse_fillnull(self, content: str) -> dict:
        """Parse fillnull command."""
        result = {"value": "", "fields": []}

        # Extract value
        value_match = re.search(
            r'value\s*=\s*("([^"]+)"|\'([^\']+)\'|(\S+))', content, re.IGNORECASE
        )
        if value_match:
            result["value"] = (
                value_match.group(2) or value_match.group(3) or value_match.group(4) or ""
            )
            content = content[: value_match.start()] + content[value_match.end() :]
        else:
            result["value"] = "0"  # Default

        # Remaining is fields
        fields = [f.strip() for f in content.split() if f.strip()]
        result["fields"] = fields if fields else []  # Empty means all fields

        return result

    def _parse_replace(self, content: str) -> dict:
        """Parse replace command."""
        result = {"replacements": [], "fields": []}

        # Pattern: value1 WITH value2 IN field1, field2
        # or: value1 WITH value2, value3 WITH value4 IN fields

        # Extract IN clause
        in_match = re.search(r"\bIN\s+(.+?)$", content, re.IGNORECASE)
        if in_match:
            result["fields"] = [f.strip() for f in in_match.group(1).split(",")]
            content = content[: in_match.start()].strip()

        # Parse replacements
        with_matches = re.findall(
            r'("([^"]+)"|\'([^\']+)\'|(\S+))\s+WITH\s+("([^"]+)"|\'([^\']+)\'|(\S+))',
            content,
            re.IGNORECASE,
        )
        for match in with_matches:
            old = match[1] or match[2] or match[3]
            new = match[5] or match[6] or match[7]
            result["replacements"].append({"from": old, "to": new})

        return result

    def _parse_iplocation(self, content: str) -> dict:
        """Parse iplocation command."""
        result = {"field": "clientip", "prefix": "", "allfields": False}

        parts = content.split()
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                if key.lower() == "prefix":
                    result["prefix"] = value.strip("\"'")
                elif key.lower() == "allfields":
                    result["allfields"] = value.lower() == "true"
            else:
                result["field"] = part

        return result

    def _parse_convert(self, content: str) -> dict:
        """Parse convert command."""
        result = {"conversions": [], "timeformat": None}

        # Extract timeformat
        tf_match = re.search(
            r'timeformat\s*=\s*("([^"]+)"|\'([^\']+)\'|(\S+))', content, re.IGNORECASE
        )
        if tf_match:
            result["timeformat"] = tf_match.group(2) or tf_match.group(3) or tf_match.group(4)
            content = content[: tf_match.start()] + content[tf_match.end() :]

        # Parse conversion functions
        # Format: function(field) [AS newfield], function(field) [AS newfield]
        conv_patterns = [
            r"(auto|num|dur|mstime|memk|rmunit|rmcomma|ctime|mktime)\s*\(([^)]+)\)(?:\s+[Aa][Ss]\s+(\w+))?"
        ]

        for pattern in conv_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                func = match.group(1)
                field = match.group(2)
                alias = match.group(3) if len(match.groups()) > 2 else None
                result["conversions"].append(
                    {"function": func, "field": field.strip(), "alias": alias}
                )

        return result

    def _parse_makemv(self, content: str) -> dict:
        """Parse makemv command."""
        result = {"field": "", "delim": " ", "allowempty": False, "setsv": False}

        # Extract delim
        delim_match = re.search(
            r'delim\s*=\s*("([^"]+)"|\'([^\']+)\'|(\S+))', content, re.IGNORECASE
        )
        if delim_match:
            result["delim"] = delim_match.group(2) or delim_match.group(3) or delim_match.group(4)
            content = content[: delim_match.start()] + content[delim_match.end() :]

        # Extract tokenizer
        tokenizer_match = re.search(
            r'tokenizer\s*=\s*("([^"]+)"|\'([^\']+)\')', content, re.IGNORECASE
        )
        if tokenizer_match:
            result["tokenizer"] = tokenizer_match.group(2) or tokenizer_match.group(3)
            content = content[: tokenizer_match.start()] + content[tokenizer_match.end() :]

        # Extract allowempty
        if "allowempty=true" in content.lower() or "allowempty=t" in content.lower():
            result["allowempty"] = True
            content = re.sub(r"allowempty\s*=\s*\w+", "", content, flags=re.IGNORECASE)

        # Extract setsv
        if "setsv=true" in content.lower() or "setsv=t" in content.lower():
            result["setsv"] = True
            content = re.sub(r"setsv\s*=\s*\w+", "", content, flags=re.IGNORECASE)

        # Remaining is field
        field = content.strip()
        if field:
            result["field"] = field

        return result

    def _store_legacy_format(self, cmd: SPLCommand, result: SPLParseResult):
        """Store command in legacy format for backward compatibility."""
        if cmd.name == "eval":
            result.eval_fields.append(cmd.args)
        elif cmd.name == "stats":
            result.stats_aggregations.append(cmd.args)
        elif cmd.name == "where":
            result.where_conditions.append(cmd.args.get("condition", cmd.raw))
        elif cmd.name == "search":
            result.where_conditions.append(f"search filter: {cmd.args.get('filter', cmd.raw)}")
        elif cmd.name == "fields":
            result.fields_selected.extend(cmd.args.get("include", []))
            result.fields_removed.extend(cmd.args.get("exclude", []))
        else:
            result.other_commands.append({"type": cmd.name, **cmd.args})

    def _infer_log_type(self, parsed: SPLParseResult) -> str:
        """Infer Panther log type from SPL index/sourcetype."""
        search_text = f"{parsed.index} {parsed.sourcetype} {parsed.base_search}".lower()

        for keyword, log_type in self.LOG_TYPE_MAPPING.items():
            if keyword in search_text:
                return log_type

        return "Custom.YourLogType"

    def _convert_span_to_sql(self, span: str, field: str = "_time") -> dict:
        """Convert SPL span to SQL DATE_TRUNC expression."""
        unit_map = {
            "s": ("second", "seconds"),
            "sec": ("second", "seconds"),
            "second": ("second", "seconds"),
            "seconds": ("second", "seconds"),
            "m": ("minute", "minutes"),
            "min": ("minute", "minutes"),
            "minute": ("minute", "minutes"),
            "minutes": ("minute", "minutes"),
            "h": ("hour", "hours"),
            "hr": ("hour", "hours"),
            "hour": ("hour", "hours"),
            "hours": ("hour", "hours"),
            "d": ("day", "days"),
            "day": ("day", "days"),
            "days": ("day", "days"),
            "w": ("week", "weeks"),
            "week": ("week", "weeks"),
            "weeks": ("week", "weeks"),
            "mon": ("month", "months"),
            "month": ("month", "months"),
            "months": ("month", "months"),
            "y": ("year", "years"),
            "year": ("year", "years"),
            "years": ("year", "years"),
        }

        match = re.match(r"^(\d+)([a-z]+)$", span.lower())
        if match:
            amount = int(match.group(1))
            unit = match.group(2)

            if unit in unit_map:
                sql_unit, human_unit = unit_map[unit]
                sql_field = "p_event_time" if field == "_time" else field

                return {
                    "select_expr": f"DATE_TRUNC('{sql_unit}', {sql_field})",
                    "group_expr": f"DATE_TRUNC('{sql_unit}', {sql_field})",
                    "description": f"Bucket by {amount} {human_unit}",
                }

        sql_field = "p_event_time" if field == "_time" else field
        return {
            "select_expr": f"DATE_TRUNC('hour', {sql_field})",
            "group_expr": f"DATE_TRUNC('hour', {sql_field})",
            "description": f"Bucket by hour (original: {span})",
        }

    def _generate_helper_functions(self, parsed: SPLParseResult) -> list[str]:
        """Generate helper functions needed for the rule."""
        helpers = []
        all_functions = set()

        for cmd in parsed.commands:
            if cmd.name == "eval":
                for assignment in cmd.args.get("assignments", []):
                    all_functions.update(assignment.get("functions", []))

        if "match" in all_functions or "like" in all_functions:
            helpers.append('''
def matches_pattern(value: str, pattern: str) -> bool:
    """Check if value matches a regex pattern (SPL match/like equivalent)."""
    if not value:
        return False
    import re
    regex_pattern = pattern.replace('%', '.*').replace('_', '.')
    return bool(re.search(regex_pattern, value, re.IGNORECASE))
''')

        if "coalesce" in all_functions:
            helpers.append('''
def coalesce(*values):
    """Return the first non-None, non-empty value (SPL coalesce equivalent)."""
    for v in values:
        if v is not None and v != "":
            return v
    return None
''')

        if "cidrmatch" in all_functions:
            helpers.append('''
def cidrmatch(cidr: str, ip: str) -> bool:
    """Check if IP matches CIDR (SPL cidrmatch equivalent)."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
''')

        if "iplocation" in all_functions or any(
            cmd.name == "iplocation" for cmd in parsed.commands
        ):
            helpers.append('''
def get_ip_location(ip: str) -> dict:
    """Get geolocation for IP using MaxMind GeoLite2 database (SPL iplocation equivalent).

    Requires: geoip2 package and MaxMind GeoLite2-City.mmdb file.
    Set GEOIP_DB_PATH environment variable to the database location.

    Returns dict with: Country, Region, City, lat, lon, timezone, postal_code
    """
    import os
    try:
        import geoip2.database
        db_path = os.environ.get("GEOIP_DB_PATH", "/var/lib/GeoIP/GeoLite2-City.mmdb")
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            return {
                "Country": response.country.name or "Unknown",
                "Region": (response.subdivisions.most_specific.name
                           if response.subdivisions else "Unknown"),
                "City": response.city.name or "Unknown",
                "lat": response.location.latitude or 0,
                "lon": response.location.longitude or 0,
                "timezone": response.location.time_zone or "Unknown",
                "postal_code": response.postal.code or "Unknown",
            }
    except Exception:
        return {"Country": "Unknown", "Region": "Unknown", "City": "Unknown", "lat": 0, "lon": 0}
''')

        # Add math helper functions if needed
        math_functions = {"abs", "ceil", "floor", "round", "pow", "sqrt", "log", "ln", "exp"}
        if math_functions & all_functions:
            helpers.append('''
import math

def spl_abs(x):
    """SPL abs() equivalent."""
    return abs(float(x)) if x is not None else None

def spl_ceil(x):
    """SPL ceiling() equivalent."""
    return math.ceil(float(x)) if x is not None else None

def spl_floor(x):
    """SPL floor() equivalent."""
    return math.floor(float(x)) if x is not None else None

def spl_round(x, digits=0):
    """SPL round() equivalent."""
    if x is None:
        return None
    return round(float(x), int(digits))

def spl_pow(base, exp):
    """SPL pow() equivalent."""
    if base is None or exp is None:
        return None
    return math.pow(float(base), float(exp))

def spl_sqrt(x):
    """SPL sqrt() equivalent."""
    if x is None or float(x) < 0:
        return None
    return math.sqrt(float(x))

def spl_log(x, base=10):
    """SPL log() equivalent (base 10 default)."""
    if x is None or float(x) <= 0:
        return None
    return math.log(float(x), float(base))

def spl_ln(x):
    """SPL ln() natural log equivalent."""
    if x is None or float(x) <= 0:
        return None
    return math.log(float(x))

def spl_exp(x):
    """SPL exp() equivalent."""
    return math.exp(float(x)) if x is not None else None
''')

        # Add string helper functions if needed
        string_functions = {"substr", "replace", "split", "mvindex", "mvjoin"}
        if string_functions & all_functions:
            helpers.append('''
def spl_substr(s, start, length=None):
    """SPL substr() equivalent. 1-indexed, returns substring."""
    if s is None:
        return None
    s = str(s)
    # SPL uses 1-based indexing
    start_idx = int(start) - 1 if int(start) > 0 else int(start)
    if length is None:
        return s[start_idx:]
    return s[start_idx:start_idx + int(length)]

def spl_replace(s, pattern, replacement):
    """SPL replace() equivalent with regex support."""
    import re
    if s is None:
        return None
    return re.sub(pattern, replacement, str(s))

def spl_split(s, delimiter=" "):
    """SPL split() equivalent - returns multivalue list."""
    if s is None:
        return []
    return str(s).split(delimiter)

def spl_mvindex(mv, index):
    """SPL mvindex() equivalent - get item from multivalue field."""
    if mv is None:
        return None
    if isinstance(mv, str):
        mv = [mv]
    idx = int(index)
    if idx < 0:
        idx = len(mv) + idx
    return mv[idx] if 0 <= idx < len(mv) else None

def spl_mvjoin(mv, delimiter=" "):
    """SPL mvjoin() equivalent - join multivalue field."""
    if mv is None:
        return None
    if isinstance(mv, str):
        return mv
    return delimiter.join(str(v) for v in mv)
''')

        return helpers

    def convert(
        self,
        spl: str,
        rule_id: str,
        class_name: str | None = None,
        severity: str | None = None,
        force_streaming: bool = False,
    ) -> EnhancedConversionResult:
        """Convert SPL to Panther rule.

        Args:
            spl: The Splunk SPL query to convert
            rule_id: Unique rule identifier
            class_name: Optional Python class name (auto-generated if not provided)
            severity: Rule severity (LOW, MEDIUM, HIGH, CRITICAL)
            force_streaming: If True, always generate Python streaming rule even for aggregations

        Returns:
            EnhancedConversionResult with generated code and metadata

        Rule Type Selection:
            - Streaming (Python): No aggregation, evaluates each event independently
            - Scheduled (SQL+Python): Has stats/aggregation, needs to query historical data
        """
        parsed = self.parse_spl(spl)

        if not class_name:
            parts = rule_id.replace(".", "_").replace("-", "_").split("_")
            class_name = "".join(p.title() for p in parts if p)

        log_type = self._infer_log_type(parsed)

        # Determine rule type based on SPL commands
        needs_aggregation = parsed.is_threshold_rule or parsed.stats_aggregations

        if needs_aggregation and not force_streaming:
            # Aggregation requires scheduled SQL query
            return self._generate_scheduled_rule(
                parsed, spl, rule_id, class_name, log_type, severity or "MEDIUM"
            )
        else:
            # Simple filters can use streaming Python rule
            return self._generate_streaming_rule(
                parsed, spl, rule_id, class_name, log_type, severity or "MEDIUM"
            )

    def _generate_streaming_rule(
        self,
        parsed: SPLParseResult,
        original_spl: str,
        rule_id: str,
        class_name: str,
        log_type: str,
        severity: str,
    ) -> EnhancedConversionResult:
        """Generate a Python streaming detection rule."""
        todos = []
        helpers = self._generate_helper_functions(parsed)

        # Check if this SPL has aggregations (which can't be fully handled in streaming)
        has_aggregation = parsed.is_threshold_rule or parsed.stats_aggregations
        if has_aggregation:
            todos.append(
                "WARNING: This SPL has aggregations (stats/count/dc) which require "
                "a Scheduled Rule with SQL, or use Panther Lookup Tables for state tracking"
            )

        # Generate Python code for eval expressions
        eval_code_lines = []
        for cmd in parsed.commands:
            if cmd.name == "eval":
                for assignment in cmd.args.get("assignments", []):
                    field = assignment["field"]
                    expr = assignment["expression"]
                    python_expr = self._convert_eval_to_python(field, expr)
                    if python_expr:
                        eval_code_lines.append(python_expr)
                    else:
                        eval_code_lines.append(f"        # TODO: {field} = {expr}")
                        todos.append(f"Translate eval '{field}': {expr}")

            elif cmd.name == "rex":
                pattern = cmd.args.get("pattern", "")
                field = cmd.args.get("field", "_raw")
                extracted = cmd.args.get("extracted_fields", [])
                if extracted:
                    eval_code_lines.append(f"        # Extract from {field} using regex")
                    eval_code_lines.append(
                        f"        _match = re.search(r'{pattern}', deep_get(event, '{field}', ''))"
                    )
                    for ef in extracted:
                        eval_code_lines.append(
                            f"        {ef} = _match.group('{ef}') if _match else None"
                        )
                else:
                    todos.append(f"Extract fields using rex: {pattern}")

            elif cmd.name == "spath":
                path = cmd.args.get("path", "")
                output = cmd.args.get("output", path.split(".")[-1] if path else "value")
                if path:
                    # Convert dot notation to deep_get path
                    path_parts = path.split(".")
                    path_str = "', '".join(path_parts)
                    eval_code_lines.append(
                        f"        {output} = deep_get(event, '{path_str}', None)"
                    )

            elif cmd.name == "lookup":
                lookup_name = cmd.args.get("lookup_name", "")
                todos.append(
                    f"Implement lookup table '{lookup_name}' - "
                    "use p_enrichment() or Panther Lookup Tables"
                )

            elif cmd.name == "iplocation":
                field = cmd.args.get("field", "clientip")
                todos.append(
                    f"Add geolocation for '{field}' - use Panther's p_enrichment() or GeoIP lookup"
                )

            elif cmd.name in (
                "stats",
                "eventstats",
                "streamstats",
                "timechart",
                "chart",
                "top",
                "rare",
            ):
                # Can't do aggregation in streaming - add detailed TODO
                pass  # Already handled above

            elif cmd.name == "transaction":
                todos.append(
                    "Transaction correlation requires Scheduled Rule "
                    "or correlation logic outside the rule"
                )

            elif cmd.name not in (
                "search",
                "where",
                "fields",
                "table",
                "rename",
                "sort",
                "head",
                "tail",
                "dedup",
            ):
                todos.append(f"Review '{cmd.name}' command: {cmd.raw}")

        # Generate Python conditions from base search
        base_conditions = self._generate_python_conditions(parsed)

        # Generate Python conditions from where clauses
        where_conditions = []
        for cmd in parsed.commands:
            if cmd.name == "where":
                cond = cmd.args.get("condition", "")
                python_cond = self._convert_where_to_python(cond)
                if python_cond:
                    where_conditions.append(python_cond)
                else:
                    where_conditions.append(f"True  # TODO: {cond}")
                    todos.append(f"Convert where condition: {cond}")

        # Build the rule code
        code_lines = [
            '"""',
            f"Panther Detection Rule: {rule_id}",
            "",
            "Original Splunk SPL:",
            f"{original_spl}",
            '"""',
            "",
            "from panther_sdk import detection, PantherEvent",
            "from panther_sdk.helpers import deep_get",
            "import re",
        ]

        for helper in helpers:
            code_lines.append(helper)

        code_lines.extend(
            [
                "",
                "",
                f"class {class_name}(detection.Rule):",
                f'    id = "{rule_id}"',
                f'    log_types = ["{log_type}"]',
                f"    severity = detection.Severity.{severity.upper()}",
                "",
                "    def rule(self, event: PantherEvent) -> bool:",
                '        """Detection logic converted from Splunk SPL."""',
            ]
        )

        # Add eval code
        if eval_code_lines:
            code_lines.append("        # Field extractions and transformations")
            code_lines.extend(eval_code_lines)
            code_lines.append("")

        # Add base search conditions
        if base_conditions:
            code_lines.append("        # Base search conditions")
            for cond in base_conditions:
                code_lines.append(f"        if not ({cond}):")
                code_lines.append("            return False")
            code_lines.append("")

        # Add where conditions
        if where_conditions:
            code_lines.append("        # Where clause conditions")
            for cond in where_conditions:
                code_lines.append(f"        if not ({cond}):")
                code_lines.append("            return False")
            code_lines.append("")

        # Final return
        if not base_conditions and not where_conditions:
            # FAIL CLOSED: no conditions could be converted. Returning True here
            # would alert on EVERY event of the log type (alert storm); an inert
            # rule with a loud TODO is the safe failure mode.
            code_lines.append("        # TODO: No conditions could be converted from the SPL.")
            code_lines.append("        # This rule is INERT (never fires) until you add the")
            code_lines.append("        # detection logic from the original query above.")
            code_lines.append("        return False")
            if not todos or "Add detection conditions" not in str(todos):
                todos.append(
                    "NO conditions were converted -- rule is inert (returns False) "
                    "until detection logic is added from the original SPL"
                )
        else:
            code_lines.append("        return True")

        # Generate title
        title_field = self._get_title_field(parsed)
        code_lines.extend(
            [
                "",
                "    def title(self, event: PantherEvent) -> str:",
                f'        return f"{class_name}: '
                f"{{deep_get(event, '{title_field}', 'unknown')}}\"",
                "",
            ]
        )

        if log_type == "Custom.YourLogType":
            todos.insert(0, f"Update log_types from '{log_type}' to your actual log type")

        source_code = "\n".join(code_lines)

        return EnhancedConversionResult(
            source_code=source_code,
            rule_id=rule_id,
            class_name=class_name,
            log_types=[log_type],
            severity=severity,
            todos=todos,
            is_threshold_rule=False,
            recommended_type=RuleType.STREAMING,
            recommendation_reasons=["No aggregation commands found - can be evaluated per event"],
            test_code=self._generate_test_code(class_name, log_type),
            parse_details=parsed,
        )

    def _generate_scheduled_rule(
        self,
        parsed: SPLParseResult,
        original_spl: str,
        rule_id: str,
        class_name: str,
        log_type: str,
        severity: str,
    ) -> EnhancedConversionResult:
        """Generate a scheduled query rule."""
        todos = []
        helpers = self._generate_helper_functions(parsed)
        reasons = []

        # Build SQL query from commands
        sql_parts = []
        group_by_fields = []
        having_conditions = []

        for cmd in parsed.commands:
            if cmd.name in ("stats", "eventstats", "streamstats"):
                reasons.append(f"Contains {cmd.name} aggregation")
                for agg in cmd.args.get("aggregations", []):
                    sql_agg = self._convert_agg_to_sql(agg)
                    if sql_agg:
                        sql_parts.append(sql_agg)
                group_by_fields.extend(cmd.args.get("by_fields", []))

            elif cmd.name in ("bin", "bucket"):
                reasons.append("Contains time bucketing")
                span = cmd.args.get("span")
                field = cmd.args.get("field", "_time")
                if span:
                    time_bucket = self._convert_span_to_sql(span, field)
                    sql_parts.insert(0, f"{time_bucket['select_expr']} AS time_bucket")
                    group_by_fields.insert(0, time_bucket["group_expr"])

            elif cmd.name in ("top", "rare"):
                reasons.append(f"Contains {cmd.name} aggregation")
                limit = cmd.args.get("limit", 10)
                fields = cmd.args.get("fields", [])
                if fields:
                    sql_parts.append("COUNT(*) AS count")
                    group_by_fields.extend(fields)
                todos.append(f"Add LIMIT {limit} to query")

            elif cmd.name in ("chart", "timechart"):
                reasons.append(f"Contains {cmd.name} aggregation")
                for agg in cmd.args.get("aggregations", []):
                    sql_agg = self._convert_agg_to_sql(agg)
                    if sql_agg:
                        sql_parts.append(sql_agg)
                group_by_fields.extend(cmd.args.get("by_fields", []))
                if cmd.args.get("span"):
                    time_bucket = self._convert_span_to_sql(cmd.args["span"])
                    sql_parts.insert(0, f"{time_bucket['select_expr']} AS time_bucket")
                    group_by_fields.insert(0, time_bucket["group_expr"])

            elif cmd.name == "transaction":
                reasons.append("Contains transaction correlation")
                todos.append("Implement transaction logic with window functions or self-join")
                todos.append(f"Transaction fields: {cmd.args.get('fields', [])}")
                if cmd.args.get("maxspan"):
                    todos.append(f"Transaction maxspan: {cmd.args['maxspan']}")

            elif cmd.name == "join":
                reasons.append("Contains join operation")
                todos.append(f"Implement {cmd.args.get('type', 'inner')} join in SQL")
                if cmd.args.get("subsearch"):
                    todos.append(f"Subsearch: {cmd.args['subsearch']}")

            elif cmd.name == "dedup":
                reasons.append("Contains deduplication")
                fields = cmd.args.get("fields", [])
                todos.append(f"Add ROW_NUMBER() OVER (PARTITION BY {', '.join(fields)}) for dedup")

            elif cmd.name == "where":
                having_conditions.append(cmd.args.get("condition", ""))

            elif cmd.name == "eval":
                for assignment in cmd.args.get("assignments", []):
                    field = assignment["field"]
                    expr = assignment["expression"]
                    sql_expr = self._convert_eval_to_sql(field, expr)
                    if sql_expr:
                        sql_parts.append(sql_expr)
                    else:
                        todos.append(f"Translate eval '{field}': {expr}")

            elif cmd.name == "rex":
                todos.append(f"Convert rex to REGEXP_EXTRACT: {cmd.args.get('pattern', '')}")

            elif cmd.name == "lookup":
                todos.append(f"Convert lookup '{cmd.args.get('lookup_name', '')}' to JOIN")

            elif cmd.name not in ("search", "fields", "table", "rename", "sort", "head", "tail"):
                todos.append(f"Review '{cmd.name}' command for SQL conversion")

        # Handle subsearches
        if parsed.has_subsearch:
            reasons.append("Contains subsearch")
            todos.append("Implement subsearch as CTE (WITH clause) or subquery")

        # Build time filter from parsed time range
        time_filter = (
            self._convert_time_range(parsed.earliest)
            if parsed.earliest
            else "p_occurs_since('1 hour')"
        )

        # Extract base search filters (EventCode, etc.)
        base_filters = self._extract_base_filters(parsed.base_search)
        base_filter_sql = self._filters_to_sql(base_filters)

        # Build WHERE clause
        where_parts = [time_filter]
        if base_filter_sql:
            where_parts.append(base_filter_sql)
        where_clause = "\n            AND ".join(where_parts)

        # Separate computed columns (CASE WHEN, COALESCE) from aggregations
        computed_columns = []
        aggregation_columns = []
        passthrough_columns = []  # Columns needed for aggregation

        # Computed column prefixes (expressions that need to be in CTE)
        computed_prefixes = ("CASE WHEN", "COALESCE(", "LOWER(", "UPPER(", "TRIM(", "CONCAT(")

        for part in sql_parts:
            if any(part.startswith(prefix) for prefix in computed_prefixes):
                computed_columns.append(part)
                # Extract the alias (AS name)
                alias_match = re.search(r"\bAS\s+(\w+)$", part, re.IGNORECASE)
                if alias_match:
                    passthrough_columns.append(alias_match.group(1))
            elif any(
                agg in part.upper()
                for agg in ["COUNT(", "SUM(", "AVG(", "MAX(", "MIN(", "ARRAY_AGG("]
            ):
                aggregation_columns.append(part)
            else:
                passthrough_columns.append(part)

        # Build SQL query - use CTE if there are computed columns
        if computed_columns:
            # CTE for computed columns
            cte_select = ",\n            ".join(computed_columns)

            # Add raw columns needed for aggregation
            raw_columns_for_agg = set()
            for agg in aggregation_columns:
                # Extract field name from aggregation like MAX(field) or ARRAY_AGG(DISTINCT field)
                field_match = re.search(r"\((?:DISTINCT\s+)?(\w+)\)", agg)
                if field_match and field_match.group(1) not in passthrough_columns:
                    raw_columns_for_agg.add(field_match.group(1))

            if raw_columns_for_agg:
                cte_select += ",\n            " + ",\n            ".join(raw_columns_for_agg)

            # Outer query aggregations
            outer_select = (
                ",\n        ".join(aggregation_columns)
                if aggregation_columns
                else "COUNT(*) AS count"
            )
            if group_by_fields:
                outer_select += ",\n        " + ",\n        ".join(group_by_fields)

            sql_group = ", ".join(group_by_fields) if group_by_fields else ""

            sql_query = f"""
    WITH computed AS (
        SELECT
            {cte_select}
        FROM {{{log_type}}}
        WHERE
            {where_clause}
    )
    SELECT
        {outer_select}
    FROM computed
    {("GROUP BY " + sql_group) if sql_group else "-- TODO: Add GROUP BY if needed"}
    {("HAVING " + " AND ".join(having_conditions)) if having_conditions else ""}
    """
        else:
            # Simple query without CTE
            sql_select = ", ".join(sql_parts) if sql_parts else "COUNT(*) AS count"
            sql_group = ", ".join(group_by_fields) if group_by_fields else ""

            select_fields = [sql_select] if sql_select else []
            if group_by_fields:
                select_fields.extend(group_by_fields)
            select_clause = ",\n        ".join(select_fields)

            sql_query = f"""
    SELECT
        {select_clause}
    FROM {{{log_type}}}
    WHERE
        {where_clause}
    {("GROUP BY " + sql_group) if sql_group else "-- TODO: Add GROUP BY if needed"}
    {
                ("HAVING " + " AND ".join(having_conditions))
                if having_conditions
                else "-- TODO: Add HAVING for thresholds"
            }
    """

        # Generate the rule code
        code_lines = [
            '"""',
            f"Panther Scheduled Query Rule: {rule_id}",
            "",
            "Original Splunk SPL:",
            f"{original_spl}",
            "",
            "This query runs on a schedule and aggregates data over time.",
            '"""',
            "",
            "from panther_sdk import detection, PantherEvent",
            "from panther_sdk.helpers import deep_get",
        ]

        for helper in helpers:
            code_lines.append(helper)

        code_lines.extend(
            [
                "",
                "",
                f"class {class_name}(detection.ScheduledRule):",
                f'    id = "{rule_id}"',
                f'    log_types = ["{log_type}"]',
                f"    severity = detection.Severity.{severity.upper()}",
                "",
                "    # Scheduled rule SQL query",
                '    query = """',
                f"{sql_query}",
                '    """',
                "",
                "    def rule(self, event: PantherEvent) -> bool:",
                '        """Evaluate each row returned by the scheduled query."""',
            ]
        )

        # Generate threshold check from where conditions
        threshold_code = self._generate_threshold_check(parsed.where_conditions, group_by_fields)
        for line in threshold_code:
            code_lines.append(line)

        # Generate title with context fields
        title_parts = []
        for field in group_by_fields[:2]:  # Use first 2 group by fields
            title_parts.append(f"{{deep_get(event, '{field}', 'unknown')}}")
        title_context = " - ".join(title_parts) if title_parts else "Aggregation alert"

        code_lines.extend(
            [
                "",
                "    def title(self, event: PantherEvent) -> str:",
                f'        return f"{class_name}: {title_context}"',
                "",
            ]
        )

        if log_type == "Custom.YourLogType":
            todos.insert(0, f"Update log_types from '{log_type}' to your actual Panther log type")

        todos.insert(0, "Review and complete the SQL query for your data schema")

        source_code = "\n".join(code_lines)

        return EnhancedConversionResult(
            source_code=source_code,
            rule_id=rule_id,
            class_name=class_name,
            log_types=[log_type],
            severity=severity,
            todos=todos,
            is_threshold_rule=True,
            threshold=None,
            recommended_type=RuleType.SCHEDULED,
            recommendation_reasons=reasons
            if reasons
            else ["Contains aggregation that requires scheduled execution"],
            test_code=self._generate_test_code(class_name, log_type),
            parse_details=parsed,
        )

    def _convert_agg_to_sql(self, agg: dict) -> str | None:
        """Convert SPL aggregation to SQL."""
        agg_type = agg.get("type", "")
        field = agg.get("field", "*")
        alias = agg.get("alias", agg_type)

        sql_map = {
            "count": f"COUNT({field}) AS {alias}",
            "distinct_count": f"COUNT(DISTINCT {field}) AS {alias}",
            "dc": f"COUNT(DISTINCT {field}) AS {alias}",
            "sum": f"SUM({field}) AS {alias}",
            "avg": f"AVG({field}) AS {alias}",
            "max": f"MAX({field}) AS {alias}",
            "min": f"MIN({field}) AS {alias}",
            "values": f"ARRAY_AGG(DISTINCT {field}) AS {alias}",
            "list": f"ARRAY_AGG({field}) AS {alias}",
            "first": f"FIRST_VALUE({field}) AS {alias}",
            "last": f"LAST_VALUE({field}) AS {alias}",
            "earliest": f"MIN({field}) AS {alias}",
            "latest": f"MAX({field}) AS {alias}",
            "stdev": f"STDDEV({field}) AS {alias}",
            "var": f"VARIANCE({field}) AS {alias}",
            "median": f"PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY {field}) AS {alias}",
            "range": f"(MAX({field}) - MIN({field})) AS {alias}",
        }

        return sql_map.get(agg_type)

    def _convert_eval_to_sql(self, field: str, expr: str) -> str | None:
        """Convert SPL eval expression to SQL.

        Handles common patterns:
        - coalesce(a, b, c) -> COALESCE(a, b, c)
        - if(cond, val1, val2) -> CASE WHEN cond THEN val1 ELSE val2 END
        - lower(field) -> LOWER(field)
        - match(field, pattern) -> REGEXP_LIKE(field, pattern)
        - like(field, pattern) -> field LIKE pattern
        """
        expr = expr.strip()

        # Simple coalesce: coalesce(a, b, c)
        coalesce_match = re.match(r"^coalesce\s*\((.+)\)$", expr, re.IGNORECASE)
        if coalesce_match:
            args = coalesce_match.group(1)
            return f"COALESCE({args}) AS {field}"

        # Simple lower/upper
        lower_match = re.match(r"^lower\s*\((\w+)\)$", expr, re.IGNORECASE)
        if lower_match:
            return f"LOWER({lower_match.group(1)}) AS {field}"

        upper_match = re.match(r"^upper\s*\((\w+)\)$", expr, re.IGNORECASE)
        if upper_match:
            return f"UPPER({upper_match.group(1)}) AS {field}"

        # Nested lower(coalesce(...)) or upper(coalesce(...))
        lower_coalesce_match = re.match(
            r"^lower\s*\(\s*coalesce\s*\((.+)\)\s*\)$", expr, re.IGNORECASE
        )
        if lower_coalesce_match:
            args = lower_coalesce_match.group(1)
            return f"LOWER(COALESCE({args})) AS {field}"

        upper_coalesce_match = re.match(
            r"^upper\s*\(\s*coalesce\s*\((.+)\)\s*\)$", expr, re.IGNORECASE
        )
        if upper_coalesce_match:
            args = upper_coalesce_match.group(1)
            return f"UPPER(COALESCE({args})) AS {field}"

        # if(condition, true_val, false_val) -> CASE WHEN
        if_match = re.match(r"^if\s*\((.+),\s*(\d+),\s*(\d+)\)$", expr, re.IGNORECASE | re.DOTALL)
        if if_match:
            condition = if_match.group(1).strip()
            true_val = if_match.group(2)
            false_val = if_match.group(3)

            # Convert the condition
            sql_condition = self._convert_condition_to_sql(condition)
            if sql_condition:
                return f"CASE WHEN {sql_condition} THEN {true_val} ELSE {false_val} END AS {field}"

        # If we can't convert, return None (will be added as TODO)
        return None

    def _convert_condition_to_sql(self, condition: str) -> str | None:
        """Convert SPL condition to SQL condition."""
        result = condition

        # Convert match(lower(field), "pattern") to REGEXP_LIKE(LOWER(field), 'pattern')
        result = re.sub(
            r'match\s*\(\s*lower\s*\(\s*(\w+)\s*\)\s*,\s*"([^"]+)"\s*\)',
            r"REGEXP_LIKE(LOWER(\1), '\2')",
            result,
            flags=re.IGNORECASE,
        )

        # Convert match(field, "pattern") to REGEXP_LIKE(field, 'pattern')
        result = re.sub(
            r'match\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)',
            r"REGEXP_LIKE(\1, '\2')",
            result,
            flags=re.IGNORECASE,
        )

        # Convert like(lower(field), "pattern") to LOWER(field) LIKE 'pattern'
        result = re.sub(
            r'like\s*\(\s*lower\s*\(\s*(\w+)\s*\)\s*,\s*"([^"]+)"\s*\)',
            r"LOWER(\1) LIKE '\2'",
            result,
            flags=re.IGNORECASE,
        )

        # Convert like(field, "pattern") to field LIKE 'pattern'
        result = re.sub(
            r'like\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)', r"\1 LIKE '\2'", result, flags=re.IGNORECASE
        )

        # Convert AND/OR (already valid SQL)
        # Convert parentheses (already valid SQL)

        return result if result != condition else None

    def _convert_eval_to_python(self, field: str, expr: str) -> str | None:
        """Convert SPL eval expression to Python code."""
        expr = expr.strip()

        # Simple coalesce: coalesce(a, b, c)
        coalesce_match = re.match(r"^coalesce\s*\((.+)\)$", expr, re.IGNORECASE)
        if coalesce_match:
            args = coalesce_match.group(1)
            # Convert field names to deep_get calls
            fields = [f.strip() for f in args.split(",")]
            gets = [f"deep_get(event, '{f}', None)" for f in fields]
            return f"        {field} = next((v for v in [{', '.join(gets)}] if v), None)"

        # Simple lower/upper
        lower_match = re.match(r"^lower\s*\((\w+)\)$", expr, re.IGNORECASE)
        if lower_match:
            src = lower_match.group(1)
            return f"        {field} = (deep_get(event, '{src}', '') or '').lower()"

        upper_match = re.match(r"^upper\s*\((\w+)\)$", expr, re.IGNORECASE)
        if upper_match:
            src = upper_match.group(1)
            return f"        {field} = (deep_get(event, '{src}', '') or '').upper()"

        # len(field)
        len_match = re.match(r"^len\s*\((\w+)\)$", expr, re.IGNORECASE)
        if len_match:
            src = len_match.group(1)
            return f"        {field} = len(str(deep_get(event, '{src}', '') or ''))"

        # trim/ltrim/rtrim
        trim_match = re.match(r"^(l?r?trim)\s*\((\w+)\)$", expr, re.IGNORECASE)
        if trim_match:
            func = trim_match.group(1).lower()
            src = trim_match.group(2)
            if func == "ltrim":
                return f"        {field} = (deep_get(event, '{src}', '') or '').lstrip()"
            elif func == "rtrim":
                return f"        {field} = (deep_get(event, '{src}', '') or '').rstrip()"
            else:
                return f"        {field} = (deep_get(event, '{src}', '') or '').strip()"

        # Nested lower(coalesce(...))
        lower_coalesce_match = re.match(
            r"^lower\s*\(\s*coalesce\s*\((.+)\)\s*\)$", expr, re.IGNORECASE
        )
        if lower_coalesce_match:
            args = lower_coalesce_match.group(1)
            fields = [f.strip() for f in args.split(",")]
            gets = [f"deep_get(event, '{f}', None)" for f in fields]
            return (
                f"        {field} = (next((v for v in [{', '.join(gets)}] if v), '') or '').lower()"
            )

        # if(condition, true_val, false_val) - improved parsing
        if_match = re.match(r"^if\s*\((.+)\)$", expr, re.IGNORECASE | re.DOTALL)
        if if_match:
            inner = if_match.group(1)
            # Parse the if() arguments considering nested parentheses
            args = self._parse_function_args(inner)
            if len(args) >= 3:
                condition = args[0].strip()
                true_val = self._convert_value_expr(args[1].strip())
                false_val = self._convert_value_expr(args[2].strip())
                python_cond = self._convert_spl_condition_to_python(condition)
                if python_cond:
                    return f"        {field} = {true_val} if ({python_cond}) else {false_val}"
                else:
                    return (
                        f"        {field} = {true_val} if ({condition}) "
                        f"else {false_val}  # TODO: verify condition"
                    )

        # case(cond1, val1, cond2, val2, ..., default)
        case_match = re.match(r"^case\s*\((.+)\)$", expr, re.IGNORECASE | re.DOTALL)
        if case_match:
            inner = case_match.group(1)
            args = self._parse_function_args(inner)
            if len(args) >= 2:
                lines = ["        # case() converted to if/elif chain"]
                for i in range(0, len(args) - 1, 2):
                    cond = args[i].strip()
                    val = self._convert_value_expr(args[i + 1].strip())
                    python_cond = self._convert_spl_condition_to_python(cond) or cond
                    if i == 0:
                        lines.append(f"        if {python_cond}:")
                    else:
                        lines.append(f"        elif {python_cond}:")
                    lines.append(f"            {field} = {val}")
                # Check for default value (odd number of args)
                if len(args) % 2 == 1:
                    default_val = self._convert_value_expr(args[-1].strip())
                    lines.append("        else:")
                    lines.append(f"            {field} = {default_val}")
                else:
                    lines.append("        else:")
                    lines.append(f"            {field} = None")
                return "\n".join(lines)

        # Math functions: abs, ceil, floor, round, pow, sqrt, log, ln, exp
        math_match = re.match(
            r"^(abs|ceil(?:ing)?|floor|round|pow|sqrt|log|ln|exp)\s*\((.+)\)$", expr, re.IGNORECASE
        )
        if math_match:
            func = math_match.group(1).lower()
            args_str = math_match.group(2)
            args = self._parse_function_args(args_str)

            if func in ("ceil", "ceiling"):
                func = "ceil"

            if func in ("abs", "ceil", "floor", "sqrt", "ln", "exp"):
                arg = self._convert_field_ref(args[0].strip())
                return f"        {field} = spl_{func}({arg})"
            elif func == "round" and len(args) >= 1:
                arg = self._convert_field_ref(args[0].strip())
                digits = args[1].strip() if len(args) > 1 else "0"
                return f"        {field} = spl_round({arg}, {digits})"
            elif func == "pow" and len(args) >= 2:
                base = self._convert_field_ref(args[0].strip())
                exp = self._convert_field_ref(args[1].strip())
                return f"        {field} = spl_pow({base}, {exp})"
            elif func == "log" and len(args) >= 1:
                arg = self._convert_field_ref(args[0].strip())
                base = args[1].strip() if len(args) > 1 else "10"
                return f"        {field} = spl_log({arg}, {base})"

        # substr(field, start, length)
        substr_match = re.match(r"^substr\s*\((.+)\)$", expr, re.IGNORECASE)
        if substr_match:
            args = self._parse_function_args(substr_match.group(1))
            if len(args) >= 2:
                src = self._convert_field_ref(args[0].strip())
                start = args[1].strip()
                length = args[2].strip() if len(args) > 2 else "None"
                return f"        {field} = spl_substr({src}, {start}, {length})"

        # replace(field, pattern, replacement)
        replace_match = re.match(r"^replace\s*\((.+)\)$", expr, re.IGNORECASE)
        if replace_match:
            args = self._parse_function_args(replace_match.group(1))
            if len(args) >= 3:
                src = self._convert_field_ref(args[0].strip())
                pattern = args[1].strip()
                replacement = args[2].strip()
                return f"        {field} = spl_replace({src}, {pattern}, {replacement})"

        # split(field, delimiter)
        split_match = re.match(r"^split\s*\((.+)\)$", expr, re.IGNORECASE)
        if split_match:
            args = self._parse_function_args(split_match.group(1))
            if len(args) >= 2:
                src = self._convert_field_ref(args[0].strip())
                delimiter = args[1].strip()
                return f"        {field} = spl_split({src}, {delimiter})"

        # mvindex(mv_field, index)
        mvindex_match = re.match(r"^mvindex\s*\((.+)\)$", expr, re.IGNORECASE)
        if mvindex_match:
            args = self._parse_function_args(mvindex_match.group(1))
            if len(args) >= 2:
                src = self._convert_field_ref(args[0].strip())
                index = args[1].strip()
                return f"        {field} = spl_mvindex({src}, {index})"

        # mvjoin(mv_field, delimiter)
        mvjoin_match = re.match(r"^mvjoin\s*\((.+)\)$", expr, re.IGNORECASE)
        if mvjoin_match:
            args = self._parse_function_args(mvjoin_match.group(1))
            if len(args) >= 2:
                src = self._convert_field_ref(args[0].strip())
                delimiter = args[1].strip()
                return f"        {field} = spl_mvjoin({src}, {delimiter})"

        # Simple field assignment: field = value
        if re.match(r'^".*"$|^\'.*\'$|^\d+$|^\d+\.\d+$', expr):
            return f"        {field} = {expr}"

        # Field reference: field = other_field
        if re.match(r"^\w+$", expr):
            return f"        {field} = deep_get(event, '{expr}', None)"

        return None

    def _parse_function_args(self, args_str: str) -> list[str]:
        """Parse function arguments, handling nested parentheses and quoted strings."""
        args = []
        current = ""
        depth = 0
        in_string = False
        string_char = None

        for char in args_str:
            if char in ('"', "'") and not in_string:
                in_string = True
                string_char = char
                current += char
            elif char == string_char and in_string:
                in_string = False
                string_char = None
                current += char
            elif char == "(" and not in_string:
                depth += 1
                current += char
            elif char == ")" and not in_string:
                depth -= 1
                current += char
            elif char == "," and depth == 0 and not in_string:
                args.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            args.append(current.strip())

        return args

    def _convert_field_ref(self, expr: str) -> str:
        """Convert field reference to deep_get or pass through literals."""
        expr = expr.strip()
        # If it's a quoted string or number, return as-is
        if re.match(r'^".*"$|^\'.*\'$|^\d+$|^\d+\.\d+$', expr):
            return expr
        # If it's a field name, convert to deep_get
        if re.match(r"^\w+$", expr):
            return f"deep_get(event, '{expr}', None)"
        # Otherwise return as-is (could be an expression)
        return expr

    def _convert_value_expr(self, expr: str) -> str:
        """Convert a value expression for use in Python code."""
        expr = expr.strip()
        # If already quoted or numeric, return as-is
        if re.match(r'^".*"$|^\'.*\'$|^\d+$|^\d+\.\d+$', expr):
            return expr
        # If it's a field name, wrap in deep_get
        if re.match(r"^\w+$", expr):
            return f"deep_get(event, '{expr}', None)"
        return expr

    def _convert_spl_condition_to_python(self, condition: str) -> str | None:
        """Convert SPL condition to Python boolean expression."""
        result = condition

        # Convert match(lower(field), "pattern") to re.search(pattern, field.lower())
        result = re.sub(
            r'match\s*\(\s*lower\s*\(\s*(\w+)\s*\)\s*,\s*"([^"]+)"\s*\)',
            r"re.search(r'\2', (deep_get(event, '\1', '') or '').lower())",
            result,
            flags=re.IGNORECASE,
        )

        # Convert match(field, "pattern")
        result = re.sub(
            r'match\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)',
            r"re.search(r'\2', deep_get(event, '\1', '') or '')",
            result,
            flags=re.IGNORECASE,
        )

        # Convert like(lower(field), "%pattern%") to pattern in field.lower()
        result = re.sub(
            r'like\s*\(\s*lower\s*\(\s*(\w+)\s*\)\s*,\s*"%([^%]+)%"\s*\)',
            r"'\2' in (deep_get(event, '\1', '') or '').lower()",
            result,
            flags=re.IGNORECASE,
        )

        # Convert like(field, "%pattern%")
        result = re.sub(
            r'like\s*\(\s*(\w+)\s*,\s*"%([^%]+)%"\s*\)',
            r"'\2' in (deep_get(event, '\1', '') or '')",
            result,
            flags=re.IGNORECASE,
        )

        # Convert AND/OR to Python
        result = re.sub(r"\bAND\b", "and", result, flags=re.IGNORECASE)
        result = re.sub(r"\bOR\b", "or", result, flags=re.IGNORECASE)

        return result if result != condition else None

    def _generate_python_conditions(self, parsed: SPLParseResult) -> list[str]:
        """Generate Python conditions from base search filters."""
        conditions = []

        # Extract filters from base search
        filters = self._extract_base_filters(parsed.base_search)
        for f in filters:
            field = f["field"]
            op = f["op"]
            value = f["value"]

            if op == "=":
                if value.isdigit():
                    conditions.append(f"deep_get(event, '{field}', None) == {value}")
                else:
                    conditions.append(f"deep_get(event, '{field}', None) == '{value}'")
            elif op == "!=":
                if value.isdigit():
                    conditions.append(f"deep_get(event, '{field}', None) != {value}")
                else:
                    conditions.append(f"deep_get(event, '{field}', None) != '{value}'")
            elif op in (">", "<", ">=", "<="):
                conditions.append(f"(deep_get(event, '{field}', 0) or 0) {op} {value}")

        return conditions

    def _convert_where_to_python(self, where_cond: str) -> str | None:
        """Convert SPL where clause to Python condition."""
        result = where_cond.strip()

        # Convert field comparisons
        # field=value -> deep_get(event, 'field', None) == value
        result = re.sub(r'\b(\w+)\s*=\s*"([^"]+)"', r"deep_get(event, '\1', None) == '\2'", result)
        result = re.sub(r"\b(\w+)\s*=\s*(\d+)\b", r"deep_get(event, '\1', None) == \2", result)

        # Convert != comparisons
        result = re.sub(r'\b(\w+)\s*!=\s*"([^"]+)"', r"deep_get(event, '\1', None) != '\2'", result)
        result = re.sub(r"\b(\w+)\s*!=\s*(\d+)\b", r"deep_get(event, '\1', None) != \2", result)

        # Convert >, <, >=, <= comparisons
        result = re.sub(
            r"\b(\w+)\s*([><=]+)\s*(\d+)\b", r"(deep_get(event, '\1', 0) or 0) \2 \3", result
        )

        # Convert AND/OR
        result = re.sub(r"\bAND\b", "and", result, flags=re.IGNORECASE)
        result = re.sub(r"\bOR\b", "or", result, flags=re.IGNORECASE)

        return result if result != where_cond else None

    def _get_title_field(self, parsed: SPLParseResult) -> str:
        """Determine best field to use in rule title."""
        # Check for host-like fields in eval
        for cmd in parsed.commands:
            if cmd.name == "eval":
                for assignment in cmd.args.get("assignments", []):
                    field = assignment["field"].lower()
                    if field in ("host", "hostname", "src_ip", "user", "victim"):
                        return assignment["field"]

        # Check common field patterns
        common_fields = [
            "hostname",
            "host",
            "ComputerName",
            "src_ip",
            "dest_ip",
            "user",
            "userName",
        ]
        for field in common_fields:
            return field  # Return first one as default

        return "hostname"

    def _convert_time_range(self, time_spec: str) -> str:
        """Convert SPL time specification to Panther SQL time filter.

        SPL formats: -15m, -1h, -24h, -7d, @d (snap to day), etc.
        Panther SQL: p_occurs_since('15 minutes'), p_occurs_since('1 hour'), etc.
        """
        if not time_spec:
            return "p_occurs_since('1 hour')"

        time_spec = time_spec.strip()

        # Handle relative time like -15m, -1h, -24h, -7d
        match = re.match(r"^-(\d+)([smhdwMy])$", time_spec)
        if match:
            amount = match.group(1)
            unit = match.group(2)
            unit_map = {
                "s": "seconds",
                "m": "minutes",
                "h": "hours",
                "d": "days",
                "w": "weeks",
                "M": "months",
                "y": "years",
            }
            human_unit = unit_map.get(unit, "hours")
            # Singularize if amount is 1
            if amount == "1" and human_unit.endswith("s"):
                human_unit = human_unit[:-1]
            return f"p_occurs_since('{amount} {human_unit}')"

        # Handle snap-to-time like @d, @h, @w
        snap_match = re.match(r"^@([smhdwMy])$", time_spec)
        if snap_match:
            unit = snap_match.group(1)
            snap_map = {
                "s": "1 second",
                "m": "1 minute",
                "h": "1 hour",
                "d": "1 day",
                "w": "1 week",
                "M": "1 month",
                "y": "1 year",
            }
            return f"p_occurs_since('{snap_map.get(unit, '1 day')}')"

        # Handle combined format like -15m@m
        combined_match = re.match(r"^-(\d+)([smhdwMy])@[smhdwMy]$", time_spec)
        if combined_match:
            amount = combined_match.group(1)
            unit = combined_match.group(2)
            unit_map = {
                "s": "seconds",
                "m": "minutes",
                "h": "hours",
                "d": "days",
                "w": "weeks",
                "M": "months",
                "y": "years",
            }
            human_unit = unit_map.get(unit, "hours")
            if amount == "1" and human_unit.endswith("s"):
                human_unit = human_unit[:-1]
            return f"p_occurs_since('{amount} {human_unit}')"

        # Default fallback
        return f"p_occurs_since('1 hour')  -- Original: {time_spec}"

    def _extract_base_filters(self, base_search: str) -> list[dict[str, str]]:
        """Extract field=value filters from SPL base search.

        Returns list of {'field': 'name', 'op': '=', 'value': 'val'} dicts.
        """
        filters = []

        if not base_search:
            return filters

        # Pattern for field=value, field="value", field='value'
        # Exclude index, sourcetype, source, earliest, latest which are handled separately
        exclude_fields = {"index", "sourcetype", "source", "earliest", "latest", "host"}

        # Match patterns like EventCode=4625, Status="Failed", etc.
        patterns = [
            # field=value (no quotes)
            r'(?<!["\'])\b(\w+)\s*=\s*(\d+)\b(?!["\'])',
            # field="value" (double quotes)
            r'\b(\w+)\s*=\s*"([^"]*)"',
            # field='value' (single quotes)
            r"\b(\w+)\s*=\s*'([^']*)'",
            # field!=value
            r'(?<!["\'])\b(\w+)\s*!=\s*"?([^"\s]+)"?\b',
            # field>value, field<value, field>=value, field<=value
            r'(?<!["\'])\b(\w+)\s*([<>]=?)\s*(\d+)\b',
        ]

        # Match field=value patterns
        for pattern in patterns[:3]:
            for match in re.finditer(pattern, base_search):
                field = match.group(1)
                value = match.group(2)
                if field.lower() not in exclude_fields:
                    filters.append({"field": field, "op": "=", "value": value})

        # Match field!=value
        for match in re.finditer(patterns[3], base_search):
            field = match.group(1)
            value = match.group(2)
            if field.lower() not in exclude_fields:
                filters.append({"field": field, "op": "!=", "value": value})

        # Match comparison operators
        for match in re.finditer(patterns[4], base_search):
            field = match.group(1)
            op = match.group(2)
            value = match.group(3)
            if field.lower() not in exclude_fields:
                filters.append({"field": field, "op": op, "value": value})

        return filters

    def _filters_to_sql(self, filters: list[dict[str, str]]) -> str:
        """Convert extracted filters to SQL WHERE conditions."""
        if not filters:
            return ""

        conditions = []
        for f in filters:
            field = f["field"]
            op = f["op"]
            value = f["value"]

            # Check if value is numeric
            if value.isdigit():
                conditions.append(f"{field} {op} {value}")
            else:
                conditions.append(f"{field} {op} '{value}'")

        return " AND ".join(conditions)

    def _generate_threshold_check(
        self, where_conditions: list[str], group_by_fields: list[str]
    ) -> list[str]:
        """Generate Python code for threshold checking from where conditions."""
        lines = []

        if not where_conditions:
            lines.append("        # No threshold conditions found")
            lines.append("        return True")
            return lines

        # Parse common threshold patterns
        # e.g., "distinct_users >= 15 OR attempts >= 20"
        python_conditions = []
        fields_needed = set()

        for cond in where_conditions:
            # Convert SPL comparison to Python
            cond_clean = cond.strip()

            # Skip non-threshold conditions
            if cond_clean.startswith("search filter:"):
                continue

            # Parse the condition
            # Handle OR/AND
            parts = re.split(r"\s+(OR|AND)\s+", cond_clean, flags=re.IGNORECASE)

            for i, part in enumerate(parts):
                part = part.strip()
                if part.upper() in ("OR", "AND"):
                    python_conditions.append(part.lower())
                    continue

                # Parse field >= value, field > value, field=value, etc.
                match = re.match(r"(\w+)\s*([><=!]+)\s*(\d+)", part)
                if match:
                    field = match.group(1)
                    op = match.group(2)
                    value = match.group(3)
                    fields_needed.add(field)
                    # Convert SPL = to Python == for comparison
                    if op == "=":
                        op = "=="
                    elif op == "!=":
                        op = "!="  # Already correct
                    python_conditions.append(f"{field} {op} {value}")
                elif part:
                    # Add as comment if we can't parse it
                    lines.append(f"        # TODO: {part}")

        # Generate field extraction code
        for field in fields_needed:
            lines.append(f'        {field} = deep_get(event, "{field}", 0)')

        lines.append("")

        if python_conditions:
            # Build the return statement
            condition_str = " ".join(python_conditions)
            lines.append(f"        return {condition_str}")
        else:
            lines.append("        return True  # TODO: Set appropriate threshold")

        return lines

    def _generate_test_code(self, class_name: str, log_type: str) -> str:
        """Generate test code for the rule."""
        return f'''
# Test cases for {class_name}

from {class_name.lower()} import {class_name}

def test_{class_name.lower()}_detection():
    """Test that the rule detects malicious activity."""
    rule = {class_name}()

    # TODO: Add test event that should trigger the rule
    malicious_event = {{
        "p_log_type": "{log_type}",
        # Add fields that trigger the detection
    }}

    assert rule.rule(malicious_event) == True

def test_{class_name.lower()}_benign():
    """Test that the rule does not trigger on benign activity."""
    rule = {class_name}()

    # TODO: Add test event that should NOT trigger the rule
    benign_event = {{
        "p_log_type": "{log_type}",
        # Add benign fields
    }}

    assert rule.rule(benign_event) == False
'''
