"""IBM QRadar AQL (Ariel Query Language) converter.

Converts AQL queries to:
- Python/Panther detection rules
- Standard SQL

AQL is a SQL-like query language used by IBM QRadar SIEM for searching
security events and flows. Key features include:
- SQL-like syntax (SELECT, FROM, WHERE, GROUP BY, ORDER BY, HAVING)
- QRadar-specific functions (LOGSOURCENAME, INCIDR, DATEFORMAT, etc.)
- Time range syntax (START, STOP, LAST X MINUTES/HOURS/DAYS)
- Reference set functions (INREFERENCESET, NOTINREFERENCESET)
- Network functions (INCIDR, ASIP, HOSTNAME, etc.)
"""

import re
from dataclasses import dataclass, field
from enum import StrEnum


class AQLTargetFormat(StrEnum):
    """Target output format for AQL conversion."""

    PYTHON = "python"
    SQL = "sql"


@dataclass
class AQLParseResult:
    """Result of parsing an AQL query."""

    select_fields: list[str] = field(default_factory=list)
    from_table: str = ""
    where_conditions: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)
    having: str = ""
    time_range: str = ""
    start_time: str = ""
    stop_time: str = ""
    limit: int | None = None
    aggregations: list[dict[str, str]] = field(default_factory=list)
    is_aggregation_query: bool = False
    reference_sets: list[str] = field(default_factory=list)
    qradar_functions: list[str] = field(default_factory=list)


@dataclass
class AQLConversionResult:
    """Result of AQL conversion."""

    source_code: str
    rule_id: str
    class_name: str
    log_types: list[str]
    severity: str
    todos: list[str]
    target_format: AQLTargetFormat
    is_aggregation_rule: bool = False
    original_aql: str = ""
    parse_details: AQLParseResult | None = None


# QRadar event categories mapped to Panther log types
QRADAR_LOG_TYPE_MAPPING = {
    # Events table
    "events": "QRadar.Events",
    "flows": "QRadar.Flows",
    # Common log source types
    "linux": "Linux.Syslog",
    "windows": "Windows.EventLog",
    "firewall": "PaloAlto.Traffic",
    "ids": "Snort.Alert",
    "ips": "Snort.Alert",
    "authentication": "LDAP.Authentication",
    "database": "MySQL.AuditLog",
    "web": "Apache.AccessLog",
    "dns": "DNS.Query",
    "dhcp": "DHCP.Lease",
    "vpn": "VPN.Connection",
    "endpoint": "CrowdStrike.FDREvent",
    "cloud": "AWS.CloudTrail",
    "aws": "AWS.CloudTrail",
    "azure": "Azure.AuditLog",
    "gcp": "GCP.AuditLog",
    "o365": "Microsoft.365.Audit",
    "okta": "Okta.SystemLog",
}

# QRadar functions and their SQL equivalents
QRADAR_FUNCTION_TO_SQL = {
    # String functions
    "STRLEN": "LENGTH",
    "UPPER": "UPPER",
    "LOWER": "LOWER",
    "TRIM": "TRIM",
    "LTRIM": "LTRIM",
    "RTRIM": "RTRIM",
    "SUBSTRING": "SUBSTRING",
    "CONCAT": "CONCAT",
    "REPLACE": "REPLACE",
    # Numeric functions
    "ABS": "ABS",
    "CEILING": "CEILING",
    "FLOOR": "FLOOR",
    "ROUND": "ROUND",
    "POWER": "POWER",
    "MOD": "MOD",
    # Date functions
    "NOW": "CURRENT_TIMESTAMP",
    "DATEFORMAT": "DATE_FORMAT",
    # Aggregation functions
    "COUNT": "COUNT",
    "SUM": "SUM",
    "AVG": "AVG",
    "MIN": "MIN",
    "MAX": "MAX",
    "FIRST": "FIRST_VALUE",
    "LAST": "LAST_VALUE",
    "UNIQUECOUNT": "COUNT(DISTINCT",
}

# QRadar-specific functions that need special handling
QRADAR_SPECIFIC_FUNCTIONS = {
    "LOGSOURCENAME": "log_source_name",
    "LOGSOURCEGROUPNAME": "log_source_group",
    "LOGSOURCETYPENAME": "log_source_type",
    "CATEGORYNAME": "category_name",
    "QIDNAME": "qid_name",
    "PROTOCOLNAME": "protocol_name",
    "INCIDR": "ip_in_cidr",
    "INREFERENCESET": "in_reference_set",
    "NOTINREFERENCESET": "not_in_reference_set",
    "ASIP": "parse_ip",
    "ASNUMBER": "parse_number",
    "HOSTNAME": "get_hostname",
    "DOMAINNAME": "get_domain",
    "UTF8": "decode_utf8",
    "HEX": "encode_hex",
    "BASE64": "decode_base64",
    "NETWORKNAME": "network_name",
    "APPLICATIONNAME": "application_name",
    "RULELNAME": "rule_name",
}

# QRadar category ID to human-readable name mapping
QRADAR_CATEGORY_MAPPING = {
    # High Level Categories
    1001: "Reconnaissance",
    2001: "DoS",
    3001: "Authentication",
    4001: "Access",
    5001: "Exploit",
    6001: "Malware",
    7001: "Suspicious Activity",
    8001: "System",
    9001: "Application",
    10001: "Audit",
    11001: "Risk Manager",
    12001: "Risk",
    13001: "VIS Host Discovery",
    14001: "SIM Audit",
    15001: "Policy",
    16001: "Control",
    17001: "Asset Profiler",
    18001: "Potential Exploit",
    # Common Low Level Categories
    3002: "Brute Force",
    3003: "Privilege Escalation",
    3004: "General Authentication",
    4002: "ACL Allow",
    4003: "ACL Deny",
    4004: "Firewall Session Open",
    4005: "Firewall Session Close",
    5002: "Buffer Overflow",
    5003: "SQL Injection",
    5004: "XSS",
    6002: "Virus",
    6003: "Trojan",
    6004: "Worm",
    6005: "Spyware",
    6006: "Ransomware",
    7002: "Port Scan",
    7003: "Network Scan",
    7004: "Suspicious Traffic",
    7005: "Data Exfiltration",
    8002: "Startup/Shutdown",
    8003: "Configuration Change",
    9002: "App Error",
    9003: "App Warning",
}

# QRadar protocol number to name mapping
QRADAR_PROTOCOL_MAPPING = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


class AQLConverter:
    """Converts IBM QRadar AQL queries to Python/Panther or SQL."""

    def __init__(self):
        self._aggregation_functions = {
            "COUNT",
            "SUM",
            "AVG",
            "MIN",
            "MAX",
            "UNIQUECOUNT",
            "FIRST",
            "LAST",
        }

    def parse(self, aql: str) -> AQLParseResult:
        """Parse an AQL query into components."""
        result = AQLParseResult()

        # Normalize whitespace
        aql = " ".join(aql.split())

        # Extract SELECT fields
        select_match = re.search(r"SELECT\s+(.+?)\s+FROM", aql, re.IGNORECASE)
        if select_match:
            fields_str = select_match.group(1)
            result.select_fields = self._parse_select_fields(fields_str)

            # Check for aggregation functions
            for func in self._aggregation_functions:
                if func in fields_str.upper():
                    result.is_aggregation_query = True
                    result.aggregations.append({"function": func, "raw": fields_str})

        # Extract FROM table
        from_match = re.search(r"FROM\s+(\w+)", aql, re.IGNORECASE)
        if from_match:
            result.from_table = from_match.group(1).lower()

        # Extract WHERE conditions
        where_match = re.search(
            r"WHERE\s+(.+?)(?:GROUP BY|ORDER BY|HAVING|LIMIT|START|STOP|LAST|$)", aql, re.IGNORECASE
        )
        if where_match:
            where_str = where_match.group(1).strip()
            result.where_conditions = self._parse_where_conditions(where_str)

            # Check for QRadar-specific functions
            for func in QRADAR_SPECIFIC_FUNCTIONS:
                if func in where_str.upper():
                    result.qradar_functions.append(func)

            # Check for reference sets
            ref_matches = re.findall(
                r'(?:IN|NOT\s*IN)REFERENCESET\s*\(\s*[\'"]([^\'"]+)[\'"]', where_str, re.IGNORECASE
            )
            result.reference_sets.extend(ref_matches)

        # Extract GROUP BY
        group_match = re.search(
            r"GROUP BY\s+(.+?)(?:ORDER BY|HAVING|LIMIT|START|STOP|LAST|$)", aql, re.IGNORECASE
        )
        if group_match:
            result.group_by = [f.strip() for f in group_match.group(1).split(",")]
            result.is_aggregation_query = True

        # Extract ORDER BY
        order_match = re.search(
            r"ORDER BY\s+(.+?)(?:HAVING|LIMIT|START|STOP|LAST|$)", aql, re.IGNORECASE
        )
        if order_match:
            result.order_by = [f.strip() for f in order_match.group(1).split(",")]

        # Extract HAVING
        having_match = re.search(r"HAVING\s+(.+?)(?:LIMIT|START|STOP|LAST|$)", aql, re.IGNORECASE)
        if having_match:
            result.having = having_match.group(1).strip()

        # Extract LIMIT
        limit_match = re.search(r"LIMIT\s+(\d+)", aql, re.IGNORECASE)
        if limit_match:
            result.limit = int(limit_match.group(1))

        # Extract time range (LAST X MINUTES/HOURS/DAYS)
        last_match = re.search(r"LAST\s+(\d+)\s+(MINUTE|HOUR|DAY|WEEK|MONTH)S?", aql, re.IGNORECASE)
        if last_match:
            result.time_range = f"LAST {last_match.group(1)} {last_match.group(2).upper()}S"

        # Extract START/STOP times
        start_match = re.search(r'START\s+[\'"]?([^\'"]+)[\'"]?', aql, re.IGNORECASE)
        if start_match:
            result.start_time = start_match.group(1).strip()

        stop_match = re.search(r'STOP\s+[\'"]?([^\'"]+)[\'"]?', aql, re.IGNORECASE)
        if stop_match:
            result.stop_time = stop_match.group(1).strip()

        return result

    def _parse_select_fields(self, fields_str: str) -> list[str]:
        """Parse SELECT field list handling functions and aliases."""
        fields = []
        depth = 0
        current = ""

        for char in fields_str:
            if char == "(":
                depth += 1
                current += char
            elif char == ")":
                depth -= 1
                current += char
            elif char == "," and depth == 0:
                if current.strip():
                    fields.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            fields.append(current.strip())

        return fields

    def _parse_where_conditions(self, where_str: str) -> list[str]:
        """Parse WHERE conditions into individual conditions."""
        conditions = []
        # Split on AND/OR while preserving them
        parts = re.split(r"\s+(AND|OR)\s+", where_str, flags=re.IGNORECASE)

        for i, part in enumerate(parts):
            part = part.strip()
            if part.upper() in ("AND", "OR"):
                if conditions:
                    conditions[-1] = conditions[-1] + f" {part.upper()}"
            elif part:
                conditions.append(part)

        return conditions

    def convert(
        self,
        aql: str,
        rule_id: str,
        class_name: str | None = None,
        severity: str | None = None,
        target_format: AQLTargetFormat = AQLTargetFormat.PYTHON,
    ) -> AQLConversionResult:
        """Convert AQL to target format (Python/Panther or SQL)."""
        parse_result = self.parse(aql)

        if target_format == AQLTargetFormat.SQL:
            return self._convert_to_sql(aql, rule_id, class_name, severity, parse_result)
        else:
            return self._convert_to_python(aql, rule_id, class_name, severity, parse_result)

    def _convert_to_python(
        self,
        aql: str,
        rule_id: str,
        class_name: str | None,
        severity: str | None,
        parse_result: AQLParseResult,
    ) -> AQLConversionResult:
        """Convert AQL to Python/Panther detection rule."""
        todos = []

        # Generate class name if not provided
        if not class_name:
            class_name = self._generate_class_name(rule_id)

        # Determine log types
        log_types = self._infer_log_types(parse_result)

        # Generate Python code
        code_lines = [
            '"""Detection rule converted from QRadar AQL.',
            "",
            "Original AQL:",
            f"{aql}",
            '"""',
            "from panther_sdk import detection, PantherEvent",
            "",
            "",
        ]

        # Add helper functions for QRadar-specific functions
        if parse_result.qradar_functions:
            code_lines.extend(self._generate_helper_functions(parse_result.qradar_functions))

        # Generate the rule class
        if parse_result.is_aggregation_query:
            code_lines.extend(
                self._generate_scheduled_rule(
                    class_name, rule_id, severity or "Medium", log_types, parse_result, todos
                )
            )
        else:
            code_lines.extend(
                self._generate_streaming_rule(
                    class_name, rule_id, severity or "Medium", log_types, parse_result, todos
                )
            )

        # Add reference set handling TODOs
        if parse_result.reference_sets:
            for ref_set in parse_result.reference_sets:
                todos.append(
                    f"TODO: Implement reference set lookup for '{ref_set}' "
                    "- consider using a Panther lookup table"
                )

        # Add QRadar function TODOs
        for func in parse_result.qradar_functions:
            if func in (
                "LOGSOURCENAME",
                "LOGSOURCEGROUPNAME",
                "LOGSOURCETYPENAME",
                "QIDNAME",
                "CATEGORYNAME",
            ):
                todos.append(f"TODO: {func} is QRadar-specific - map to appropriate log field")

        return AQLConversionResult(
            source_code="\n".join(code_lines),
            rule_id=rule_id,
            class_name=class_name,
            log_types=log_types,
            severity=severity or "Medium",
            todos=todos,
            target_format=AQLTargetFormat.PYTHON,
            is_aggregation_rule=parse_result.is_aggregation_query,
            original_aql=aql,
            parse_details=parse_result,
        )

    def _convert_to_sql(
        self,
        aql: str,
        rule_id: str,
        class_name: str | None,
        severity: str | None,
        parse_result: AQLParseResult,
    ) -> AQLConversionResult:
        """Convert AQL to standard SQL."""
        todos = []
        sql_lines = []

        # Build SELECT clause
        select_fields = []
        for field_name in parse_result.select_fields:
            converted = self._convert_field_to_sql(field_name)
            select_fields.append(converted)

        if select_fields:
            sql_lines.append(f"SELECT {', '.join(select_fields)}")
        else:
            sql_lines.append("SELECT *")

        # Build FROM clause
        table_name = self._convert_table_to_sql(parse_result.from_table)
        sql_lines.append(f"FROM {table_name}")

        # Build WHERE clause
        if parse_result.where_conditions:
            where_parts = []
            for condition in parse_result.where_conditions:
                converted = self._convert_condition_to_sql(condition, todos)
                where_parts.append(converted)
            sql_lines.append(f"WHERE {' '.join(where_parts)}")

        # Build GROUP BY clause
        if parse_result.group_by:
            sql_lines.append(f"GROUP BY {', '.join(parse_result.group_by)}")

        # Build HAVING clause
        if parse_result.having:
            sql_lines.append(f"HAVING {parse_result.having}")

        # Build ORDER BY clause
        if parse_result.order_by:
            sql_lines.append(f"ORDER BY {', '.join(parse_result.order_by)}")

        # Build LIMIT clause
        if parse_result.limit:
            sql_lines.append(f"LIMIT {parse_result.limit}")

        # Add time range as comment
        if parse_result.time_range or parse_result.start_time:
            time_comment = "-- Time range: "
            if parse_result.time_range:
                time_comment += parse_result.time_range
            elif parse_result.start_time:
                time_comment += f"FROM {parse_result.start_time}"
                if parse_result.stop_time:
                    time_comment += f" TO {parse_result.stop_time}"
            sql_lines.insert(0, time_comment)

        # Add header comment
        sql_lines.insert(0, "-- Converted from QRadar AQL")
        sql_lines.insert(1, f"-- Original: {aql}")
        sql_lines.insert(2, "")

        return AQLConversionResult(
            source_code="\n".join(sql_lines),
            rule_id=rule_id,
            class_name=class_name or self._generate_class_name(rule_id),
            log_types=self._infer_log_types(parse_result),
            severity=severity or "Medium",
            todos=todos,
            target_format=AQLTargetFormat.SQL,
            is_aggregation_rule=parse_result.is_aggregation_query,
            original_aql=aql,
            parse_details=parse_result,
        )

    def _convert_field_to_sql(self, field: str) -> str:
        """Convert a QRadar field/function to SQL equivalent."""
        result = field

        # Convert QRadar functions to SQL
        for qradar_func, sql_func in QRADAR_FUNCTION_TO_SQL.items():
            pattern = rf"\b{qradar_func}\s*\("
            if re.search(pattern, result, re.IGNORECASE):
                result = re.sub(pattern, f"{sql_func}(", result, flags=re.IGNORECASE)

        # Handle UNIQUECOUNT -> COUNT(DISTINCT ...)
        uniquecount_match = re.search(r"COUNT\(DISTINCT\s*\(([^)]+)\)", result, re.IGNORECASE)
        if uniquecount_match:
            result = re.sub(
                r"COUNT\(DISTINCT\s*\(([^)]+)\)\)",
                r"COUNT(DISTINCT \1)",
                result,
                flags=re.IGNORECASE,
            )

        return result

    def _convert_table_to_sql(self, table: str) -> str:
        """Convert QRadar table name to SQL table name."""
        # QRadar uses 'events' and 'flows' as main tables
        table_mapping = {
            "events": "security_events",
            "flows": "network_flows",
        }
        return table_mapping.get(table.lower(), table)

    def _convert_condition_to_sql(self, condition: str, todos: list[str]) -> str:
        """Convert a QRadar WHERE condition to SQL."""
        result = condition

        # Handle INCIDR function
        incidr_match = re.search(
            r"INCIDR\s*\(\s*['\"]?([^'\"]+)['\"]?\s*,\s*(\w+)\s*\)", result, re.IGNORECASE
        )
        if incidr_match:
            cidr = incidr_match.group(1)
            field = incidr_match.group(2)
            # Convert to standard SQL CIDR check (PostgreSQL style)
            result = re.sub(
                r"INCIDR\s*\([^)]+\)",
                f"{field}::inet <<= '{cidr}'::inet",
                result,
                flags=re.IGNORECASE,
            )
            todos.append(
                "TODO: INCIDR converted to PostgreSQL inet syntax - adjust for your database"
            )

        # Handle INREFERENCESET
        refset_match = re.search(
            r"INREFERENCESET\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)\s*\)", result, re.IGNORECASE
        )
        if refset_match:
            refset_name = refset_match.group(1)
            field = refset_match.group(2)
            result = re.sub(
                r"INREFERENCESET\s*\([^)]+\)",
                f"{field} IN (SELECT value FROM "
                f"reference_set_{refset_name.replace(' ', '_').lower()})",
                result,
                flags=re.IGNORECASE,
            )
            todos.append(
                "TODO: Create reference table "
                f"'reference_set_{refset_name.replace(' ', '_').lower()}' "
                "for reference set lookup"
            )

        # Handle NOTINREFERENCESET
        notrefset_match = re.search(
            r"NOTINREFERENCESET\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)\s*\)", result, re.IGNORECASE
        )
        if notrefset_match:
            refset_name = notrefset_match.group(1)
            field = notrefset_match.group(2)
            result = re.sub(
                r"NOTINREFERENCESET\s*\([^)]+\)",
                f"{field} NOT IN (SELECT value FROM "
                f"reference_set_{refset_name.replace(' ', '_').lower()})",
                result,
                flags=re.IGNORECASE,
            )
            todos.append(
                "TODO: Create reference table "
                f"'reference_set_{refset_name.replace(' ', '_').lower()}' "
                "for reference set lookup"
            )

        # Handle LOGSOURCENAME and similar
        for func, replacement in QRADAR_SPECIFIC_FUNCTIONS.items():
            pattern = rf"\b{func}\s*\(\s*(\w+)\s*\)"
            if re.search(pattern, result, re.IGNORECASE):
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                todos.append(f"TODO: {func} converted to '{replacement}' - verify field mapping")

        return result

    def _generate_class_name(self, rule_id: str) -> str:
        """Generate a Python class name from rule ID."""
        # Remove non-alphanumeric characters and convert to PascalCase
        words = re.split(r"[^a-zA-Z0-9]+", rule_id)
        return "".join(word.capitalize() for word in words if word)

    def _infer_log_types(self, parse_result: AQLParseResult) -> list[str]:
        """Infer Panther log types from parsed AQL."""
        log_types = []

        # Check FROM table
        if parse_result.from_table:
            table = parse_result.from_table.lower()
            if table in QRADAR_LOG_TYPE_MAPPING:
                log_types.append(QRADAR_LOG_TYPE_MAPPING[table])

        # Check WHERE conditions for log source hints
        for condition in parse_result.where_conditions:
            condition_lower = condition.lower()
            for keyword, log_type in QRADAR_LOG_TYPE_MAPPING.items():
                if keyword in condition_lower and log_type not in log_types:
                    log_types.append(log_type)

        if not log_types:
            log_types = ["Custom.QRadarEvents"]

        return log_types

    def _generate_helper_functions(self, functions: list[str]) -> list[str]:
        """Generate helper functions for QRadar-specific operations."""
        lines = []

        if "INCIDR" in functions:
            lines.extend(
                [
                    "import ipaddress",
                    "",
                    "",
                    "def ip_in_cidr(ip: str, cidr: str) -> bool:",
                    '    """Check if IP address is in CIDR range (QRadar INCIDR equivalent).',
                    "    ",
                    "    Args:",
                    "        ip: IP address to check (IPv4 or IPv6)",
                    '        cidr: CIDR notation network (e.g., "192.168.1.0/24")',
                    "    ",
                    "    Returns:",
                    "        True if IP is in the CIDR range, False otherwise",
                    '    """',
                    "    if not ip or not cidr:",
                    "        return False",
                    "    try:",
                    "        # Handle both IPv4 and IPv6",
                    "        ip_obj = ipaddress.ip_address(ip.strip())",
                    "        network = ipaddress.ip_network(cidr.strip(), strict=False)",
                    "        return ip_obj in network",
                    "    except (ValueError, TypeError):",
                    "        # Invalid IP or CIDR format",
                    "        return False",
                    "",
                    "",
                    "def ip_in_cidrs(ip: str, cidrs: list) -> bool:",
                    '    """Check if IP address is in any of multiple CIDR ranges."""',
                    "    return any(ip_in_cidr(ip, cidr) for cidr in cidrs)",
                    "",
                    "",
                ]
            )

        if "INREFERENCESET" in functions or "NOTINREFERENCESET" in functions:
            lines.extend(
                [
                    "# Reference set implementation using Panther lookup tables",
                    "# To use: Create a Panther Lookup Table with the same name "
                    "as the QRadar reference set",
                    "",
                    "# Lookup table cache for performance",
                    "_reference_set_cache = {}",
                    "",
                    "",
                    "def get_reference_set(set_name: str) -> set:",
                    '    """Get or load a reference set as a Panther lookup table.',
                    "    ",
                    "    In Panther, create a Lookup Table with columns: "
                    "value, description, added_date",
                    "    The lookup table name should match the QRadar reference set name.",
                    '    """',
                    "    global _reference_set_cache",
                    "    ",
                    "    if set_name not in _reference_set_cache:",
                    "        try:",
                    "            # Import Panther lookup table at runtime",
                    "            from panther_sdk import lookup_table",
                    "            lt = lookup_table(set_name)",
                    "            # Load all values into a set for O(1) lookup",
                    "            _reference_set_cache[set_name] = set(lt.keys()) if lt else set()",
                    "        except ImportError:",
                    "            # Fallback: read from JSON file if Panther SDK not available",
                    "            import json",
                    "            import os",
                    '            ref_path = os.environ.get("REFERENCE_SETS_PATH", '
                    '"/var/reference_sets")',
                    "            try:",
                    '                with open(f"{ref_path}/{set_name}.json") as f:',
                    "                    data = json.load(f)",
                    "                    _reference_set_cache[set_name] = "
                    'set(data.get("values", []))',
                    "            except (FileNotFoundError, json.JSONDecodeError):",
                    "                _reference_set_cache[set_name] = set()",
                    "    ",
                    "    return _reference_set_cache.get(set_name, set())",
                    "",
                    "",
                    "def in_reference_set(set_name: str, value: str) -> bool:",
                    '    """Check if value is in reference set '
                    '(QRadar INREFERENCESET equivalent)."""',
                    "    if value is None:",
                    "        return False",
                    "    return str(value).lower() in "
                    "{v.lower() for v in get_reference_set(set_name)}",
                    "",
                    "",
                    "def not_in_reference_set(set_name: str, value: str) -> bool:",
                    '    """Check if value is NOT in reference set '
                    '(QRadar NOTINREFERENCESET equivalent)."""',
                    "    if value is None:",
                    "        return True",
                    "    return str(value).lower() not in "
                    "{v.lower() for v in get_reference_set(set_name)}",
                    "",
                    "",
                ]
            )

        if "PROTOCOLNAME" in functions:
            lines.extend(
                [
                    "# Protocol number to name mapping (QRadar PROTOCOLNAME equivalent)",
                    "PROTOCOL_MAP = {",
                    '    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",',
                    '    51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",',
                    "}",
                    "",
                    "",
                    "def get_protocol_name(protocol_number) -> str:",
                    '    """Convert protocol number to name (QRadar PROTOCOLNAME equivalent)."""',
                    "    try:",
                    "        return PROTOCOL_MAP.get(int(protocol_number), "
                    'f"PROTOCOL_{protocol_number}")',
                    "    except (ValueError, TypeError):",
                    "        return str(protocol_number)",
                    "",
                    "",
                ]
            )

        if "CATEGORYNAME" in functions or "QIDNAME" in functions:
            lines.extend(
                [
                    "# QRadar category ID to name mapping (subset - add more as needed)",
                    "CATEGORY_MAP = {",
                    '    1001: "Reconnaissance", 2001: "DoS", 3001: "Authentication",',
                    '    3002: "Brute Force", 3003: "Privilege Escalation",',
                    '    4001: "Access", 4002: "ACL Allow", 4003: "ACL Deny",',
                    '    5001: "Exploit", 5002: "Buffer Overflow", 5003: "SQL Injection",',
                    '    6001: "Malware", 6002: "Virus", 6003: "Trojan", 6006: "Ransomware",',
                    '    7001: "Suspicious Activity", 7002: "Port Scan", '
                    '7005: "Data Exfiltration",',
                    '    8001: "System", 8003: "Configuration Change",',
                    "}",
                    "",
                    "",
                    "def get_category_name(category_id) -> str:",
                    '    """Convert QRadar category ID to name (CATEGORYNAME equivalent)."""',
                    "    try:",
                    '        return CATEGORY_MAP.get(int(category_id), f"CATEGORY_{category_id}")',
                    "    except (ValueError, TypeError):",
                    "        return str(category_id)",
                    "",
                    "",
                    "def get_qid_name(qid) -> str:",
                    '    """Get QID name - requires mapping file or lookup table.',
                    "    ",
                    "    QIDs are QRadar-specific event identifiers. Map these to your",
                    "    log source event types for accurate detection.",
                    '    """',
                    "    # TODO: Implement QID lookup from mapping file or table",
                    '    return f"QID_{qid}"',
                    "",
                    "",
                ]
            )

        return lines

    def _generate_streaming_rule(
        self,
        class_name: str,
        rule_id: str,
        severity: str,
        log_types: list[str],
        parse_result: AQLParseResult,
        todos: list[str],
    ) -> list[str]:
        """Generate a streaming Panther rule."""
        lines = [
            "@detection.rule(",
            f'    rule_id="{rule_id}",',
            f"    log_types={log_types},",
            "    severity=detection.SeverityInfo"
            if severity.lower() == "info"
            else "    severity=detection.SeverityLow"
            if severity.lower() == "low"
            else "    severity=detection.SeverityMedium"
            if severity.lower() == "medium"
            else "    severity=detection.SeverityHigh"
            if severity.lower() == "high"
            else "    severity=detection.SeverityCritical",
            ")",
            f"class {class_name}(detection.Rule):",
            '    """Detection rule converted from QRadar AQL."""',
            "",
            "    def rule(self, event: PantherEvent) -> bool:",
            '        """',
            "        Original AQL WHERE conditions:",
        ]

        for condition in parse_result.where_conditions:
            lines.append(f"        - {condition}")

        lines.extend(
            [
                '        """',
                "        # TODO: Implement detection logic based on AQL conditions",
            ]
        )

        # Generate condition checks
        for i, condition in enumerate(parse_result.where_conditions):
            python_condition = self._condition_to_python(condition, todos)
            if i == 0:
                lines.append(f"        if not ({python_condition}):")
                lines.append("            return False")
            else:
                # Handle AND/OR
                if condition.rstrip().upper().endswith("AND"):
                    lines.append(f"        if not ({python_condition.rstrip()[:-3]}):")
                    lines.append("            return False")
                elif condition.rstrip().upper().endswith("OR"):
                    lines.append("        # OR condition - adjust logic as needed")
                    lines.append(f"        # {python_condition}")
                else:
                    lines.append(f"        if not ({python_condition}):")
                    lines.append("            return False")

        lines.extend(
            [
                "",
                "        return True",
                "",
                "    def title(self, event: PantherEvent) -> str:",
                '        """Generate alert title."""',
                f'        return f"{class_name} triggered"',
                "",
            ]
        )

        return lines

    def _generate_scheduled_rule(
        self,
        class_name: str,
        rule_id: str,
        severity: str,
        log_types: list[str],
        parse_result: AQLParseResult,
        todos: list[str],
    ) -> list[str]:
        """Generate a scheduled Panther rule for aggregation queries."""
        todos.append(
            "TODO: This is an aggregation query - implement as a Scheduled Rule in Panther"
        )

        lines = [
            "# NOTE: This AQL query uses aggregation and should be implemented as a Scheduled Rule",
            "# See: https://docs.panther.com/detections/scheduled-rules",
            "",
            "@detection.rule(",
            f'    rule_id="{rule_id}",',
            f"    log_types={log_types},",
            "    severity=detection.SeverityInfo"
            if severity.lower() == "info"
            else "    severity=detection.SeverityLow"
            if severity.lower() == "low"
            else "    severity=detection.SeverityMedium"
            if severity.lower() == "medium"
            else "    severity=detection.SeverityHigh"
            if severity.lower() == "high"
            else "    severity=detection.SeverityCritical",
            ")",
            f"class {class_name}(detection.Rule):",
            '    """',
            "    Aggregation-based detection rule converted from QRadar AQL.",
            "    ",
            "    Original aggregations:",
        ]

        for agg in parse_result.aggregations:
            lines.append(f"    - {agg['function']}: {agg.get('raw', '')}")

        if parse_result.group_by:
            lines.append("    ")
            lines.append(f"    Group by: {', '.join(parse_result.group_by)}")

        lines.extend(
            [
                '    """',
                "",
                "    def rule(self, event: PantherEvent) -> bool:",
                '        """Streaming component - filter events for scheduled aggregation."""',
            ]
        )

        # Add basic filtering
        for condition in parse_result.where_conditions:
            if not any(agg in condition.upper() for agg in self._aggregation_functions):
                python_condition = self._condition_to_python(condition, todos)
                lines.append(f"        if not ({python_condition}):")
                lines.append("            return False")

        lines.extend(
            [
                "        return True",
                "",
                "    def title(self, event: PantherEvent) -> str:",
                '        """Generate alert title."""',
                f'        return f"{class_name} - Aggregation Alert"',
                "",
                "    # Scheduled query SQL (for reference):",
                '    # """',
            ]
        )

        # Add SQL equivalent
        sql_result = self._convert_to_sql("", rule_id, class_name, severity, parse_result)
        for sql_line in sql_result.source_code.split("\n"):
            lines.append(f"    # {sql_line}")

        lines.append('    # """')

        return lines

    def _condition_to_python(self, condition: str, todos: list[str]) -> str:
        """Convert a single AQL condition to Python."""
        result = condition

        # Remove trailing AND/OR
        result = re.sub(r"\s+(AND|OR)\s*$", "", result, flags=re.IGNORECASE)

        # Handle common patterns
        # field = 'value' -> event.get('field') == 'value'
        eq_match = re.match(r"(\w+)\s*=\s*'([^']*)'", result)
        if eq_match:
            field, value = eq_match.groups()
            return f"event.get('{field}') == '{value}'"

        # field = number -> event.get('field') == number
        eq_num_match = re.match(r"(\w+)\s*=\s*(\d+)", result)
        if eq_num_match:
            field, value = eq_num_match.groups()
            return f"event.get('{field}') == {value}"

        # field != 'value' -> event.get('field') != 'value'
        neq_match = re.match(r"(\w+)\s*!=\s*'([^']*)'", result)
        if neq_match:
            field, value = neq_match.groups()
            return f"event.get('{field}') != '{value}'"

        # field > number -> event.get('field', 0) > number
        gt_match = re.match(r"(\w+)\s*>\s*(\d+)", result)
        if gt_match:
            field, value = gt_match.groups()
            return f"event.get('{field}', 0) > {value}"

        # field < number -> event.get('field', 0) < number
        lt_match = re.match(r"(\w+)\s*<\s*(\d+)", result)
        if lt_match:
            field, value = lt_match.groups()
            return f"event.get('{field}', 0) < {value}"

        # field LIKE '%value%' -> 'value' in event.get('field', '')
        like_match = re.match(r"(\w+)\s+LIKE\s+'%([^%]+)%'", result, re.IGNORECASE)
        if like_match:
            field, value = like_match.groups()
            return f"'{value}' in event.get('{field}', '')"

        # field ILIKE '%value%' -> 'value'.lower() in event.get('field', '').lower()
        ilike_match = re.match(r"(\w+)\s+ILIKE\s+'%([^%]+)%'", result, re.IGNORECASE)
        if ilike_match:
            field, value = ilike_match.groups()
            return f"'{value}'.lower() in event.get('{field}', '').lower()"

        # INCIDR('cidr', field) -> ip_in_cidr(event.get('field'), 'cidr')
        incidr_match = re.search(r"INCIDR\s*\(\s*'([^']+)'\s*,\s*(\w+)\s*\)", result, re.IGNORECASE)
        if incidr_match:
            cidr, field = incidr_match.groups()
            return f"ip_in_cidr(event.get('{field}', ''), '{cidr}')"

        # INREFERENCESET('setname', field)
        refset_match = re.search(
            r"INREFERENCESET\s*\(\s*'([^']+)'\s*,\s*(\w+)\s*\)", result, re.IGNORECASE
        )
        if refset_match:
            setname, field = refset_match.groups()
            todos.append(f"TODO: Create Panther Lookup Table '{setname}' for reference set")
            return f"in_reference_set('{setname}', event.get('{field}', ''))"

        # NOTINREFERENCESET('setname', field)
        notrefset_match = re.search(
            r"NOTINREFERENCESET\s*\(\s*'([^']+)'\s*,\s*(\w+)\s*\)", result, re.IGNORECASE
        )
        if notrefset_match:
            setname, field = notrefset_match.groups()
            todos.append(f"TODO: Create Panther Lookup Table '{setname}' for reference set")
            return f"not_in_reference_set('{setname}', event.get('{field}', ''))"

        # PROTOCOLNAME(protocol) = 'TCP'
        protocolname_match = re.search(
            r"PROTOCOLNAME\s*\(\s*(\w+)\s*\)\s*=\s*'([^']+)'", result, re.IGNORECASE
        )
        if protocolname_match:
            field, expected = protocolname_match.groups()
            return f"get_protocol_name(event.get('{field}')) == '{expected}'"

        # CATEGORYNAME(category) = 'Malware'
        categoryname_match = re.search(
            r"CATEGORYNAME\s*\(\s*(\w+)\s*\)\s*=\s*'([^']+)'", result, re.IGNORECASE
        )
        if categoryname_match:
            field, expected = categoryname_match.groups()
            return f"get_category_name(event.get('{field}')) == '{expected}'"

        # CATEGORYNAME(category) LIKE '%Malware%'
        categoryname_like_match = re.search(
            r"CATEGORYNAME\s*\(\s*(\w+)\s*\)\s+LIKE\s+'%([^%]+)%'", result, re.IGNORECASE
        )
        if categoryname_like_match:
            field, pattern = categoryname_like_match.groups()
            return f"'{pattern}' in get_category_name(event.get('{field}'))"

        # QIDNAME(qid) = 'event_name'
        qidname_match = re.search(
            r"QIDNAME\s*\(\s*(\w+)\s*\)\s*=\s*'([^']+)'", result, re.IGNORECASE
        )
        if qidname_match:
            field, expected = qidname_match.groups()
            todos.append(f"TODO: Map QID to your log source event type for '{expected}'")
            return f"get_qid_name(event.get('{field}')) == '{expected}'"

        # category = 6001 (numeric category check)
        category_num_match = re.match(r"category\s*=\s*(\d+)", result, re.IGNORECASE)
        if category_num_match:
            cat_id = int(category_num_match.group(1))
            if cat_id in QRADAR_CATEGORY_MAPPING:
                cat_name = QRADAR_CATEGORY_MAPPING[cat_id]
                return f"event.get('category') == {cat_id}  # {cat_name}"
            return f"event.get('category') == {cat_id}"

        # field IS NULL -> event.get('field') is None
        null_match = re.match(r"(\w+)\s+IS\s+NULL", result, re.IGNORECASE)
        if null_match:
            field = null_match.group(1)
            return f"event.get('{field}') is None"

        # field IS NOT NULL -> event.get('field') is not None
        not_null_match = re.match(r"(\w+)\s+IS\s+NOT\s+NULL", result, re.IGNORECASE)
        if not_null_match:
            field = not_null_match.group(1)
            return f"event.get('{field}') is not None"

        # field IN ('a', 'b', 'c') -> event.get('field') in ['a', 'b', 'c']
        in_match = re.match(r"(\w+)\s+IN\s*\(([^)]+)\)", result, re.IGNORECASE)
        if in_match:
            field, values = in_match.groups()
            # Parse values
            value_list = [v.strip().strip("'\"") for v in values.split(",")]
            return f"event.get('{field}') in {value_list}"

        # Default: add as comment with TODO
        todos.append(f"TODO: Convert AQL condition to Python: {condition}")
        return f"True  # TODO: {condition}"


# Singleton instance
aql_converter = AQLConverter()
