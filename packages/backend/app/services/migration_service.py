"""
Migration Service - Universal SIEM Detection Rule Converter

Supports conversion between:
- Sigma (universal intermediate format)
- SPL (Splunk)
- YARA-L (Google SecOps / Chronicle)
- KQL (Microsoft Sentinel)
- EQL (Elastic Security)
- ES|QL (Elastic - new query language)
- Python (Panther)

Architecture: Source → Sigma (intermediate) → Target
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum

import yaml


class SIEMFormat(StrEnum):
    SIGMA = "sigma"
    SPL = "spl"
    YARAL = "yaral"
    AQL = "aql"
    KQL = "kql"
    EQL = "eql"
    ESQL = "esql"
    PANTHER = "panther"
    SQL = "sql"
    CQL = "cql"  # Chronicle Query Language (Google Chronicle / SecOps)


# =============================================================================
# Universal Field Mapping System
# =============================================================================


class FieldMapper:
    """
    Universal field name translation between SIEM platforms.
    Uses a canonical (Sigma-style) representation as the intermediate.
    """

    # Canonical field names -> Platform-specific names
    FIELD_MAPPINGS = {
        # Process fields
        "Image": {
            "spl": "NewProcessName",
            "kql": "NewProcessName",
            "eql": "process.name",
            "esql": "process.name",
            "yaral": "target.process.file.full_path",
            "panther": "process_name",
            "aql": "Application",
            "sql": "process_name",
            "cql": "target.process.file.full_path",
        },
        "CommandLine": {
            "spl": "CommandLine",
            "kql": "CommandLine",
            "eql": "process.command_line",
            "esql": "process.command_line",
            "yaral": "target.process.command_line",
            "panther": "command_line",
            "aql": "Command",
            "sql": "command_line",
            "cql": "target.process.command_line",
        },
        "ParentImage": {
            "spl": "ParentProcessName",
            "kql": "ParentProcessName",
            "eql": "process.parent.name",
            "esql": "process.parent.name",
            "yaral": "principal.process.file.full_path",
            "panther": "parent_process_name",
            "aql": "ParentApplication",
            "sql": "parent_process_name",
            "cql": "principal.process.file.full_path",
        },
        "ParentCommandLine": {
            "spl": "ParentCommandLine",
            "kql": "ParentCommandLine",
            "eql": "process.parent.command_line",
            "esql": "process.parent.command_line",
            "yaral": "principal.process.command_line",
            "panther": "parent_command_line",
            "aql": "ParentCommand",
            "sql": "parent_command_line",
            "cql": "principal.process.command_line",
        },
        "ProcessId": {
            "spl": "ProcessId",
            "kql": "ProcessId",
            "eql": "process.pid",
            "esql": "process.pid",
            "yaral": "target.process.pid",
            "panther": "pid",
            "aql": "pid",
            "sql": "pid",
            "cql": "target.process.pid",
        },
        # User fields
        "User": {
            "spl": "User",
            "kql": "Account",
            "eql": "user.name",
            "esql": "user.name",
            "yaral": "principal.user.userid",
            "panther": "user",
            "aql": "username",
            "sql": "username",
            "cql": "principal.user.userid",
        },
        "UserDomain": {
            "spl": "UserDomain",
            "kql": "AccountDomain",
            "eql": "user.domain",
            "esql": "user.domain",
            "yaral": "principal.user.windows_sid",
            "panther": "user_domain",
            "aql": "AccountDomain",
            "sql": "user_domain",
            "cql": "principal.user.windows_sid",
        },
        # Host fields
        "ComputerName": {
            "spl": "ComputerName",
            "kql": "Computer",
            "eql": "host.name",
            "esql": "host.name",
            "yaral": "principal.hostname",
            "panther": "hostname",
            "aql": "hostname",
            "sql": "hostname",
            "cql": "principal.hostname",
        },
        "HostIP": {
            "spl": "src_ip",
            "kql": "HostIP",
            "eql": "host.ip",
            "esql": "host.ip",
            "yaral": "principal.ip",
            "panther": "host_ip",
            "aql": "localip",
            "sql": "host_ip",
            "cql": "principal.ip",
        },
        # Network fields
        "SourceIP": {
            "spl": "src_ip",
            "kql": "SourceIP",
            "eql": "source.ip",
            "esql": "source.ip",
            "yaral": "principal.ip",
            "panther": "source_ip",
            "aql": "sourceip",
            "sql": "source_ip",
            "cql": "principal.ip",
        },
        "DestinationIP": {
            "spl": "dest_ip",
            "kql": "DestinationIP",
            "eql": "destination.ip",
            "esql": "destination.ip",
            "yaral": "target.ip",
            "panther": "destination_ip",
            "aql": "destinationip",
            "sql": "destination_ip",
            "cql": "target.ip",
        },
        "SourcePort": {
            "spl": "src_port",
            "kql": "SourcePort",
            "eql": "source.port",
            "esql": "source.port",
            "yaral": "principal.port",
            "panther": "source_port",
            "aql": "sourceport",
            "sql": "source_port",
            "cql": "principal.port",
        },
        "DestinationPort": {
            "spl": "dest_port",
            "kql": "DestinationPort",
            "eql": "destination.port",
            "esql": "destination.port",
            "yaral": "target.port",
            "panther": "destination_port",
            "aql": "destinationport",
            "sql": "destination_port",
            "cql": "target.port",
        },
        "Protocol": {
            "spl": "protocol",
            "kql": "Protocol",
            "eql": "network.protocol",
            "esql": "network.protocol",
            "yaral": "network.ip_protocol",
            "panther": "protocol",
            "aql": "protocolid",
            "sql": "protocol",
            "cql": "network.ip_protocol",
        },
        # File fields
        "TargetFilename": {
            "spl": "file_path",
            "kql": "TargetFilename",
            "eql": "file.path",
            "esql": "file.path",
            "yaral": "target.file.full_path",
            "panther": "file_path",
            "aql": "Filename",
            "sql": "file_path",
            "cql": "target.file.full_path",
        },
        "FileHash": {
            "spl": "file_hash",
            "kql": "FileHash",
            "eql": "file.hash.sha256",
            "esql": "file.hash.sha256",
            "yaral": "target.file.sha256",
            "panther": "file_hash",
            "aql": "SHA256Hash",
            "sql": "file_hash",
            "cql": "target.file.sha256",
        },
        # Event metadata
        "EventID": {
            "spl": "EventCode",
            "kql": "EventID",
            "eql": "event.code",
            "esql": "event.code",
            "yaral": "metadata.product_event_type",
            "panther": "event_id",
            "aql": "qid",
            "sql": "event_id",
            "cql": "metadata.product_event_type",
        },
        "EventType": {
            "spl": "EventType",
            "kql": "EventType",
            "eql": "event.type",
            "esql": "event.type",
            "yaral": "metadata.event_type",
            "panther": "event_type",
            "aql": "categoryname",
            "sql": "event_type",
            "cql": "metadata.event_type",
        },
    }

    # Reverse mappings (platform field -> canonical)
    _reverse_mappings: dict[str, dict[str, str]] = {}

    @classmethod
    def _build_reverse_mappings(cls):
        """Build reverse lookup tables."""
        if cls._reverse_mappings:
            return

        for canonical, platform_names in cls.FIELD_MAPPINGS.items():
            for platform, field_name in platform_names.items():
                if platform not in cls._reverse_mappings:
                    cls._reverse_mappings[platform] = {}
                # Store lowercase for case-insensitive lookup
                cls._reverse_mappings[platform][field_name.lower()] = canonical

    @classmethod
    def to_canonical(cls, field: str, source_platform: str) -> str:
        """Convert a platform-specific field to canonical name."""
        cls._build_reverse_mappings()

        platform_map = cls._reverse_mappings.get(source_platform, {})
        canonical = platform_map.get(field.lower())

        if canonical:
            return canonical

        # Try to normalize common patterns
        field_lower = field.lower().replace("_", "").replace(".", "")

        # Common field name variations
        normalizations = {
            "srcip": "SourceIP",
            "sourceip": "SourceIP",
            "sourceaddress": "SourceIP",
            "dstip": "DestinationIP",
            "destip": "DestinationIP",
            "destinationip": "DestinationIP",
            "destinationaddress": "DestinationIP",
            "srcport": "SourcePort",
            "sourceport": "SourcePort",
            "dstport": "DestinationPort",
            "destport": "DestinationPort",
            "destinationport": "DestinationPort",
            "username": "User",
            "userid": "User",
            "user": "User",
            "accountname": "User",
            "hostname": "ComputerName",
            "computername": "ComputerName",
            "hostip": "HostIP",
            "host": "ComputerName",
            "processname": "Image",
            "image": "Image",
            "newprocessname": "Image",
            "executable": "Image",
            "commandline": "CommandLine",
            "cmdline": "CommandLine",
            "command": "CommandLine",
            "parentimage": "ParentImage",
            "parentprocessname": "ParentImage",
            "filepath": "TargetFilename",
            "filename": "TargetFilename",
            "targetfilename": "TargetFilename",
            "eventcode": "EventID",
            "eventid": "EventID",
        }

        if field_lower in normalizations:
            return normalizations[field_lower]

        # Return as-is if no mapping found
        return field

    @classmethod
    def from_canonical(cls, canonical_field: str, target_platform: str) -> str:
        """Convert canonical field name to platform-specific."""
        if canonical_field in cls.FIELD_MAPPINGS:
            return cls.FIELD_MAPPINGS[canonical_field].get(target_platform, canonical_field.lower())

        # Default: convert to snake_case for most platforms
        if target_platform in ["panther", "sql", "aql"]:
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", canonical_field)
            return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
        elif target_platform in ["eql", "esql"]:
            # Use dot notation for Elastic
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1.\2", canonical_field)
            return re.sub("([a-z0-9])([A-Z])", r"\1.\2", s1).lower()
        elif target_platform in ["cql", "yaral"]:
            # Use UDM field paths for Chronicle/CQL
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1.\2", canonical_field)
            s2 = re.sub("([a-z0-9])([A-Z])", r"\1.\2", s1).lower()
            return f"target.{s2}"

        return canonical_field


# =============================================================================
# Time Range Handling
# =============================================================================


@dataclass
class TimeRange:
    """Represents a time range for queries."""

    value: int
    unit: str  # MINUTE, HOUR, DAY, WEEK, MONTH

    def to_spl(self) -> str:
        unit_map = {"MINUTE": "m", "HOUR": "h", "DAY": "d", "WEEK": "w", "MONTH": "mon"}
        return f"earliest=-{self.value}{unit_map.get(self.unit.upper(), 'h')}"

    def to_kql(self) -> str:
        unit_map = {"MINUTE": "m", "HOUR": "h", "DAY": "d", "WEEK": "d", "MONTH": "d"}
        multiplier = {"MINUTE": 1, "HOUR": 1, "DAY": 1, "WEEK": 7, "MONTH": 30}
        val = self.value * multiplier.get(self.unit.upper(), 1)
        return f"ago({val}{unit_map.get(self.unit.upper(), 'h')})"

    def to_aql(self) -> str:
        return f"LAST {self.value} {self.unit.upper()}S"

    def to_sql(self) -> str:
        unit_map = {
            "MINUTE": "MINUTE",
            "HOUR": "HOUR",
            "DAY": "DAY",
            "WEEK": "WEEK",
            "MONTH": "MONTH",
        }
        return (
            f"timestamp >= NOW() - INTERVAL {self.value} {unit_map.get(self.unit.upper(), 'HOUR')}"
        )

    def to_panther(self) -> str:
        unit_map = {
            "MINUTE": "minutes",
            "HOUR": "hours",
            "DAY": "days",
            "WEEK": "weeks",
            "MONTH": "days",
        }
        multiplier = {"MINUTE": 1, "HOUR": 1, "DAY": 1, "WEEK": 7, "MONTH": 30}
        val = self.value * multiplier.get(self.unit.upper(), 1)
        return f"p_occurs_since('{val} {unit_map.get(self.unit.upper(), 'hours')}')"

    def to_cql(self) -> str:
        unit_map = {"MINUTE": "m", "HOUR": "h", "DAY": "d", "WEEK": "d", "MONTH": "d"}
        multiplier = {"MINUTE": 1, "HOUR": 1, "DAY": 1, "WEEK": 7, "MONTH": 30}
        val = self.value * multiplier.get(self.unit.upper(), 1)
        return (
            "| filter timestamp.seconds > timestamp.current_timestamp() - "
            f"{val * 60 if unit_map.get(self.unit.upper()) == 'm' else val * 3600}"
        )


# =============================================================================
# Aggregation Support
# =============================================================================


@dataclass
class Aggregation:
    """Represents an aggregation clause."""

    function: str  # COUNT, SUM, AVG, MIN, MAX, UNIQUECOUNT
    field: str | None = None  # Field to aggregate (None for COUNT(*))
    alias: str | None = None  # AS alias

    def to_spl(self) -> str:
        func_map = {
            "COUNT": "count",
            "SUM": "sum",
            "AVG": "avg",
            "MIN": "min",
            "MAX": "max",
            "UNIQUECOUNT": "dc",
        }
        func = func_map.get(self.function.upper(), self.function.lower())
        if self.field:
            expr = f"{func}({self.field})"
        else:
            expr = f"{func}()" if func == "count" else f"{func}(*)"
        if self.alias:
            expr += f" AS {self.alias}"
        return expr

    def to_kql(self) -> str:
        func_map = {
            "COUNT": "count",
            "SUM": "sum",
            "AVG": "avg",
            "MIN": "min",
            "MAX": "max",
            "UNIQUECOUNT": "dcount",
        }
        func = func_map.get(self.function.upper(), self.function.lower())
        if self.field:
            expr = f"{func}({self.field})"
        else:
            expr = f"{func}()"
        if self.alias:
            expr = f"{self.alias} = {expr}"
        return expr

    def to_sql(self) -> str:
        func_map = {
            "COUNT": "COUNT",
            "SUM": "SUM",
            "AVG": "AVG",
            "MIN": "MIN",
            "MAX": "MAX",
            "UNIQUECOUNT": "COUNT(DISTINCT",
        }
        func = func_map.get(self.function.upper(), self.function.upper())
        if self.function.upper() == "UNIQUECOUNT":
            expr = f"COUNT(DISTINCT {self.field or '*'})"
        elif self.field:
            expr = f"{func}({self.field})"
        else:
            expr = f"{func}(*)"
        if self.alias:
            expr += f" AS {self.alias}"
        return expr

    def to_cql(self) -> str:
        """Convert aggregation to CQL format."""
        func_map = {
            "COUNT": "count",
            "SUM": "sum",
            "AVG": "avg",
            "MIN": "min",
            "MAX": "max",
            "UNIQUECOUNT": "count_distinct",
        }
        func = func_map.get(self.function.upper(), self.function.lower())
        if self.field:
            expr = f"{func}({self.field})"
        else:
            expr = f"{func}()"
        if self.alias:
            expr += f" as {self.alias}"
        return expr


@dataclass
class SigmaRule:
    """Intermediate Sigma representation for conversions."""

    title: str = "Converted Rule"
    status: str = "experimental"
    description: str = ""
    author: str = "Migration Tool"
    logsource: dict = field(
        default_factory=lambda: {"category": "process_creation", "product": "windows"}
    )
    detection: dict = field(default_factory=dict)
    fields: list = field(default_factory=list)
    falsepositives: list = field(default_factory=list)
    level: str = "medium"
    tags: list = field(default_factory=list)
    # Extended attributes for better conversion
    time_range: TimeRange | None = None
    aggregations: list = field(default_factory=list)  # List of Aggregation objects
    group_by: list = field(default_factory=list)  # GROUP BY fields
    having: str | None = None  # HAVING clause condition
    limit: int | None = None  # LIMIT value
    order_by: list = field(default_factory=list)  # ORDER BY fields

    def is_aggregation_query(self) -> bool:
        """Check if this rule uses aggregation."""
        return bool(self.aggregations or self.group_by or self.having)

    def to_yaml(self) -> str:
        """Convert to YAML string."""
        data = {
            "title": self.title,
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "logsource": self.logsource,
            "detection": self.detection,
            "fields": self.fields,
            "falsepositives": self.falsepositives,
            "level": self.level,
            "tags": self.tags,
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "SigmaRule":
        """Parse from YAML string."""
        data = yaml.safe_load(yaml_str)
        return cls(
            title=data.get("title", "Converted Rule"),
            status=data.get("status", "experimental"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            fields=data.get("fields", []),
            falsepositives=data.get("falsepositives", []),
            level=data.get("level", "medium"),
            tags=data.get("tags", []),
        )


# =============================================================================
# Base Converter Classes
# =============================================================================


class ToSigmaConverter(ABC):
    """Base class for converting a SIEM format to Sigma."""

    @abstractmethod
    def convert(self, source: str) -> SigmaRule:
        """Convert source format to Sigma intermediate."""
        pass


class FromSigmaConverter(ABC):
    """Base class for converting Sigma to a SIEM format."""

    @abstractmethod
    def convert(self, sigma: SigmaRule) -> str:
        """Convert Sigma intermediate to target format."""
        pass


# =============================================================================
# SPL (Splunk) Converters
# =============================================================================


class SPLToSigma(ToSigmaConverter):
    """Convert Splunk SPL to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from SPL"

        # Parse index and sourcetype
        re.search(r"index\s*=\s*(\w+)", source, re.IGNORECASE)
        sourcetype_match = re.search(r"sourcetype\s*=\s*([^\s|]+)", source, re.IGNORECASE)

        if sourcetype_match:
            st = sourcetype_match.group(1)
            if "WinEventLog" in st or "windows" in st.lower():
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif "linux" in st.lower():
                sigma.logsource = {"category": "process_creation", "product": "linux"}
            else:
                sigma.logsource = {"category": "generic", "product": st}

        # Extract conditions from where clauses
        detection = {"selection": {}, "condition": "selection"}

        # Parse where clauses
        where_matches = re.findall(r"\|\s*where\s+(.+?)(?=\||$)", source, re.IGNORECASE)
        for i, where_clause in enumerate(where_matches):
            field_match = re.search(
                r'(\w+)\s*(?:like|contains|=|==)\s*["\']?([^"\'|]+)["\']?',
                where_clause,
                re.IGNORECASE,
            )
            if field_match:
                field_name = self._normalize_field(field_match.group(1))
                value = field_match.group(2).strip().strip("%").strip("*")

                if (
                    "like" in where_clause.lower()
                    or "%" in field_match.group(2)
                    or "*" in field_match.group(2)
                ):
                    detection["selection"][f"{field_name}|contains"] = value
                else:
                    detection["selection"][field_name] = value

        # Parse search terms (field=value patterns)
        field_patterns = re.findall(r'(\w+)\s*=\s*["\']?([^"\'\s|]+)["\']?', source)
        for field_name, value in field_patterns:
            if field_name.lower() not in ["index", "sourcetype", "source"]:
                normalized = self._normalize_field(field_name)
                if value.startswith("*") or value.endswith("*"):
                    detection["selection"][f"{normalized}|contains"] = value.strip("*")
                else:
                    detection["selection"][normalized] = value

        sigma.detection = detection

        # Extract fields from table command
        table_match = re.search(r"\|\s*table\s+(.+?)(?=\||$)", source, re.IGNORECASE)
        if table_match:
            sigma.fields = [f.strip() for f in table_match.group(1).split(",")]

        return sigma

    def _normalize_field(self, field: str) -> str:
        """Normalize SPL field names to Sigma."""
        mappings = {
            "newprocessname": "Image",
            "processname": "Image",
            "commandline": "CommandLine",
            "parentprocessname": "ParentImage",
            "user": "User",
            "computername": "ComputerName",
            "eventcode": "EventID",
        }
        return mappings.get(field.lower(), field)


class SigmaToSPL(FromSigmaConverter):
    """Convert Sigma to Splunk SPL."""

    def convert(self, sigma: SigmaRule) -> str:
        lines = []

        # Determine index and sourcetype
        product = sigma.logsource.get("product", "windows")
        category = sigma.logsource.get("category", "")

        if product == "windows":
            lines.append("index=windows sourcetype=WinEventLog:Security")
        elif product == "linux":
            lines.append("index=linux sourcetype=syslog")
        else:
            lines.append(f"index=main sourcetype={product}")

        # Add EventCode if process creation
        if category == "process_creation" and product == "windows":
            lines.append("EventCode=4688")

        # Convert detection to where clauses
        detection = sigma.detection
        selection = detection.get("selection", {})

        where_clauses = []
        for key, value in selection.items():
            field = self._denormalize_field(key.split("|")[0])
            modifier = key.split("|")[1] if "|" in key else None

            if isinstance(value, list):
                conditions = []
                for v in value:
                    if modifier in ["contains", "startswith", "endswith"]:
                        conditions.append(f'like({field}, "%{v}%")')
                    else:
                        conditions.append(f'{field}="{v}"')
                where_clauses.append(f"({' OR '.join(conditions)})")
            else:
                if modifier == "contains":
                    where_clauses.append(f'like({field}, "%{value}%")')
                elif modifier == "startswith":
                    where_clauses.append(f'like({field}, "{value}%")')
                elif modifier == "endswith":
                    where_clauses.append(f'like({field}, "%{value}")')
                else:
                    where_clauses.append(f'{field}="{value}"')

        if where_clauses:
            for clause in where_clauses:
                lines.append(f"| where {clause}")
        else:
            lines.append("``` No WHERE filters - query returns all matching events ```")

        # Add table output
        fields = sigma.fields or ["_time", "ComputerName", "User", "CommandLine"]
        lines.append(f"| table {', '.join(fields)}")

        return "\n".join(lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to SPL."""
        mappings = {
            "Image": "NewProcessName",
            "CommandLine": "CommandLine",
            "ParentImage": "ParentProcessName",
            "User": "User",
            "ComputerName": "ComputerName",
            "EventID": "EventCode",
        }
        return mappings.get(field, field)


# =============================================================================
# YARA-L (Google SecOps / Chronicle) Converters
# =============================================================================


class YARALToSigma(ToSigmaConverter):
    """Convert YARA-L to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()

        # Extract rule name
        name_match = re.search(r"rule\s+(\w+)", source)
        if name_match:
            sigma.title = name_match.group(1).replace("_", " ").title()

        # Extract meta section
        meta_match = re.search(r"meta:\s*(.+?)(?=events:|condition:|$)", source, re.DOTALL)
        if meta_match:
            meta_content = meta_match.group(1)
            author_match = re.search(r'author\s*=\s*["\']([^"\']+)["\']', meta_content)
            desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', meta_content)
            if author_match:
                sigma.author = author_match.group(1)
            if desc_match:
                sigma.description = desc_match.group(1)

        # Extract events section and build detection
        events_match = re.search(
            r"events:\s*(.+?)(?=condition:|match:|outcome:|$)", source, re.DOTALL
        )
        detection = {"selection": {}, "condition": "selection"}

        if events_match:
            events_content = events_match.group(1)
            # Parse field comparisons
            comparisons = re.findall(
                r'\$\w+\.([a-z_.]+)\s*(?:=|!=)\s*(?:/([^/]+)/|["\']([^"\']+)["\'])',
                events_content,
                re.IGNORECASE,
            )
            for field_path, regex_val, string_val in comparisons:
                field = self._normalize_field(field_path)
                value = regex_val or string_val
                if regex_val:
                    detection["selection"][f"{field}|re"] = value
                else:
                    detection["selection"][field] = value

        sigma.detection = detection
        sigma.logsource = {"category": "process_creation", "product": "windows"}

        return sigma

    def _normalize_field(self, field_path: str) -> str:
        """Normalize YARA-L field paths to Sigma."""
        mappings = {
            "target.process.file.full_path": "Image",
            "target.process.command_line": "CommandLine",
            "principal.user.userid": "User",
            "metadata.event_type": "EventType",
            "principal.hostname": "ComputerName",
        }
        return mappings.get(field_path, field_path.split(".")[-1])


class SigmaToYARAL(FromSigmaConverter):
    """Convert Sigma to YARA-L."""

    def convert(self, sigma: SigmaRule) -> str:
        rule_name = re.sub(r"[^a-z0-9_]", "_", sigma.title.lower())

        lines = [
            f"rule {rule_name} {{",
            "  meta:",
            f'    author = "{sigma.author}"',
            f'    description = "{sigma.description or sigma.title}"',
            f'    severity = "{self._map_severity(sigma.level)}"',
            "",
            "  events:",
        ]

        # Convert detection to YARA-L events
        detection = sigma.detection
        selection = detection.get("selection", {})

        event_var = "$e"
        event_conditions = []

        # Add event type based on logsource
        category = sigma.logsource.get("category", "")
        if category == "process_creation":
            event_conditions.append(f'{event_var}.metadata.event_type = "PROCESS_LAUNCH"')

        for key, value in selection.items():
            field = key.split("|")[0]
            modifier = key.split("|")[1] if "|" in key else None
            yaral_field = self._denormalize_field(field)

            if isinstance(value, list):
                regex_parts = [re.escape(str(v)) for v in value]
                event_conditions.append(f"{event_var}.{yaral_field} = /({'|'.join(regex_parts)})/")
            else:
                if modifier == "contains":
                    event_conditions.append(
                        f"{event_var}.{yaral_field} = /{re.escape(str(value))}/"
                    )
                elif modifier == "startswith":
                    event_conditions.append(
                        f"{event_var}.{yaral_field} = /^{re.escape(str(value))}/"
                    )
                elif modifier == "endswith":
                    event_conditions.append(
                        f"{event_var}.{yaral_field} = /{re.escape(str(value))}$/"
                    )
                elif modifier == "re":
                    event_conditions.append(f"{event_var}.{yaral_field} = /{value}/")
                else:
                    event_conditions.append(f'{event_var}.{yaral_field} = "{value}"')

        if event_conditions:
            for condition in event_conditions:
                lines.append(f"    {condition}")
        else:
            # No specific conditions - add placeholder
            lines.append("    // TODO: Add event matching conditions")
            lines.append("    // Original query had no WHERE clause filters")
            lines.append(f'    {event_var}.metadata.event_type = "GENERIC_EVENT"')

        lines.extend(
            [
                "",
                "  condition:",
                f"    {event_var}",
                "}",
            ]
        )

        return "\n".join(lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to YARA-L."""
        mappings = {
            "Image": "target.process.file.full_path",
            "CommandLine": "target.process.command_line",
            "User": "principal.user.userid",
            "ComputerName": "principal.hostname",
            "ParentImage": "principal.process.file.full_path",
            "EventID": "metadata.product_event_type",
        }
        return mappings.get(field, f"target.{field.lower()}")

    def _map_severity(self, level: str) -> str:
        """Map Sigma level to YARA-L severity."""
        mapping = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "informational": "INFORMATIONAL",
        }
        return mapping.get(level.lower(), "MEDIUM")


# =============================================================================
# KQL (Microsoft Sentinel) Converters
# =============================================================================


class KQLToSigma(ToSigmaConverter):
    """Convert KQL to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from KQL"

        # Determine logsource from table
        table_match = re.match(r"^(\w+)", source.strip())
        if table_match:
            table = table_match.group(1)
            if table == "SecurityEvent":
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif table == "Syslog":
                sigma.logsource = {"category": "process_creation", "product": "linux"}
            else:
                sigma.logsource = {"category": "generic", "product": table}

        # Parse where clauses
        detection = {"selection": {}, "condition": "selection"}

        where_matches = re.findall(r"\|\s*where\s+(.+?)(?=\||$)", source, re.IGNORECASE)
        for where_clause in where_matches:
            # Parse field conditions
            conditions = re.findall(
                r'(\w+)\s*(==|!=|contains|endswith|startswith|has)\s*["\']?([^"\'\s|]+)["\']?',
                where_clause,
                re.IGNORECASE,
            )
            for field_name, operator, value in conditions:
                normalized = self._normalize_field(field_name)
                if operator.lower() == "contains" or operator.lower() == "has":
                    detection["selection"][f"{normalized}|contains"] = value
                elif operator.lower() == "startswith":
                    detection["selection"][f"{normalized}|startswith"] = value
                elif operator.lower() == "endswith":
                    detection["selection"][f"{normalized}|endswith"] = value
                else:
                    detection["selection"][normalized] = value

        sigma.detection = detection

        # Extract fields from project
        project_match = re.search(r"\|\s*project\s+(.+?)(?=\||$)", source, re.IGNORECASE)
        if project_match:
            sigma.fields = [f.strip() for f in project_match.group(1).split(",")]

        return sigma

    def _normalize_field(self, field: str) -> str:
        """Normalize KQL field names to Sigma."""
        mappings = {
            "NewProcessName": "Image",
            "Process": "Image",
            "CommandLine": "CommandLine",
            "ParentProcessName": "ParentImage",
            "Account": "User",
            "Computer": "ComputerName",
            "EventID": "EventID",
        }
        return mappings.get(field, field)


class SigmaToKQL(FromSigmaConverter):
    """Convert Sigma to KQL."""

    def convert(self, sigma: SigmaRule) -> str:
        lines = []

        # Determine table
        product = sigma.logsource.get("product", "windows")
        category = sigma.logsource.get("category", "")

        if product == "windows":
            lines.append("SecurityEvent")
        elif product == "linux":
            lines.append("Syslog")
        else:
            lines.append("CommonSecurityLog")

        # Add EventID filter for process creation
        if category == "process_creation" and product == "windows":
            lines.append("| where EventID == 4688")

        # Convert detection to where clauses
        detection = sigma.detection
        selection = detection.get("selection", {})

        for key, value in selection.items():
            field = key.split("|")[0]
            modifier = key.split("|")[1] if "|" in key else None
            kql_field = self._denormalize_field(field)

            if isinstance(value, list):
                conditions = []
                for v in value:
                    if modifier == "contains":
                        conditions.append(f'{kql_field} contains "{v}"')
                    else:
                        conditions.append(f'{kql_field} == "{v}"')
                lines.append(f"| where ({' or '.join(conditions)})")
            else:
                if modifier == "contains":
                    lines.append(f'| where {kql_field} contains "{value}"')
                elif modifier == "startswith":
                    lines.append(f'| where {kql_field} startswith "{value}"')
                elif modifier == "endswith":
                    lines.append(f'| where {kql_field} endswith "{value}"')
                else:
                    lines.append(f'| where {kql_field} == "{value}"')

        # Add project
        fields = sigma.fields or [
            "TimeGenerated",
            "Computer",
            "Account",
            "NewProcessName",
            "CommandLine",
        ]
        lines.append(f"| project {', '.join(fields)}")

        return "\n".join(lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to KQL."""
        mappings = {
            "Image": "NewProcessName",
            "CommandLine": "CommandLine",
            "ParentImage": "ParentProcessName",
            "User": "Account",
            "ComputerName": "Computer",
            "EventID": "EventID",
        }
        return mappings.get(field, field)


# =============================================================================
# EQL (Elastic Security) Converters
# =============================================================================


class EQLToSigma(ToSigmaConverter):
    """Convert EQL to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from EQL"

        # Parse event type
        event_match = re.match(r"(\w+)\s+where", source.strip())
        if event_match:
            event_type = event_match.group(1)
            if event_type == "process":
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif event_type == "file":
                sigma.logsource = {"category": "file_event", "product": "windows"}
            elif event_type == "network":
                sigma.logsource = {"category": "network_connection", "product": "windows"}

        # Parse conditions
        detection = {"selection": {}, "condition": "selection"}

        # Find conditions after 'where'
        where_match = re.search(r"where\s+(.+)", source, re.DOTALL)
        if where_match:
            conditions_str = where_match.group(1)

            # Parse field == value patterns
            eq_matches = re.findall(r'([\w.]+)\s*==\s*["\']([^"\']+)["\']', conditions_str)
            for field, value in eq_matches:
                normalized = self._normalize_field(field)
                detection["selection"][normalized] = value

            # Parse field : "*value*" patterns (wildcards)
            like_matches = re.findall(r'([\w.]+)\s*:\s*["\']([^"\']+)["\']', conditions_str)
            for field, value in like_matches:
                normalized = self._normalize_field(field)
                if value.startswith("*") and value.endswith("*"):
                    detection["selection"][f"{normalized}|contains"] = value.strip("*")
                elif value.startswith("*"):
                    detection["selection"][f"{normalized}|endswith"] = value.lstrip("*")
                elif value.endswith("*"):
                    detection["selection"][f"{normalized}|startswith"] = value.rstrip("*")
                else:
                    detection["selection"][normalized] = value

        sigma.detection = detection
        return sigma

    def _normalize_field(self, field: str) -> str:
        """Normalize EQL field names to Sigma."""
        mappings = {
            "process.name": "Image",
            "process.executable": "Image",
            "process.command_line": "CommandLine",
            "process.parent.name": "ParentImage",
            "user.name": "User",
            "host.name": "ComputerName",
        }
        return mappings.get(field, field.split(".")[-1])


class SigmaToEQL(FromSigmaConverter):
    """Convert Sigma to EQL."""

    def convert(self, sigma: SigmaRule) -> str:
        # Determine event type
        category = sigma.logsource.get("category", "process_creation")
        if category in ["process_creation", "process_start"]:
            event_type = "process"
        elif "file" in category:
            event_type = "file"
        elif "network" in category:
            event_type = "network"
        else:
            event_type = "any"

        conditions = []
        detection = sigma.detection
        selection = detection.get("selection", {})

        for key, value in selection.items():
            field = key.split("|")[0]
            modifier = key.split("|")[1] if "|" in key else None
            eql_field = self._denormalize_field(field)

            if isinstance(value, list):
                value_conditions = []
                for v in value:
                    if modifier == "contains":
                        value_conditions.append(f'{eql_field} : "*{v}*"')
                    else:
                        value_conditions.append(f'{eql_field} == "{v}"')
                conditions.append(f"({' or '.join(value_conditions)})")
            else:
                if modifier == "contains":
                    conditions.append(f'{eql_field} : "*{value}*"')
                elif modifier == "startswith":
                    conditions.append(f'{eql_field} : "{value}*"')
                elif modifier == "endswith":
                    conditions.append(f'{eql_field} : "*{value}"')
                else:
                    conditions.append(f'{eql_field} == "{value}"')

        condition_str = " and ".join(conditions) if conditions else "true"
        return f"{event_type} where {condition_str}"

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to EQL."""
        mappings = {
            "Image": "process.name",
            "CommandLine": "process.command_line",
            "ParentImage": "process.parent.name",
            "User": "user.name",
            "ComputerName": "host.name",
        }
        return mappings.get(field, f"process.{field.lower()}")


# =============================================================================
# ES|QL (Elastic - new) Converters
# =============================================================================


class ESQLToSigma(ToSigmaConverter):
    """Convert ES|QL to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from ES|QL"

        # Parse FROM clause to determine logsource
        from_match = re.search(r"FROM\s+([^\s|]+)", source, re.IGNORECASE)
        if from_match:
            index = from_match.group(1)
            if "windows" in index.lower():
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif "linux" in index.lower():
                sigma.logsource = {"category": "process_creation", "product": "linux"}

        # Parse WHERE clause
        detection = {"selection": {}, "condition": "selection"}

        where_match = re.search(r"WHERE\s+(.+?)(?=\||$)", source, re.IGNORECASE | re.DOTALL)
        if where_match:
            where_clause = where_match.group(1)

            # Parse field == value
            eq_matches = re.findall(r'([\w.]+)\s*==\s*["\']([^"\']+)["\']', where_clause)
            for field, value in eq_matches:
                normalized = self._normalize_field(field)
                detection["selection"][normalized] = value

            # Parse LIKE patterns
            like_matches = re.findall(
                r'([\w.]+)\s+LIKE\s+["\']([^"\']+)["\']', where_clause, re.IGNORECASE
            )
            for field, value in like_matches:
                normalized = self._normalize_field(field)
                if value.startswith("%") and value.endswith("%"):
                    detection["selection"][f"{normalized}|contains"] = value.strip("%")
                elif value.startswith("%"):
                    detection["selection"][f"{normalized}|endswith"] = value.lstrip("%")
                elif value.endswith("%"):
                    detection["selection"][f"{normalized}|startswith"] = value.rstrip("%")

        sigma.detection = detection

        # Parse KEEP clause for fields
        keep_match = re.search(r"KEEP\s+(.+?)(?=\||$)", source, re.IGNORECASE)
        if keep_match:
            sigma.fields = [f.strip() for f in keep_match.group(1).split(",")]

        return sigma

    def _normalize_field(self, field: str) -> str:
        """Normalize ES|QL field names to Sigma."""
        mappings = {
            "process.name": "Image",
            "process.executable": "Image",
            "process.command_line": "CommandLine",
            "user.name": "User",
            "host.name": "ComputerName",
        }
        return mappings.get(field, field.split(".")[-1])


class SigmaToESQL(FromSigmaConverter):
    """Convert Sigma to ES|QL."""

    def convert(self, sigma: SigmaRule) -> str:
        lines = []

        # Determine index
        product = sigma.logsource.get("product", "windows")
        if product == "windows":
            lines.append("FROM logs-windows.*")
        elif product == "linux":
            lines.append("FROM logs-linux.*")
        else:
            lines.append("FROM logs-*")

        # Build WHERE clause
        detection = sigma.detection
        selection = detection.get("selection", {})

        conditions = []
        for key, value in selection.items():
            field = key.split("|")[0]
            modifier = key.split("|")[1] if "|" in key else None
            esql_field = self._denormalize_field(field)

            if isinstance(value, list):
                value_conditions = []
                for v in value:
                    if modifier == "contains":
                        value_conditions.append(f'{esql_field} LIKE "%{v}%"')
                    else:
                        value_conditions.append(f'{esql_field} == "{v}"')
                conditions.append(f"({' OR '.join(value_conditions)})")
            else:
                if modifier == "contains":
                    conditions.append(f'{esql_field} LIKE "%{value}%"')
                elif modifier == "startswith":
                    conditions.append(f'{esql_field} LIKE "{value}%"')
                elif modifier == "endswith":
                    conditions.append(f'{esql_field} LIKE "%{value}"')
                else:
                    conditions.append(f'{esql_field} == "{value}"')

        if conditions:
            lines.append(f"| WHERE {' AND '.join(conditions)}")

        # Add KEEP
        fields = sigma.fields or [
            "@timestamp",
            "host.name",
            "user.name",
            "process.name",
            "process.command_line",
        ]
        lines.append(f"| KEEP {', '.join(fields)}")

        return "\n".join(lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to ES|QL."""
        mappings = {
            "Image": "process.name",
            "CommandLine": "process.command_line",
            "ParentImage": "process.parent.name",
            "User": "user.name",
            "ComputerName": "host.name",
        }
        return mappings.get(field, field.lower())


# =============================================================================
# Panther Python Converters
# =============================================================================


class PantherToSigma(ToSigmaConverter):
    """Convert Panther Python rules to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from Panther Python rule"
        sigma.logsource = {"category": "process_creation", "product": "windows"}

        detection = {"selection": {}, "condition": "selection"}

        # Parse title function for rule name
        title_match = re.search(
            r'def title\([^)]*\):\s*\n\s*return\s+[f]?["\']([^"\']+)["\']', source
        )
        if title_match:
            sigma.title = title_match.group(1).split("{")[0].strip()

        # Parse rule function for conditions
        # Look for event.get() calls
        re.findall(
            r'event\.get\(["\']([^"\']+)["\']\s*(?:,\s*["\'][^"\']*["\'])?\)', source
        )

        # Look for 'in' checks (e.g., if "value" in field)
        in_matches = re.findall(
            r'["\']([^"\']+)["\']\s+in\s+(?:event\.get\(["\']([^"\']+)["\']|(\w+))', source
        )
        for value, field1, field2 in in_matches:
            field = self._normalize_field(field1 or field2)
            detection["selection"][f"{field}|contains"] = value

        # Look for endswith/startswith checks
        endswith_matches = re.findall(r'\.endswith\(["\']([^"\']+)["\']\)', source)
        for value in endswith_matches:
            detection["selection"]["Image|endswith"] = value

        startswith_matches = re.findall(r'\.startswith\(["\']([^"\']+)["\']\)', source)
        for value in startswith_matches:
            detection["selection"]["Image|startswith"] = value

        # Look for == comparisons
        eq_matches = re.findall(
            r'event\.get\(["\']([^"\']+)["\']\)\s*==\s*["\']([^"\']+)["\']', source
        )
        for field, value in eq_matches:
            normalized = self._normalize_field(field)
            detection["selection"][normalized] = value

        sigma.detection = detection
        return sigma

    def _normalize_field(self, field: str) -> str:
        """Normalize Panther field names to Sigma."""
        mappings = {
            "process_name": "Image",
            "command_line": "CommandLine",
            "parent_process_name": "ParentImage",
            "user": "User",
            "hostname": "ComputerName",
        }
        return mappings.get(field.lower(), field)


class SigmaToPanther(FromSigmaConverter):
    """Convert Sigma to Panther Python rules."""

    def convert(self, sigma: SigmaRule) -> str:
        # Check if this is an aggregation query
        if sigma.is_aggregation_query():
            return self._convert_aggregation_rule(sigma)
        else:
            return self._convert_streaming_rule(sigma)

    def _convert_aggregation_rule(self, sigma: SigmaRule) -> str:
        """Generate a Scheduled Rule for aggregation queries."""
        lines = []

        lines.append('"""')
        lines.append(f"Scheduled Rule: {sigma.title}")
        lines.append("")
        lines.append("This is an AGGREGATION query that requires a Panther Scheduled Rule.")
        lines.append("Scheduled Rules run SQL queries on a schedule and alert on results.")
        lines.append("See: https://docs.panther.com/detections/scheduled-rules")
        lines.append('"""')
        lines.append("")

        # Generate SQL for the scheduled query
        lines.append('SCHEDULED_QUERY = """')

        # Build SELECT clause
        select_parts = []
        for field_name in sigma.group_by:
            panther_field = FieldMapper.from_canonical(field_name, "panther")
            select_parts.append(f"    {panther_field}")

        for agg in sigma.aggregations:
            agg_sql = agg.to_sql()
            select_parts.append(f"    {agg_sql}")

        if not select_parts:
            select_parts = ["    source_ip", "    COUNT(*) AS event_count"]

        lines.append("SELECT")
        lines.append(",\n".join(select_parts))

        # Table
        lines.append("FROM panther_logs.public.your_log_table")

        # Build WHERE clause
        detection = sigma.detection
        selection = detection.get("selection", {})

        where_parts = []
        for key, value in selection.items():
            parts = key.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None
            panther_field = FieldMapper.from_canonical(field, "sql")

            if modifier in [">=", "<=", ">", "<", "!=", "="]:
                where_parts.append(f"{panther_field} {modifier} {value}")
            elif modifier == "contains":
                where_parts.append(f"{panther_field} LIKE '%{value}%'")
            elif modifier == "startswith":
                where_parts.append(f"{panther_field} LIKE '{value}%'")
            elif modifier == "endswith":
                where_parts.append(f"{panther_field} LIKE '%{value}'")
            elif isinstance(value, list):
                escaped = [f"'{v}'" for v in value]
                where_parts.append(f"{panther_field} IN ({', '.join(escaped)})")
            else:
                where_parts.append(f"{panther_field} = '{value}'")

        # Add time filter
        if sigma.time_range:
            where_parts.append(sigma.time_range.to_panther())
        else:
            where_parts.append("p_occurs_since('1 hour')")

        if where_parts:
            lines.append(f"WHERE {where_parts[0]}")
            for part in where_parts[1:]:
                lines.append(f"    AND {part}")
        else:
            lines.append("WHERE p_occurs_since('1 hour')")

        # GROUP BY
        if sigma.group_by:
            group_fields = [FieldMapper.from_canonical(f, "panther") for f in sigma.group_by]
            lines.append(f"GROUP BY {', '.join(group_fields)}")
        else:
            lines.append("GROUP BY source_ip")

        # HAVING
        if sigma.having:
            lines.append(f"HAVING {sigma.having}")
        else:
            # Try to infer threshold from aggregation
            lines.append("HAVING COUNT(*) > 5  -- Adjust threshold as needed")

        # ORDER BY and LIMIT
        if sigma.order_by:
            lines.append(f"ORDER BY {', '.join(sigma.order_by)}")

        if sigma.limit:
            lines.append(f"LIMIT {sigma.limit}")

        lines.append('"""')
        lines.append("")
        lines.append("")

        # Generate rule function
        # Determine the primary aggregation field for the rule
        agg_field = "event_count"
        threshold = 5
        if sigma.aggregations:
            agg_field = sigma.aggregations[0].alias or "event_count"

        # Try to parse threshold from HAVING
        if sigma.having:
            threshold_match = re.search(r">\s*(\d+)", sigma.having)
            if threshold_match:
                threshold = int(threshold_match.group(1))

        lines.append("def rule(event):")
        lines.append('    """')
        lines.append("    Process each row returned by the scheduled query.")
        lines.append('    """')
        lines.append(f'    {agg_field} = event.get("{agg_field}", 0)')
        lines.append(f"    return {agg_field} > {threshold}")
        lines.append("")
        lines.append("")

        # Generate title function
        title_field = sigma.group_by[0] if sigma.group_by else "source_ip"
        title_panther = FieldMapper.from_canonical(title_field, "panther")
        safe_title = sigma.title.replace('"', '\\"')

        lines.append("def title(event):")
        lines.append(f'    source = event.get("{title_panther}", "unknown")')
        lines.append(f'    count = event.get("{agg_field}", 0)')
        lines.append(f'    return f"{safe_title}: {{source}} had {{count}} events"')
        lines.append("")
        lines.append("")

        # Generate severity function
        lines.append("def severity(event):")
        lines.append(f'    count = event.get("{agg_field}", 0)')
        lines.append(f"    if count > {threshold * 20}:")
        lines.append('        return "CRITICAL"')
        lines.append(f"    elif count > {threshold * 10}:")
        lines.append('        return "HIGH"')
        lines.append(f"    elif count > {threshold * 4}:")
        lines.append('        return "MEDIUM"')
        lines.append('    return "LOW"')

        return "\n".join(lines)

    def _convert_streaming_rule(self, sigma: SigmaRule) -> str:
        """Generate a streaming rule for non-aggregation queries."""
        lines = []

        # Build conditions list
        detection = sigma.detection
        selection = detection.get("selection", {})

        conditions = []
        for key, value in selection.items():
            parts = key.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None
            panther_field = FieldMapper.from_canonical(field, "panther")

            # Skip comparison operators for streaming rules
            if modifier in [">=", "<=", ">", "<", "!=", "="]:
                continue

            if isinstance(value, list):
                value_checks = []
                for v in value:
                    if modifier == "contains":
                        value_checks.append(
                            f'"{v}".lower() in event.get("{panther_field}", "").lower()'
                        )
                    elif modifier == "endswith":
                        value_checks.append(
                            f'event.get("{panther_field}", "").lower().endswith("{v}".lower())'
                        )
                    elif modifier == "startswith":
                        value_checks.append(
                            f'event.get("{panther_field}", "").lower().startswith("{v}".lower())'
                        )
                    else:
                        value_checks.append(f'event.get("{panther_field}") == "{v}"')
                conditions.append(f"({' or '.join(value_checks)})")
            else:
                if modifier == "contains":
                    conditions.append(
                        f'"{value}".lower() in event.get("{panther_field}", "").lower()'
                    )
                elif modifier == "endswith":
                    conditions.append(
                        f'event.get("{panther_field}", "").lower().endswith("{value}".lower())'
                    )
                elif modifier == "startswith":
                    conditions.append(
                        f'event.get("{panther_field}", "").lower().startswith("{value}".lower())'
                    )
                else:
                    conditions.append(f'event.get("{panther_field}") == "{value}"')

        # Generate rule function
        lines.append("def rule(event):")
        lines.append('    """')
        lines.append(f"    {sigma.title}")
        if sigma.description and not sigma.description.startswith("Converted from"):
            lines.append(f"    {sigma.description}")
        lines.append(f"    Severity: {sigma.level.upper()}")
        lines.append('    """')

        if conditions:
            # Format conditions nicely
            if len(conditions) == 1:
                lines.append(f"    return {conditions[0]}")
            else:
                lines.append("    return (")
                for i, cond in enumerate(conditions):
                    if i < len(conditions) - 1:
                        lines.append(f"        {cond} and")
                    else:
                        lines.append(f"        {cond}")
                lines.append("    )")
        else:
            lines.append("    # TODO: Add detection logic based on original query")
            lines.append("    return True  # Match all events - refine as needed")
        lines.append("")
        lines.append("")

        # Generate title function
        safe_title = sigma.title.replace('"', '\\"')
        lines.append("def title(event):")
        lines.append(f"    return f\"{safe_title} on {{event.get('hostname', 'unknown')}}\"")
        lines.append("")
        lines.append("")

        # Generate severity function
        lines.append("def severity(event):")
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "informational": "INFO",
        }
        panther_severity = severity_map.get(sigma.level.lower(), "MEDIUM")
        lines.append(f'    return "{panther_severity}"')

        return "\n".join(lines)


# =============================================================================
# AQL (IBM QRadar) Converters
# =============================================================================


class AQLToSigma(ToSigmaConverter):
    """Convert IBM QRadar AQL to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from QRadar AQL"

        # Determine logsource from FROM table
        from_match = re.search(r"FROM\s+(\w+)", source, re.IGNORECASE)
        if from_match:
            table = from_match.group(1).lower()
            if table == "events":
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif table == "flows":
                sigma.logsource = {"category": "network_connection", "product": "generic"}
            else:
                sigma.logsource = {"category": "generic", "product": table}

        # Parse time range (LAST X HOURS/DAYS/MINUTES)
        last_match = re.search(
            r"LAST\s+(\d+)\s+(MINUTE|HOUR|DAY|WEEK|MONTH)S?", source, re.IGNORECASE
        )
        if last_match:
            sigma.time_range = TimeRange(
                value=int(last_match.group(1)), unit=last_match.group(2).upper()
            )

        # Parse LIMIT
        limit_match = re.search(r"LIMIT\s+(\d+)", source, re.IGNORECASE)
        if limit_match:
            sigma.limit = int(limit_match.group(1))

        # Parse ORDER BY
        order_match = re.search(r"ORDER\s+BY\s+([^LIMIT\n]+)", source, re.IGNORECASE)
        if order_match:
            sigma.order_by = [f.strip() for f in order_match.group(1).split(",")]

        # Parse GROUP BY
        group_by_match = re.search(
            r"GROUP\s+BY\s+([^HAVING\nORDER\nLIMIT]+)", source, re.IGNORECASE
        )
        if group_by_match:
            sigma.group_by = [
                FieldMapper.to_canonical(f.strip(), "aql")
                for f in group_by_match.group(1).split(",")
            ]

        # Parse HAVING
        having_match = re.search(r"HAVING\s+(.+?)(?:ORDER BY|LIMIT|LAST|$)", source, re.IGNORECASE)
        if having_match:
            sigma.having = having_match.group(1).strip()

        # Parse aggregation functions in SELECT
        select_match = re.search(r"SELECT\s+(.+?)\s+FROM", source, re.IGNORECASE)
        if select_match:
            select_clause = select_match.group(1)

            # Parse aggregation functions: COUNT(*), SUM(field), etc.
            agg_pattern = (
                r"(COUNT|SUM|AVG|MIN|MAX|UNIQUECOUNT)\s*\(\s*(\*|\w+)\s*\)(?:\s+AS\s+(\w+))?"
            )
            agg_matches = re.findall(agg_pattern, select_clause, re.IGNORECASE)
            for func, agg_field, alias in agg_matches:
                sigma.aggregations.append(
                    Aggregation(
                        function=func.upper(),
                        field=agg_field if agg_field != "*" else None,
                        alias=alias if alias else None,
                    )
                )

            # Extract non-aggregation fields
            if select_clause.strip() != "*":
                fields = []
                for part in select_clause.split(","):
                    part = part.strip()
                    # Skip aggregation functions
                    if not re.match(
                        r"(COUNT|SUM|AVG|MIN|MAX|UNIQUECOUNT)\s*\(", part, re.IGNORECASE
                    ):
                        # Get field name (last word, handles "field AS alias")
                        field_name = (
                            part.split()[-1] if " AS " not in part.upper() else part.split()[0]
                        )
                        if field_name and field_name != "*":
                            fields.append(field_name)
                sigma.fields = fields

        detection = {"selection": {}, "condition": "selection"}

        # Parse WHERE clause
        where_match = re.search(
            r"WHERE\s+(.+?)(?:GROUP BY|ORDER BY|HAVING|LIMIT|START|STOP|LAST|$)",
            source,
            re.IGNORECASE | re.DOTALL,
        )
        if where_match:
            where_clause = where_match.group(1)

            # Parse field = 'value' patterns
            eq_matches = re.findall(r"(\w+)\s*=\s*'([^']+)'", where_clause)
            for field, value in eq_matches:
                normalized = FieldMapper.to_canonical(field, "aql")
                detection["selection"][normalized] = value

            # Parse ILIKE patterns (case-insensitive LIKE)
            ilike_matches = re.findall(r"(\w+)\s+ILIKE\s+'([^']+)'", where_clause, re.IGNORECASE)
            for field, value in ilike_matches:
                normalized = FieldMapper.to_canonical(field, "aql")
                if value.startswith("%") and value.endswith("%"):
                    detection["selection"][f"{normalized}|contains"] = value.strip("%")
                elif value.startswith("%"):
                    detection["selection"][f"{normalized}|endswith"] = value.lstrip("%")
                elif value.endswith("%"):
                    detection["selection"][f"{normalized}|startswith"] = value.rstrip("%")
                else:
                    detection["selection"][normalized] = value

            # Parse LIKE patterns
            like_matches = re.findall(r"(\w+)\s+LIKE\s+'([^']+)'", where_clause, re.IGNORECASE)
            for field, value in like_matches:
                normalized = FieldMapper.to_canonical(field, "aql")
                if value.startswith("%") and value.endswith("%"):
                    detection["selection"][f"{normalized}|contains"] = value.strip("%")
                elif value.startswith("%"):
                    detection["selection"][f"{normalized}|endswith"] = value.lstrip("%")
                elif value.endswith("%"):
                    detection["selection"][f"{normalized}|startswith"] = value.rstrip("%")
                else:
                    detection["selection"][normalized] = value

            # Parse IN clauses
            in_matches = re.findall(r"(\w+)\s+IN\s*\(([^)]+)\)", where_clause, re.IGNORECASE)
            for field, values_str in in_matches:
                normalized = FieldMapper.to_canonical(field, "aql")
                values = [v.strip().strip("'\"") for v in values_str.split(",")]
                detection["selection"][normalized] = values

            # Parse comparison operators with numbers
            cmp_matches = re.findall(r"(\w+)\s*(>=|<=|>|<|!=|=)\s*(\d+)", where_clause)
            for field, op, value in cmp_matches:
                normalized = FieldMapper.to_canonical(field, "aql")
                detection["selection"][f"{normalized}|{op}"] = int(value)

        sigma.detection = detection
        return sigma


class SigmaToAQL(FromSigmaConverter):
    """Convert Sigma to IBM QRadar AQL."""

    def convert(self, sigma: SigmaRule) -> str:
        lines = []

        # Build SELECT clause
        fields = sigma.fields or [
            "sourceip",
            "destinationip",
            "username",
            "LOGSOURCENAME(logsourceid)",
            "starttime",
        ]
        lines.append(f"SELECT {', '.join(fields)}")

        # Determine table from logsource
        category = sigma.logsource.get("category", "")
        if "network" in category:
            lines.append("FROM flows")
        else:
            lines.append("FROM events")

        # Build WHERE clause
        detection = sigma.detection
        selection = detection.get("selection", {})

        conditions = []
        for key, value in selection.items():
            field = key.split("|")[0]
            modifier = key.split("|")[1] if "|" in key else None
            aql_field = self._denormalize_field(field)

            if isinstance(value, list):
                value_conditions = []
                for v in value:
                    if modifier == "contains":
                        value_conditions.append(f"{aql_field} ILIKE '%{v}%'")
                    else:
                        value_conditions.append(f"{aql_field} = '{v}'")
                conditions.append(f"({' OR '.join(value_conditions)})")
            else:
                if modifier == "contains":
                    conditions.append(f"{aql_field} ILIKE '%{value}%'")
                elif modifier == "startswith":
                    conditions.append(f"{aql_field} ILIKE '{value}%'")
                elif modifier == "endswith":
                    conditions.append(f"{aql_field} ILIKE '%{value}'")
                elif modifier == "re":
                    conditions.append(f"{aql_field} MATCHES '{value}'")
                else:
                    # Check if it's a comparison operator
                    if str(value).startswith((">=", "<=", ">", "<", "!=")):
                        conditions.append(f"{aql_field} {value}")
                    else:
                        conditions.append(f"{aql_field} = '{value}'")

        if conditions:
            lines.append(f"WHERE {' AND '.join(conditions)}")

        # Add time range
        lines.append("LAST 24 HOURS")

        return "\n".join(lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to AQL."""
        mappings = {
            "SourceIP": "sourceip",
            "DestinationIP": "destinationip",
            "User": "username",
            "Category": "category",
            "Severity": "magnitude",
            "SourcePort": "sourceport",
            "DestinationPort": "destinationport",
            "Protocol": "protocol",
            "LogSource": "logsourceid",
            "EventID": "qid",
            "Image": "Application",
            "CommandLine": "Command",
            "ComputerName": "hostname",
        }
        return mappings.get(field, field.lower())


# =============================================================================
# Standard SQL Converter (output only)
# =============================================================================


class SigmaToSQL(FromSigmaConverter):
    """Convert Sigma to standard SQL."""

    def convert(self, sigma: SigmaRule) -> str:
        lines = []

        # Comment header
        lines.append(f"-- Converted from Sigma rule: {sigma.title}")
        if sigma.description and not sigma.description.startswith("Converted from"):
            lines.append(f"-- {sigma.description}")
        lines.append("")

        # Build SELECT clause
        if sigma.is_aggregation_query():
            select_parts = []
            # Add GROUP BY fields first
            for field in sigma.group_by:
                sql_field = FieldMapper.from_canonical(field, "sql")
                select_parts.append(sql_field)
            # Add aggregations
            for agg in sigma.aggregations:
                select_parts.append(agg.to_sql())
            if select_parts:
                lines.append(f"SELECT {', '.join(select_parts)}")
            else:
                lines.append("SELECT *")
        else:
            fields = sigma.fields or ["*"]
            sql_fields = [FieldMapper.from_canonical(f, "sql") for f in fields]
            lines.append(f"SELECT {', '.join(sql_fields)}")

        # Determine table from logsource
        product = sigma.logsource.get("product", "security_events")
        category = sigma.logsource.get("category", "")

        table_name = f"{product}_{category}" if category else product
        table_name = re.sub(r"[^a-z0-9_]", "_", table_name.lower())
        lines.append(f"FROM {table_name}")

        # Build WHERE clause
        detection = sigma.detection
        selection = detection.get("selection", {})

        conditions = []
        for key, value in selection.items():
            parts = key.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None
            sql_field = FieldMapper.from_canonical(field, "sql")

            # Handle comparison operators stored as modifiers
            if modifier in [">=", "<=", ">", "<", "!=", "="]:
                conditions.append(f"{sql_field} {modifier} {value}")
                continue

            if isinstance(value, list):
                if modifier == "contains":
                    value_conditions = [f"{sql_field} LIKE '%{v}%'" for v in value]
                    conditions.append(f"({' OR '.join(value_conditions)})")
                else:
                    escaped_values = [f"'{v}'" for v in value]
                    conditions.append(f"{sql_field} IN ({', '.join(escaped_values)})")
            else:
                if modifier == "contains":
                    conditions.append(f"{sql_field} LIKE '%{value}%'")
                elif modifier == "startswith":
                    conditions.append(f"{sql_field} LIKE '{value}%'")
                elif modifier == "endswith":
                    conditions.append(f"{sql_field} LIKE '%{value}'")
                elif modifier == "re":
                    conditions.append(f"{sql_field} REGEXP '{value}'")
                else:
                    conditions.append(f"{sql_field} = '{value}'")

        # Add time range condition
        if sigma.time_range:
            conditions.append(sigma.time_range.to_sql())

        if conditions:
            lines.append(f"WHERE {' AND '.join(conditions)}")

        # Add GROUP BY
        if sigma.group_by:
            group_fields = [FieldMapper.from_canonical(f, "sql") for f in sigma.group_by]
            lines.append(f"GROUP BY {', '.join(group_fields)}")

        # Add HAVING
        if sigma.having:
            lines.append(f"HAVING {sigma.having}")

        # Add ORDER BY
        if sigma.order_by:
            lines.append(f"ORDER BY {', '.join(sigma.order_by)}")
        else:
            lines.append("ORDER BY timestamp DESC")

        # Add LIMIT
        limit = sigma.limit or 1000
        lines.append(f"LIMIT {limit};")

        return "\n".join(lines)

    def _normalize_field_for_sql(self, field: str) -> str:
        """Normalize field names for SQL."""
        return FieldMapper.from_canonical(field, "sql")


class SQLToSigma(ToSigmaConverter):
    """Convert standard SQL to Sigma (basic support)."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from SQL"

        # Parse FROM table
        from_match = re.search(r"FROM\s+(\w+)", source, re.IGNORECASE)
        if from_match:
            table = from_match.group(1)
            sigma.logsource = {"category": "generic", "product": table}

        detection = {"selection": {}, "condition": "selection"}

        # Parse WHERE clause
        where_match = re.search(
            r"WHERE\s+(.+?)(?:ORDER BY|GROUP BY|LIMIT|;|$)", source, re.IGNORECASE | re.DOTALL
        )
        if where_match:
            where_clause = where_match.group(1)

            # Parse field = 'value' patterns
            eq_matches = re.findall(r"(\w+)\s*=\s*'([^']+)'", where_clause)
            for field, value in eq_matches:
                detection["selection"][field] = value

            # Parse LIKE patterns
            like_matches = re.findall(r"(\w+)\s+LIKE\s+'([^']+)'", where_clause, re.IGNORECASE)
            for field, value in like_matches:
                if value.startswith("%") and value.endswith("%"):
                    detection["selection"][f"{field}|contains"] = value.strip("%")
                elif value.startswith("%"):
                    detection["selection"][f"{field}|endswith"] = value.lstrip("%")
                elif value.endswith("%"):
                    detection["selection"][f"{field}|startswith"] = value.rstrip("%")

        sigma.detection = detection

        # Parse SELECT fields
        select_match = re.search(r"SELECT\s+(.+?)\s+FROM", source, re.IGNORECASE)
        if select_match:
            fields_str = select_match.group(1)
            if fields_str.strip() != "*":
                sigma.fields = [f.strip() for f in fields_str.split(",")]

        return sigma


# =============================================================================
# CQL (Chronicle Query Language) Converters
# =============================================================================


class CQLToSigma(ToSigmaConverter):
    """Convert Chronicle Query Language (CQL) to Sigma."""

    def convert(self, source: str) -> SigmaRule:
        sigma = SigmaRule()
        sigma.description = "Converted from CQL"

        # Default logsource for CQL (typically UDM events)
        sigma.logsource = {"category": "generic", "product": "chronicle"}

        detection = {"selection": {}, "condition": "selection"}

        # Parse filter statements
        # CQL uses: | filter field = "value" or field =~ /regex/
        filter_matches = re.findall(r"\|\s*filter\s+([^\|]+)", source, re.IGNORECASE)

        for filter_clause in filter_matches:
            # Parse equality: field = "value"
            eq_matches = re.findall(r'(\S+)\s*=\s*"([^"]+)"', filter_clause)
            for field_name, value in eq_matches:
                canonical = self._normalize_field(field_name)
                detection["selection"][canonical] = value

            # Parse regex: field =~ /pattern/
            regex_matches = re.findall(r"(\S+)\s*=~\s*/([^/]+)/", filter_clause)
            for field_name, pattern in regex_matches:
                canonical = self._normalize_field(field_name)
                # Convert common regex patterns to Sigma modifiers
                if pattern.startswith("^"):
                    detection["selection"][f"{canonical}|startswith"] = pattern[1:]
                elif pattern.endswith("$"):
                    detection["selection"][f"{canonical}|endswith"] = pattern[:-1].replace("\\", "")
                else:
                    detection["selection"][f"{canonical}|contains"] = pattern.replace("\\", "")

            # Parse inequality: field != "value"
            neq_matches = re.findall(r'(\S+)\s*!=\s*"([^"]+)"', filter_clause)
            for field_name, value in neq_matches:
                canonical = self._normalize_field(field_name)
                if "filter_not" not in detection:
                    detection["filter_not"] = {}
                detection["filter_not"][canonical] = value

        # Detect event type from metadata
        event_type_match = re.search(r'metadata\.event_type\s*=\s*"([^"]+)"', source)
        if event_type_match:
            event_type = event_type_match.group(1)
            if event_type == "PROCESS_LAUNCH":
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif event_type == "NETWORK_CONNECTION":
                sigma.logsource = {"category": "network_connection", "product": "windows"}
            elif event_type == "FILE_CREATION":
                sigma.logsource = {"category": "file_event", "product": "windows"}

        if detection.get("filter_not"):
            detection["condition"] = "selection and not filter_not"

        sigma.detection = detection

        # Parse aggregations
        agg_match = re.search(r"\|\s*aggregate\s+(\w+)\s*\(\s*(\w*)\s*\)", source, re.IGNORECASE)
        if agg_match:
            func = agg_match.group(1).upper()
            field = agg_match.group(2) or None
            sigma.aggregations.append(Aggregation(function=func, field=field))

        # Parse group by
        group_match = re.search(r"\|\s*group\s+by\s+([^\|]+)", source, re.IGNORECASE)
        if group_match:
            fields = [f.strip() for f in group_match.group(1).split(",")]
            sigma.group_by = [self._normalize_field(f) for f in fields]

        # Parse outcome/limit
        limit_match = re.search(r"\|\s*head\s+(\d+)", source, re.IGNORECASE)
        if limit_match:
            sigma.limit = int(limit_match.group(1))

        return sigma

    def _normalize_field(self, field: str) -> str:
        """Normalize CQL field paths to Sigma canonical names."""
        mappings = {
            "target.process.file.full_path": "Image",
            "target.process.command_line": "CommandLine",
            "principal.process.file.full_path": "ParentImage",
            "principal.process.command_line": "ParentCommandLine",
            "target.process.pid": "ProcessId",
            "principal.user.userid": "User",
            "principal.hostname": "ComputerName",
            "principal.ip": "SourceIP",
            "target.ip": "DestinationIP",
            "principal.port": "SourcePort",
            "target.port": "DestinationPort",
            "target.file.full_path": "TargetFilename",
            "target.file.sha256": "FileHash",
            "metadata.product_event_type": "EventID",
            "metadata.event_type": "EventType",
            "network.ip_protocol": "Protocol",
        }
        return mappings.get(field, field.split(".")[-1])


class SigmaToCQL(FromSigmaConverter):
    """Convert Sigma to Chronicle Query Language (CQL)."""

    def convert(self, sigma: SigmaRule) -> str:
        lines = []

        # Start with events source
        lines.append("events")

        # Add event type filter based on logsource
        category = sigma.logsource.get("category", "")
        event_type = self._get_event_type(category)
        if event_type:
            lines.append(f'| filter metadata.event_type = "{event_type}"')

        # Convert detection to filter statements
        detection = sigma.detection
        selection = detection.get("selection", {})

        for key, value in selection.items():
            field = key.split("|")[0]
            modifier = key.split("|")[1] if "|" in key else None
            cql_field = self._denormalize_field(field)

            if isinstance(value, list):
                # Multiple values - use regex OR pattern
                patterns = [re.escape(str(v)) for v in value]
                lines.append(f"| filter {cql_field} =~ /({'|'.join(patterns)})/")
            else:
                if modifier == "contains":
                    lines.append(f"| filter {cql_field} =~ /{re.escape(str(value))}/")
                elif modifier == "startswith":
                    lines.append(f"| filter {cql_field} =~ /^{re.escape(str(value))}/")
                elif modifier == "endswith":
                    lines.append(f"| filter {cql_field} =~ /{re.escape(str(value))}$/")
                elif modifier == "re":
                    lines.append(f"| filter {cql_field} =~ /{value}/")
                else:
                    lines.append(f'| filter {cql_field} = "{value}"')

        # Handle filter_not conditions
        filter_not = detection.get("filter_not", {})
        for key, value in filter_not.items():
            field = key.split("|")[0]
            cql_field = self._denormalize_field(field)
            lines.append(f'| filter {cql_field} != "{value}"')

        # Add aggregations if present
        if sigma.aggregations:
            for agg in sigma.aggregations:
                lines.append(f"| aggregate {agg.to_cql()}")

        # Add group by
        if sigma.group_by:
            group_fields = [self._denormalize_field(f) for f in sigma.group_by]
            lines.append(f"| group by {', '.join(group_fields)}")

        # Add time window if present
        if sigma.time_range:
            lines.append(sigma.time_range.to_cql())

        # Add limit
        if sigma.limit:
            lines.append(f"| head {sigma.limit}")

        # Add comment with rule metadata
        header = [
            f"// Rule: {sigma.title}",
            f"// Description: {sigma.description or 'Converted from Sigma'}",
            f"// Severity: {sigma.level}",
            "",
        ]

        return "\n".join(header + lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to CQL UDM paths."""
        mappings = {
            "Image": "target.process.file.full_path",
            "CommandLine": "target.process.command_line",
            "ParentImage": "principal.process.file.full_path",
            "ParentCommandLine": "principal.process.command_line",
            "ProcessId": "target.process.pid",
            "User": "principal.user.userid",
            "ComputerName": "principal.hostname",
            "SourceIP": "principal.ip",
            "DestinationIP": "target.ip",
            "SourcePort": "principal.port",
            "DestinationPort": "target.port",
            "TargetFilename": "target.file.full_path",
            "FileHash": "target.file.sha256",
            "EventID": "metadata.product_event_type",
            "EventType": "metadata.event_type",
            "Protocol": "network.ip_protocol",
        }
        return mappings.get(field, f"target.{field.lower()}")

    def _get_event_type(self, category: str) -> str:
        """Map Sigma logsource category to CQL event type."""
        mapping = {
            "process_creation": "PROCESS_LAUNCH",
            "network_connection": "NETWORK_CONNECTION",
            "file_event": "FILE_CREATION",
            "file_creation": "FILE_CREATION",
            "file_delete": "FILE_DELETION",
            "registry_event": "REGISTRY_MODIFICATION",
            "dns": "NETWORK_DNS",
            "web": "NETWORK_HTTP",
            "authentication": "USER_LOGIN",
        }
        return mapping.get(category, "GENERIC_EVENT")


# =============================================================================
# Main Conversion Service
# =============================================================================


class MigrationService:
    """Main service for converting detection rules between SIEM formats."""

    def __init__(self):
        # Converters TO Sigma
        self._to_sigma: dict[SIEMFormat, ToSigmaConverter] = {
            SIEMFormat.SPL: SPLToSigma(),
            SIEMFormat.YARAL: YARALToSigma(),
            SIEMFormat.AQL: AQLToSigma(),
            SIEMFormat.KQL: KQLToSigma(),
            SIEMFormat.EQL: EQLToSigma(),
            SIEMFormat.ESQL: ESQLToSigma(),
            SIEMFormat.PANTHER: PantherToSigma(),
            SIEMFormat.SQL: SQLToSigma(),
            SIEMFormat.CQL: CQLToSigma(),
        }

        # Converters FROM Sigma
        self._from_sigma: dict[SIEMFormat, FromSigmaConverter] = {
            SIEMFormat.SPL: SigmaToSPL(),
            SIEMFormat.YARAL: SigmaToYARAL(),
            SIEMFormat.AQL: SigmaToAQL(),
            SIEMFormat.KQL: SigmaToKQL(),
            SIEMFormat.EQL: SigmaToEQL(),
            SIEMFormat.ESQL: SigmaToESQL(),
            SIEMFormat.PANTHER: SigmaToPanther(),
            SIEMFormat.SQL: SigmaToSQL(),
            SIEMFormat.CQL: SigmaToCQL(),
        }

    def convert(
        self,
        source_code: str,
        source_format: SIEMFormat,
        target_format: SIEMFormat,
    ) -> str:
        """
        Convert detection rule from source format to target format.

        Uses Sigma as intermediate format:
        Source → Sigma → Target
        """
        if source_format == target_format:
            return source_code

        # If source is already Sigma, just convert to target
        if source_format == SIEMFormat.SIGMA:
            sigma_rule = SigmaRule.from_yaml(source_code)
        else:
            # Convert source to Sigma first
            if source_format not in self._to_sigma:
                raise ValueError(f"Unsupported source format: {source_format}")
            sigma_rule = self._to_sigma[source_format].convert(source_code)

        # If target is Sigma, return YAML
        if target_format == SIEMFormat.SIGMA:
            return sigma_rule.to_yaml()

        # Convert Sigma to target
        if target_format not in self._from_sigma:
            raise ValueError(f"Unsupported target format: {target_format}")

        return self._from_sigma[target_format].convert(sigma_rule)

    def get_supported_formats(self) -> list[dict]:
        """Return list of supported formats with metadata."""
        return [
            {"id": "sigma", "name": "Sigma", "description": "Universal detection format"},
            {"id": "spl", "name": "SPL", "description": "Splunk"},
            {"id": "yaral", "name": "YARA-L", "description": "Google SecOps / Chronicle (Rules)"},
            {"id": "cql", "name": "CQL", "description": "Google Chronicle (Query)"},
            {"id": "aql", "name": "AQL", "description": "IBM QRadar"},
            {"id": "kql", "name": "KQL", "description": "Microsoft Sentinel"},
            {"id": "eql", "name": "EQL", "description": "Elastic Security"},
            {"id": "esql", "name": "ES|QL", "description": "Elastic (new)"},
            {"id": "panther", "name": "Python", "description": "Panther SIEM"},
            {"id": "sql", "name": "SQL", "description": "Standard SQL"},
        ]


# Singleton instance
migration_service = MigrationService()
