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
import json
import yaml
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class SIEMFormat(str, Enum):
    SIGMA = "sigma"
    SPL = "spl"
    YARAL = "yaral"
    KQL = "kql"
    EQL = "eql"
    ESQL = "esql"
    PANTHER = "panther"


@dataclass
class SigmaRule:
    """Intermediate Sigma representation for conversions."""
    title: str = "Converted Rule"
    status: str = "experimental"
    description: str = ""
    author: str = "Migration Tool"
    logsource: dict = field(default_factory=lambda: {"category": "process_creation", "product": "windows"})
    detection: dict = field(default_factory=dict)
    fields: list = field(default_factory=list)
    falsepositives: list = field(default_factory=list)
    level: str = "medium"
    tags: list = field(default_factory=list)

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
        index_match = re.search(r'index\s*=\s*(\w+)', source, re.IGNORECASE)
        sourcetype_match = re.search(r'sourcetype\s*=\s*([^\s|]+)', source, re.IGNORECASE)

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
        where_matches = re.findall(r'\|\s*where\s+(.+?)(?=\||$)', source, re.IGNORECASE)
        for i, where_clause in enumerate(where_matches):
            field_match = re.search(r'(\w+)\s*(?:like|contains|=|==)\s*["\']?([^"\'|]+)["\']?', where_clause, re.IGNORECASE)
            if field_match:
                field_name = self._normalize_field(field_match.group(1))
                value = field_match.group(2).strip().strip('%').strip('*')

                if "like" in where_clause.lower() or "%" in field_match.group(2) or "*" in field_match.group(2):
                    detection["selection"][f"{field_name}|contains"] = value
                else:
                    detection["selection"][field_name] = value

        # Parse search terms (field=value patterns)
        field_patterns = re.findall(r'(\w+)\s*=\s*["\']?([^"\'\s|]+)["\']?', source)
        for field, value in field_patterns:
            if field.lower() not in ['index', 'sourcetype', 'source']:
                normalized = self._normalize_field(field)
                if value.startswith('*') or value.endswith('*'):
                    detection["selection"][f"{normalized}|contains"] = value.strip('*')
                else:
                    detection["selection"][normalized] = value

        sigma.detection = detection

        # Extract fields from table command
        table_match = re.search(r'\|\s*table\s+(.+?)(?=\||$)', source, re.IGNORECASE)
        if table_match:
            sigma.fields = [f.strip() for f in table_match.group(1).split(',')]

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
            lines.append('index=windows sourcetype=WinEventLog:Security')
        elif product == "linux":
            lines.append('index=linux sourcetype=syslog')
        else:
            lines.append(f'index=main sourcetype={product}')

        # Add EventCode if process creation
        if category == "process_creation" and product == "windows":
            lines.append('EventCode=4688')

        # Convert detection to where clauses
        detection = sigma.detection
        selection = detection.get("selection", {})

        where_clauses = []
        for key, value in selection.items():
            field = self._denormalize_field(key.split('|')[0])
            modifier = key.split('|')[1] if '|' in key else None

            if isinstance(value, list):
                conditions = []
                for v in value:
                    if modifier in ['contains', 'startswith', 'endswith']:
                        conditions.append(f'like({field}, "%{v}%")')
                    else:
                        conditions.append(f'{field}="{v}"')
                where_clauses.append(f'({" OR ".join(conditions)})')
            else:
                if modifier == 'contains':
                    where_clauses.append(f'like({field}, "%{value}%")')
                elif modifier == 'startswith':
                    where_clauses.append(f'like({field}, "{value}%")')
                elif modifier == 'endswith':
                    where_clauses.append(f'like({field}, "%{value}")')
                else:
                    where_clauses.append(f'{field}="{value}"')

        for clause in where_clauses:
            lines.append(f'| where {clause}')

        # Add table output
        fields = sigma.fields or ['_time', 'ComputerName', 'User', 'CommandLine']
        lines.append(f'| table {", ".join(fields)}')

        return '\n'.join(lines)

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
        name_match = re.search(r'rule\s+(\w+)', source)
        if name_match:
            sigma.title = name_match.group(1).replace('_', ' ').title()

        # Extract meta section
        meta_match = re.search(r'meta:\s*(.+?)(?=events:|condition:|$)', source, re.DOTALL)
        if meta_match:
            meta_content = meta_match.group(1)
            author_match = re.search(r'author\s*=\s*["\']([^"\']+)["\']', meta_content)
            desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', meta_content)
            if author_match:
                sigma.author = author_match.group(1)
            if desc_match:
                sigma.description = desc_match.group(1)

        # Extract events section and build detection
        events_match = re.search(r'events:\s*(.+?)(?=condition:|match:|outcome:|$)', source, re.DOTALL)
        detection = {"selection": {}, "condition": "selection"}

        if events_match:
            events_content = events_match.group(1)
            # Parse field comparisons
            comparisons = re.findall(r'\$\w+\.([a-z_.]+)\s*(?:=|!=)\s*(?:/([^/]+)/|["\']([^"\']+)["\'])', events_content, re.IGNORECASE)
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
        return mappings.get(field_path, field_path.split('.')[-1])


class SigmaToYARAL(FromSigmaConverter):
    """Convert Sigma to YARA-L."""

    def convert(self, sigma: SigmaRule) -> str:
        rule_name = re.sub(r'[^a-z0-9_]', '_', sigma.title.lower())

        lines = [
            f'rule {rule_name} {{',
            '  meta:',
            f'    author = "{sigma.author}"',
            f'    description = "{sigma.description or sigma.title}"',
            f'    severity = "{self._map_severity(sigma.level)}"',
            '',
            '  events:',
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
            field = key.split('|')[0]
            modifier = key.split('|')[1] if '|' in key else None
            yaral_field = self._denormalize_field(field)

            if isinstance(value, list):
                regex_parts = [re.escape(str(v)) for v in value]
                event_conditions.append(f'{event_var}.{yaral_field} = /({"|".join(regex_parts)})/')
            else:
                if modifier == 'contains':
                    event_conditions.append(f'{event_var}.{yaral_field} = /{re.escape(str(value))}/')
                elif modifier == 'startswith':
                    event_conditions.append(f'{event_var}.{yaral_field} = /^{re.escape(str(value))}/')
                elif modifier == 'endswith':
                    event_conditions.append(f'{event_var}.{yaral_field} = /{re.escape(str(value))}$/')
                elif modifier == 're':
                    event_conditions.append(f'{event_var}.{yaral_field} = /{value}/')
                else:
                    event_conditions.append(f'{event_var}.{yaral_field} = "{value}"')

        for condition in event_conditions:
            lines.append(f'    {condition}')

        lines.extend([
            '',
            '  condition:',
            f'    {event_var}',
            '}',
        ])

        return '\n'.join(lines)

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
        table_match = re.match(r'^(\w+)', source.strip())
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

        where_matches = re.findall(r'\|\s*where\s+(.+?)(?=\||$)', source, re.IGNORECASE)
        for where_clause in where_matches:
            # Parse field conditions
            conditions = re.findall(r'(\w+)\s*(==|!=|contains|endswith|startswith|has)\s*["\']?([^"\'\s|]+)["\']?', where_clause, re.IGNORECASE)
            for field, operator, value in conditions:
                normalized = self._normalize_field(field)
                if operator.lower() == 'contains' or operator.lower() == 'has':
                    detection["selection"][f"{normalized}|contains"] = value
                elif operator.lower() == 'startswith':
                    detection["selection"][f"{normalized}|startswith"] = value
                elif operator.lower() == 'endswith':
                    detection["selection"][f"{normalized}|endswith"] = value
                else:
                    detection["selection"][normalized] = value

        sigma.detection = detection

        # Extract fields from project
        project_match = re.search(r'\|\s*project\s+(.+?)(?=\||$)', source, re.IGNORECASE)
        if project_match:
            sigma.fields = [f.strip() for f in project_match.group(1).split(',')]

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
            field = key.split('|')[0]
            modifier = key.split('|')[1] if '|' in key else None
            kql_field = self._denormalize_field(field)

            if isinstance(value, list):
                conditions = []
                for v in value:
                    if modifier == 'contains':
                        conditions.append(f'{kql_field} contains "{v}"')
                    else:
                        conditions.append(f'{kql_field} == "{v}"')
                lines.append(f'| where ({" or ".join(conditions)})')
            else:
                if modifier == 'contains':
                    lines.append(f'| where {kql_field} contains "{value}"')
                elif modifier == 'startswith':
                    lines.append(f'| where {kql_field} startswith "{value}"')
                elif modifier == 'endswith':
                    lines.append(f'| where {kql_field} endswith "{value}"')
                else:
                    lines.append(f'| where {kql_field} == "{value}"')

        # Add project
        fields = sigma.fields or ['TimeGenerated', 'Computer', 'Account', 'NewProcessName', 'CommandLine']
        lines.append(f'| project {", ".join(fields)}')

        return '\n'.join(lines)

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
        event_match = re.match(r'(\w+)\s+where', source.strip())
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
        where_match = re.search(r'where\s+(.+)', source, re.DOTALL)
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
                if value.startswith('*') and value.endswith('*'):
                    detection["selection"][f"{normalized}|contains"] = value.strip('*')
                elif value.startswith('*'):
                    detection["selection"][f"{normalized}|endswith"] = value.lstrip('*')
                elif value.endswith('*'):
                    detection["selection"][f"{normalized}|startswith"] = value.rstrip('*')
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
        return mappings.get(field, field.split('.')[-1])


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
            field = key.split('|')[0]
            modifier = key.split('|')[1] if '|' in key else None
            eql_field = self._denormalize_field(field)

            if isinstance(value, list):
                value_conditions = []
                for v in value:
                    if modifier == 'contains':
                        value_conditions.append(f'{eql_field} : "*{v}*"')
                    else:
                        value_conditions.append(f'{eql_field} == "{v}"')
                conditions.append(f'({" or ".join(value_conditions)})')
            else:
                if modifier == 'contains':
                    conditions.append(f'{eql_field} : "*{value}*"')
                elif modifier == 'startswith':
                    conditions.append(f'{eql_field} : "{value}*"')
                elif modifier == 'endswith':
                    conditions.append(f'{eql_field} : "*{value}"')
                else:
                    conditions.append(f'{eql_field} == "{value}"')

        condition_str = " and ".join(conditions) if conditions else "true"
        return f'{event_type} where {condition_str}'

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
        from_match = re.search(r'FROM\s+([^\s|]+)', source, re.IGNORECASE)
        if from_match:
            index = from_match.group(1)
            if "windows" in index.lower():
                sigma.logsource = {"category": "process_creation", "product": "windows"}
            elif "linux" in index.lower():
                sigma.logsource = {"category": "process_creation", "product": "linux"}

        # Parse WHERE clause
        detection = {"selection": {}, "condition": "selection"}

        where_match = re.search(r'WHERE\s+(.+?)(?=\||$)', source, re.IGNORECASE | re.DOTALL)
        if where_match:
            where_clause = where_match.group(1)

            # Parse field == value
            eq_matches = re.findall(r'([\w.]+)\s*==\s*["\']([^"\']+)["\']', where_clause)
            for field, value in eq_matches:
                normalized = self._normalize_field(field)
                detection["selection"][normalized] = value

            # Parse LIKE patterns
            like_matches = re.findall(r'([\w.]+)\s+LIKE\s+["\']([^"\']+)["\']', where_clause, re.IGNORECASE)
            for field, value in like_matches:
                normalized = self._normalize_field(field)
                if value.startswith('%') and value.endswith('%'):
                    detection["selection"][f"{normalized}|contains"] = value.strip('%')
                elif value.startswith('%'):
                    detection["selection"][f"{normalized}|endswith"] = value.lstrip('%')
                elif value.endswith('%'):
                    detection["selection"][f"{normalized}|startswith"] = value.rstrip('%')

        sigma.detection = detection

        # Parse KEEP clause for fields
        keep_match = re.search(r'KEEP\s+(.+?)(?=\||$)', source, re.IGNORECASE)
        if keep_match:
            sigma.fields = [f.strip() for f in keep_match.group(1).split(',')]

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
        return mappings.get(field, field.split('.')[-1])


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
            field = key.split('|')[0]
            modifier = key.split('|')[1] if '|' in key else None
            esql_field = self._denormalize_field(field)

            if isinstance(value, list):
                value_conditions = []
                for v in value:
                    if modifier == 'contains':
                        value_conditions.append(f'{esql_field} LIKE "%{v}%"')
                    else:
                        value_conditions.append(f'{esql_field} == "{v}"')
                conditions.append(f'({" OR ".join(value_conditions)})')
            else:
                if modifier == 'contains':
                    conditions.append(f'{esql_field} LIKE "%{value}%"')
                elif modifier == 'startswith':
                    conditions.append(f'{esql_field} LIKE "{value}%"')
                elif modifier == 'endswith':
                    conditions.append(f'{esql_field} LIKE "%{value}"')
                else:
                    conditions.append(f'{esql_field} == "{value}"')

        if conditions:
            lines.append(f'| WHERE {" AND ".join(conditions)}')

        # Add KEEP
        fields = sigma.fields or ['@timestamp', 'host.name', 'user.name', 'process.name', 'process.command_line']
        lines.append(f'| KEEP {", ".join(fields)}')

        return '\n'.join(lines)

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
        title_match = re.search(r'def title\([^)]*\):\s*\n\s*return\s+[f]?["\']([^"\']+)["\']', source)
        if title_match:
            sigma.title = title_match.group(1).split('{')[0].strip()

        # Parse rule function for conditions
        # Look for event.get() calls
        get_matches = re.findall(r'event\.get\(["\']([^"\']+)["\']\s*(?:,\s*["\'][^"\']*["\'])?\)', source)

        # Look for 'in' checks (e.g., if "value" in field)
        in_matches = re.findall(r'["\']([^"\']+)["\']\s+in\s+(?:event\.get\(["\']([^"\']+)["\']|(\w+))', source)
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
        eq_matches = re.findall(r'event\.get\(["\']([^"\']+)["\']\)\s*==\s*["\']([^"\']+)["\']', source)
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
        lines = []

        # Build conditions list
        detection = sigma.detection
        selection = detection.get("selection", {})

        conditions = []
        for key, value in selection.items():
            field = key.split('|')[0]
            modifier = key.split('|')[1] if '|' in key else None
            panther_field = self._denormalize_field(field)

            if isinstance(value, list):
                value_checks = []
                for v in value:
                    if modifier == 'contains':
                        value_checks.append(f'"{v}" in event.get("{panther_field}", "")')
                    elif modifier == 'endswith':
                        value_checks.append(f'event.get("{panther_field}", "").endswith("{v}")')
                    elif modifier == 'startswith':
                        value_checks.append(f'event.get("{panther_field}", "").startswith("{v}")')
                    else:
                        value_checks.append(f'event.get("{panther_field}") == "{v}"')
                conditions.append(f'({" or ".join(value_checks)})')
            else:
                if modifier == 'contains':
                    conditions.append(f'"{value}" in event.get("{panther_field}", "").lower()')
                elif modifier == 'endswith':
                    conditions.append(f'event.get("{panther_field}", "").endswith("{value}")')
                elif modifier == 'startswith':
                    conditions.append(f'event.get("{panther_field}", "").startswith("{value}")')
                else:
                    conditions.append(f'event.get("{panther_field}") == "{value}"')

        # Generate rule function
        lines.append('def rule(event):')
        lines.append(f'    """')
        lines.append(f'    {sigma.description or sigma.title}')
        lines.append(f'    Severity: {sigma.level}')
        lines.append(f'    """')

        if conditions:
            combined = " and ".join(conditions)
            # Break long conditions across lines
            lines.append(f'    if {combined}:')
            lines.append('        return True')

        lines.append('    return False')
        lines.append('')
        lines.append('')

        # Generate title function
        safe_title = sigma.title.replace('"', '\\"')
        lines.append('def title(event):')
        lines.append(f'    return f"{safe_title} on {{event.get(\'hostname\', \'unknown\')}}"')
        lines.append('')
        lines.append('')

        # Generate severity function
        lines.append('def severity(event):')
        severity_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'informational': 'INFO'}
        panther_severity = severity_map.get(sigma.level.lower(), 'MEDIUM')
        lines.append(f'    return "{panther_severity}"')

        return '\n'.join(lines)

    def _denormalize_field(self, field: str) -> str:
        """Convert Sigma field names to Panther."""
        mappings = {
            "Image": "process_name",
            "CommandLine": "command_line",
            "ParentImage": "parent_process_name",
            "User": "user",
            "ComputerName": "hostname",
            "EventID": "event_id",
        }
        return mappings.get(field, field.lower())


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
            SIEMFormat.KQL: KQLToSigma(),
            SIEMFormat.EQL: EQLToSigma(),
            SIEMFormat.ESQL: ESQLToSigma(),
            SIEMFormat.PANTHER: PantherToSigma(),
        }

        # Converters FROM Sigma
        self._from_sigma: dict[SIEMFormat, FromSigmaConverter] = {
            SIEMFormat.SPL: SigmaToSPL(),
            SIEMFormat.YARAL: SigmaToYARAL(),
            SIEMFormat.KQL: SigmaToKQL(),
            SIEMFormat.EQL: SigmaToEQL(),
            SIEMFormat.ESQL: SigmaToESQL(),
            SIEMFormat.PANTHER: SigmaToPanther(),
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
            {"id": "yaral", "name": "YARA-L", "description": "Google SecOps / Chronicle"},
            {"id": "kql", "name": "KQL", "description": "Microsoft Sentinel"},
            {"id": "eql", "name": "EQL", "description": "Elastic Security"},
            {"id": "esql", "name": "ES|QL", "description": "Elastic (new)"},
            {"id": "panther", "name": "Python", "description": "Panther SIEM"},
        ]


# Singleton instance
migration_service = MigrationService()
