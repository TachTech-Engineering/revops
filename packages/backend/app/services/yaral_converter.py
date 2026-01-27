"""Service for Google SecOps YARA-L to Panther rule conversion.

Converts YARA-L detection rules into Panther Python detection rules.
YARA-L is the detection language used by Google Chronicle/SecOps.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class RuleType(Enum):
    STREAMING = "streaming"
    SCHEDULED = "scheduled"


@dataclass
class YARALParseResult:
    """Parsed YARA-L rule components."""
    rule_name: str = ""
    meta: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    match_section: list = field(default_factory=list)
    outcome_section: dict = field(default_factory=dict)
    condition: str = ""
    options: dict = field(default_factory=dict)

    # Inferred properties
    log_types: list = field(default_factory=list)
    is_multi_event: bool = False
    recommended_type: RuleType = RuleType.STREAMING


@dataclass
class YARALConversionResult:
    """Result of YARA-L to Panther conversion."""
    source_code: str
    rule_id: str
    class_name: str
    log_types: list
    severity: str
    is_threshold_rule: bool
    threshold: Optional[int]
    todos: list
    test_code: str
    recommended_type: RuleType
    recommendation_reasons: list


class YARALConverter:
    """Converts YARA-L rules to Panther Python rules."""

    # Map YARA-L severity to Panther severity
    SEVERITY_MAP = {
        "INFORMATIONAL": "INFO",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }

    # Map common YARA-L event types to Panther log types
    EVENT_TYPE_MAP = {
        "network": "AWS.VPCFlow",
        "dns": "AWS.Route53",
        "http": "AWS.ALB",
        "process": "CrowdStrike.ProcessRollup2",
        "file": "CrowdStrike.FileWritten",
        "auth": "Okta.SystemLog",
        "user": "Okta.SystemLog",
        "cloud": "AWS.CloudTrail",
        "gcp": "GCP.AuditLog",
        "aws": "AWS.CloudTrail",
        "azure": "Azure.AuditLog",
    }

    def parse_yaral(self, yaral: str) -> YARALParseResult:
        """Parse a YARA-L rule into components."""
        result = YARALParseResult()

        # Clean input
        yaral = yaral.strip()

        # Extract rule name
        rule_match = re.search(r'rule\s+(\w+)\s*\{', yaral, re.IGNORECASE)
        if rule_match:
            result.rule_name = rule_match.group(1)

        # Extract meta section
        meta_match = re.search(r'meta:\s*\n(.*?)(?=\n\s*(?:events|match|condition|outcome|options):|\Z)',
                               yaral, re.DOTALL | re.IGNORECASE)
        if meta_match:
            result.meta = self._parse_meta(meta_match.group(1))

        # Extract events section
        events_match = re.search(r'events:\s*\n(.*?)(?=\n\s*(?:match|condition|outcome|options):|\}?\s*\Z)',
                                 yaral, re.DOTALL | re.IGNORECASE)
        if events_match:
            result.events = self._parse_events(events_match.group(1))
            result.is_multi_event = len(result.events) > 1

        # Extract match section (for multi-event correlation)
        match_match = re.search(r'match:\s*\n(.*?)(?=\n\s*(?:condition|outcome|options):|\}?\s*\Z)',
                                yaral, re.DOTALL | re.IGNORECASE)
        if match_match:
            result.match_section = self._parse_match(match_match.group(1))

        # Extract condition section
        condition_match = re.search(r'condition:\s*\n(.*?)(?=\n\s*(?:outcome|options):|\}?\s*\Z)',
                                    yaral, re.DOTALL | re.IGNORECASE)
        if condition_match:
            result.condition = condition_match.group(1).strip()

        # Extract outcome section
        outcome_match = re.search(r'outcome:\s*\n(.*?)(?=\n\s*options:|\}?\s*\Z)',
                                  yaral, re.DOTALL | re.IGNORECASE)
        if outcome_match:
            result.outcome_section = self._parse_outcome(outcome_match.group(1))

        # Extract options section
        options_match = re.search(r'options:\s*\n(.*?)(?=\}?\s*\Z)',
                                  yaral, re.DOTALL | re.IGNORECASE)
        if options_match:
            result.options = self._parse_options(options_match.group(1))

        # Infer log types from events
        result.log_types = self._infer_log_types(result.events, result.meta)

        # Determine rule type
        if result.is_multi_event or result.match_section:
            result.recommended_type = RuleType.SCHEDULED

        return result

    def _parse_meta(self, meta_text: str) -> dict:
        """Parse meta section key-value pairs."""
        meta = {}
        for line in meta_text.strip().split('\n'):
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                meta[key] = value
        return meta

    def _parse_events(self, events_text: str) -> list:
        """Parse events section."""
        events = []
        current_event = {}

        for line in events_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Event variable declaration: $event.metadata.event_type = "NETWORK_CONNECTION"
            var_match = re.match(r'\$(\w+)\.(\S+)\s*=\s*(.+)', line)
            if var_match:
                var_name = var_match.group(1)
                field_path = var_match.group(2)
                value = var_match.group(3).strip('"').strip("'")

                if not current_event or current_event.get('name') != var_name:
                    if current_event:
                        events.append(current_event)
                    current_event = {'name': var_name, 'conditions': []}

                current_event['conditions'].append({
                    'field': field_path,
                    'value': value,
                    'raw': line,
                })
            else:
                # Other condition lines
                if current_event:
                    current_event['conditions'].append({'raw': line})

        if current_event:
            events.append(current_event)

        return events

    def _parse_match(self, match_text: str) -> list:
        """Parse match section for multi-event correlation."""
        matches = []
        for line in match_text.strip().split('\n'):
            line = line.strip()
            if line:
                matches.append(line)
        return matches

    def _parse_outcome(self, outcome_text: str) -> dict:
        """Parse outcome section."""
        outcome = {}
        for line in outcome_text.strip().split('\n'):
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                outcome[key.strip().strip('$')] = value.strip()
        return outcome

    def _parse_options(self, options_text: str) -> dict:
        """Parse options section."""
        options = {}
        for line in options_text.strip().split('\n'):
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                options[key.strip()] = value.strip()
        return options

    def _infer_log_types(self, events: list, meta: dict) -> list:
        """Infer Panther log types from YARA-L events."""
        log_types = set()

        # Check meta for data source hints
        data_source = meta.get('data_source', '').lower()
        for key, log_type in self.EVENT_TYPE_MAP.items():
            if key in data_source:
                log_types.add(log_type)

        # Check event conditions for type hints
        for event in events:
            for condition in event.get('conditions', []):
                field = condition.get('field', '').lower()
                value = condition.get('value', '').lower()

                if 'event_type' in field:
                    for key, log_type in self.EVENT_TYPE_MAP.items():
                        if key in value:
                            log_types.add(log_type)

                if 'product_name' in field or 'vendor_name' in field:
                    if 'crowdstrike' in value:
                        log_types.add('CrowdStrike.ProcessRollup2')
                    elif 'okta' in value:
                        log_types.add('Okta.SystemLog')
                    elif 'aws' in value:
                        log_types.add('AWS.CloudTrail')

        return list(log_types) if log_types else ['Custom.LogType']

    def convert(
        self,
        yaral: str,
        rule_id: str,
        class_name: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> YARALConversionResult:
        """Convert YARA-L rule to Panther Python rule."""
        parsed = self.parse_yaral(yaral)

        # Generate class name
        if not class_name:
            if parsed.rule_name:
                class_name = self._to_class_name(parsed.rule_name)
            else:
                class_name = self._to_class_name(rule_id)

        # Determine severity
        if not severity:
            meta_severity = parsed.meta.get('severity', 'MEDIUM').upper()
            severity = self.SEVERITY_MAP.get(meta_severity, 'MEDIUM')

        # Build the Python rule
        todos = []
        source_code = self._generate_python_rule(parsed, rule_id, class_name, severity, todos)
        test_code = self._generate_test_code(parsed, class_name)

        # Determine if threshold rule
        is_threshold = parsed.is_multi_event or '#' in parsed.condition

        recommendation_reasons = []
        if parsed.is_multi_event:
            recommendation_reasons.append("Multi-event correlation detected - consider scheduled rule")
        if parsed.match_section:
            recommendation_reasons.append("Match section for event correlation - requires scheduled rule")

        return YARALConversionResult(
            source_code=source_code,
            rule_id=rule_id,
            class_name=class_name,
            log_types=parsed.log_types,
            severity=severity,
            is_threshold_rule=is_threshold,
            threshold=None,
            todos=todos,
            test_code=test_code,
            recommended_type=parsed.recommended_type,
            recommendation_reasons=recommendation_reasons,
        )

    def _to_class_name(self, name: str) -> str:
        """Convert a name to PascalCase class name."""
        # Remove special characters and split
        parts = re.split(r'[_\-\s]+', name)
        return ''.join(word.capitalize() for word in parts if word)

    def _generate_python_rule(
        self,
        parsed: YARALParseResult,
        rule_id: str,
        class_name: str,
        severity: str,
        todos: list,
    ) -> str:
        """Generate Panther Python rule code."""
        lines = [
            '"""',
            f'Panther Rule: {rule_id}',
            f'Converted from YARA-L rule: {parsed.rule_name}',
        ]

        # Add meta description if available
        if parsed.meta.get('description'):
            lines.append(f'\nDescription: {parsed.meta["description"]}')
        if parsed.meta.get('author'):
            lines.append(f'Author: {parsed.meta["author"]}')
        if parsed.meta.get('reference'):
            lines.append(f'Reference: {parsed.meta["reference"]}')

        lines.extend([
            '"""',
            '',
        ])

        # Generate the rule function
        lines.extend([
            f'def rule(event):',
            f'    """',
            f'    {parsed.meta.get("description", "Detection rule converted from YARA-L")}',
            f'    """',
        ])

        # Convert event conditions to Python
        conditions = self._convert_conditions_to_python(parsed, todos)
        if conditions:
            for condition in conditions:
                lines.append(f'    {condition}')
        else:
            lines.append('    # TODO: Add detection logic based on YARA-L conditions')
            todos.append('Add detection logic based on original YARA-L conditions')
            lines.append('    return True')

        lines.append('')

        # Add title function
        title = parsed.meta.get('description', parsed.rule_name or rule_id)
        lines.extend([
            '',
            'def title(event):',
            f'    return "{title}"',
            '',
        ])

        # Add severity function
        lines.extend([
            '',
            'def severity(event):',
            f'    return "{severity}"',
            '',
        ])

        # Add alert context
        lines.extend([
            '',
            'def alert_context(event):',
            '    return {',
        ])

        # Include relevant fields in context
        context_fields = self._get_context_fields(parsed)
        for field in context_fields:
            lines.append(f'        "{field}": event.deep_get("{field}"),')

        lines.extend([
            '    }',
            '',
        ])

        return '\n'.join(lines)

    def _convert_conditions_to_python(self, parsed: YARALParseResult, todos: list) -> list:
        """Convert YARA-L conditions to Python code."""
        python_lines = []

        for event in parsed.events:
            for condition in event.get('conditions', []):
                raw = condition.get('raw', '')
                field = condition.get('field', '')
                value = condition.get('value', '')

                if field and value:
                    # Convert field path to deep_get
                    python_field = self._convert_field_path(field)

                    # Handle different comparison types
                    if '!=' in raw or 'nocase' in raw.lower():
                        python_lines.append(f'# {raw}')
                        python_lines.append(f'if event.deep_get("{python_field}") != "{value}":')
                        python_lines.append(f'    return False')
                    elif 'regex' in raw.lower() or re.search(r'/.*/', value):
                        python_lines.append(f'# {raw}')
                        pattern = value.strip('/')
                        python_lines.append(f'import re')
                        python_lines.append(f'if not re.search(r"{pattern}", str(event.deep_get("{python_field}", "")), re.IGNORECASE):')
                        python_lines.append(f'    return False')
                        todos.append(f'Verify regex pattern: {pattern}')
                    else:
                        python_lines.append(f'# {raw}')
                        python_lines.append(f'if event.deep_get("{python_field}") != "{value}":')
                        python_lines.append(f'    return False')
                elif raw:
                    # Complex condition - add as comment
                    python_lines.append(f'# TODO: Convert YARA-L condition: {raw}')
                    todos.append(f'Convert YARA-L condition: {raw}')

        if python_lines:
            python_lines.append('')
            python_lines.append('return True')

        return python_lines

    def _convert_field_path(self, yaral_path: str) -> str:
        """Convert YARA-L field path to Panther event path."""
        # Remove leading metadata/principal/target prefixes common in YARA-L
        path = re.sub(r'^(metadata|principal|target|src|network|about)\.', '', yaral_path)
        # Convert to dot notation compatible with deep_get
        return path.replace('_', '.')

    def _get_context_fields(self, parsed: YARALParseResult) -> list:
        """Get relevant fields for alert context."""
        fields = set()

        # Common useful fields
        fields.add('sourceIPAddress')
        fields.add('userIdentity.userName')
        fields.add('eventName')

        # Add fields from events
        for event in parsed.events:
            for condition in event.get('conditions', []):
                field = condition.get('field', '')
                if field:
                    python_field = self._convert_field_path(field)
                    fields.add(python_field)

        return list(fields)[:10]  # Limit to 10 fields

    def _generate_test_code(self, parsed: YARALParseResult, class_name: str) -> str:
        """Generate test code for the rule."""
        lines = [
            '"""',
            f'Unit tests for {class_name}',
            '"""',
            'from unittest.mock import MagicMock',
            '',
            '',
            'def test_rule_matches():',
            '    """Test that rule matches expected event."""',
            '    event = MagicMock()',
            '    event.deep_get = lambda path, default=None: {',
        ]

        # Add expected values from conditions
        for event in parsed.events:
            for condition in event.get('conditions', []):
                field = condition.get('field', '')
                value = condition.get('value', '')
                if field and value:
                    python_field = self._convert_field_path(field)
                    lines.append(f'        "{python_field}": "{value}",')

        lines.extend([
            '    }.get(path, default)',
            '',
            '    assert rule(event) is True',
            '',
            '',
            'def test_rule_no_match():',
            '    """Test that rule does not match non-matching event."""',
            '    event = MagicMock()',
            '    event.deep_get = lambda path, default=None: default',
            '',
            '    assert rule(event) is False',
            '',
        ])

        return '\n'.join(lines)


# Singleton instance
yaral_converter = YARALConverter()
