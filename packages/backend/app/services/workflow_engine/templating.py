"""
Template Resolver

Resolves template variables in workflow configurations.

Syntax:
- {{trigger.alert.severity}} - Access trigger data
- {{steps.step_1.output.body}} - Access step output
- {{variables.my_var}} - Access workflow variables
- {{loop.item}} - Current loop item
- {{loop.index}} - Current loop index
"""

import re
import json
from typing import Any


class TemplateResolver:
    """
    Resolves Jinja-like template variables in workflow node configurations.
    """

    # Pattern to match {{variable.path}} with optional filters
    TEMPLATE_PATTERN = re.compile(r'\{\{\s*([^}|]+?)(?:\s*\|\s*(\w+))?\s*\}\}')

    def __init__(self, context: dict[str, Any]):
        """
        Initialize with execution context.

        Args:
            context: Dictionary containing trigger, steps, variables, and loop data
        """
        self.context = context

    def resolve(self, template: Any) -> Any:
        """
        Resolve template variables in any value.

        Handles:
        - Strings with {{variable}} syntax
        - Dictionaries (recursive)
        - Lists (recursive)
        - Other types (returned as-is)
        """
        if isinstance(template, str):
            return self._resolve_string(template)
        elif isinstance(template, dict):
            return {k: self.resolve(v) for k, v in template.items()}
        elif isinstance(template, list):
            return [self.resolve(item) for item in template]
        else:
            return template

    def _resolve_string(self, template: str) -> Any:
        """Resolve template variables in a string."""
        # Check if the entire string is a single template expression
        match = self.TEMPLATE_PATTERN.fullmatch(template.strip())
        if match:
            # Return the raw value (preserves type)
            value = self._get_value(match.group(1).strip())
            filter_name = match.group(2)
            if filter_name:
                value = self._apply_filter(value, filter_name)
            return value

        # Otherwise, do string substitution
        def replace_match(match: re.Match) -> str:
            path = match.group(1).strip()
            filter_name = match.group(2)
            value = self._get_value(path)
            if filter_name:
                value = self._apply_filter(value, filter_name)
            return self._to_string(value)

        return self.TEMPLATE_PATTERN.sub(replace_match, template)

    def _get_value(self, path: str) -> Any:
        """
        Get a value from the context using dot notation.

        Examples:
        - "trigger.alert.severity" -> context["trigger"]["alert"]["severity"]
        - "steps.step_1.output.body" -> context["steps"]["step_1"]["body"]
        """
        parts = path.split('.')
        value = self.context

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif isinstance(value, list):
                try:
                    index = int(part)
                    value = value[index]
                except (ValueError, IndexError):
                    return None
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return None

            if value is None:
                return None

        return value

    def _apply_filter(self, value: Any, filter_name: str) -> Any:
        """Apply a filter transformation to a value."""
        filters = {
            'json': lambda v: json.dumps(v) if not isinstance(v, str) else v,
            'upper': lambda v: str(v).upper(),
            'lower': lambda v: str(v).lower(),
            'strip': lambda v: str(v).strip(),
            'int': lambda v: int(v) if v is not None else 0,
            'float': lambda v: float(v) if v is not None else 0.0,
            'bool': lambda v: bool(v),
            'str': lambda v: str(v) if v is not None else '',
            'len': lambda v: len(v) if hasattr(v, '__len__') else 0,
            'keys': lambda v: list(v.keys()) if isinstance(v, dict) else [],
            'values': lambda v: list(v.values()) if isinstance(v, dict) else [],
            'first': lambda v: v[0] if v and hasattr(v, '__getitem__') else None,
            'last': lambda v: v[-1] if v and hasattr(v, '__getitem__') else None,
            'default': lambda v: v if v is not None else '',
        }

        filter_func = filters.get(filter_name)
        if filter_func:
            try:
                return filter_func(value)
            except Exception:
                return value
        return value

    def _to_string(self, value: Any) -> str:
        """Convert a value to string for template substitution."""
        if value is None:
            return ''
        elif isinstance(value, (dict, list)):
            return json.dumps(value)
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        else:
            return str(value)


def resolve_templates(config: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """
    Convenience function to resolve all templates in a configuration dict.

    Args:
        config: Configuration dictionary with template variables
        context: Execution context for variable resolution

    Returns:
        Configuration with all templates resolved
    """
    resolver = TemplateResolver(context)
    return resolver.resolve(config)
