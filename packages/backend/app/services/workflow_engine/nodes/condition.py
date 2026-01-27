"""
Condition Node Executor

Evaluates conditions and routes execution to true/false branches.
"""

import operator
from typing import Any

from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.context import ExecutionContext


class ConditionExecutor(NodeExecutor):
    """
    Evaluates conditions and determines branch flow.

    Config:
    - conditions: List of condition groups (AND within group, OR between groups)
    - each condition: {field, operator, value}

    Operators:
    - eq, ne: Equal, not equal
    - gt, gte, lt, lte: Greater/less than
    - contains, not_contains: String/list contains
    - starts_with, ends_with: String prefix/suffix
    - is_empty, is_not_empty: Check for empty value
    - matches: Regex match
    """

    OPERATORS = {
        "eq": operator.eq,
        "ne": operator.ne,
        "gt": operator.gt,
        "gte": operator.ge,
        "lt": operator.lt,
        "lte": operator.le,
    }

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Evaluate condition and return branch handle."""
        try:
            conditions = self.config.get("conditions", [])
            if not conditions:
                # No conditions = true
                return NodeResult(
                    success=True,
                    output={"result": True},
                    next_handle="true",
                )

            # Evaluate condition groups (OR between groups)
            result = self._evaluate_groups(conditions, context.to_template_context())

            return NodeResult(
                success=True,
                output={"result": result, "evaluated_conditions": conditions},
                next_handle="true" if result else "false",
            )

        except Exception as e:
            return NodeResult(
                success=False,
                error=f"Condition evaluation error: {str(e)}",
            )

    def _evaluate_groups(self, groups: list, template_context: dict) -> bool:
        """Evaluate condition groups (OR logic between groups)."""
        for group in groups:
            if isinstance(group, list):
                # AND within group
                if all(self._evaluate_condition(cond, template_context) for cond in group):
                    return True
            else:
                # Single condition
                if self._evaluate_condition(group, template_context):
                    return True
        return False

    def _evaluate_condition(self, condition: dict, template_context: dict) -> bool:
        """Evaluate a single condition."""
        field_path = condition.get("field", "")
        op = condition.get("operator", "eq")
        expected = condition.get("value")

        # Get actual value from context
        actual = self._get_nested_value(template_context, field_path)

        # Type coercion
        if expected is not None and actual is not None:
            try:
                if isinstance(expected, bool):
                    actual = bool(actual)
                elif isinstance(expected, int) and not isinstance(expected, bool):
                    actual = int(actual)
                elif isinstance(expected, float):
                    actual = float(actual)
            except (ValueError, TypeError):
                pass

        # Evaluate based on operator
        if op in self.OPERATORS:
            try:
                return self.OPERATORS[op](actual, expected)
            except TypeError:
                return False

        elif op == "contains":
            if isinstance(actual, str):
                return str(expected) in actual
            elif isinstance(actual, (list, tuple)):
                return expected in actual
            return False

        elif op == "not_contains":
            if isinstance(actual, str):
                return str(expected) not in actual
            elif isinstance(actual, (list, tuple)):
                return expected not in actual
            return True

        elif op == "starts_with":
            return str(actual).startswith(str(expected))

        elif op == "ends_with":
            return str(actual).endswith(str(expected))

        elif op == "is_empty":
            return actual is None or actual == "" or actual == [] or actual == {}

        elif op == "is_not_empty":
            return actual is not None and actual != "" and actual != [] and actual != {}

        elif op == "matches":
            import re
            try:
                return bool(re.match(str(expected), str(actual)))
            except re.error:
                return False

        elif op == "in":
            return actual in expected if isinstance(expected, (list, tuple)) else False

        elif op == "not_in":
            return actual not in expected if isinstance(expected, (list, tuple)) else True

        return False

    def _get_nested_value(self, data: dict, path: str) -> Any:
        """Get a nested value using dot notation."""
        parts = path.split(".")
        value = data
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif isinstance(value, list):
                try:
                    value = value[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            if value is None:
                return None
        return value
