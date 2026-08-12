"""SPL to Python Transformer - Transforms SPL AST to Python code."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .analyzer import AnalysisResult
from .ast_nodes import (
    BooleanExpr,
    BooleanOperator,
    ComparisonOperator,
    EvalBinaryOp,
    EvalCase,
    EvalConditional,
    EvalExpr,
    EvalFieldRef,
    EvalFunctionCall,
    EvalLiteral,
    EvalUnaryOp,
    FieldComparison,
    FreeTextSearch,
    NotExpr,
    ParenExpr,
    SearchTerm,
)


@dataclass
class TransformResult:
    """Result of transforming SPL to Python code."""

    # Main rule condition (Python expression string)
    rule_condition: str = ""

    # Dedup method body (Python expression string)
    dedup_expression: str | None = None

    # Title method body (Python f-string)
    title_expression: str | None = None

    # Alert context fields (for alert_context method)
    alert_context_fields: list[str] = field(default_factory=list)

    # Additional helper expressions (eval results)
    helper_expressions: dict[str, str] = field(default_factory=dict)

    # Required imports
    required_imports: set[str] = field(default_factory=set)

    # Rex pattern extractions
    rex_extractions: list[tuple[str, str, str]] = field(
        default_factory=list
    )  # (field, pattern, var_name)


class SPLToPythonTransformer:
    """Transforms SPL AST to Python code strings."""

    def __init__(self, analysis: AnalysisResult) -> None:
        """
        Initialize the transformer.

        Args:
            analysis: Analysis result from SPLAnalyzer
        """
        self.analysis = analysis
        self.result = TransformResult()
        self._field_counter = 0

    def transform(self) -> TransformResult:
        """
        Transform the analyzed SPL to Python code.

        Returns:
            TransformResult with Python code strings
        """
        # Always need deep_get for nested field access
        self.result.required_imports.add("deep_get")

        # Transform search conditions to rule() condition
        if self.analysis.search_conditions:
            conditions = []
            for term in self.analysis.search_conditions:
                cond = self._transform_search_term(term)
                if cond and cond != "True":
                    conditions.append(cond)

            if conditions:
                self.result.rule_condition = self._join_conditions(conditions, "and")
            else:
                self.result.rule_condition = "True"
        else:
            self.result.rule_condition = "True"

        # Transform dedup fields
        if self.analysis.dedup_fields:
            dedup_parts = []
            for field in self.analysis.dedup_fields:
                dedup_parts.append(self._get_field_access(field))
            if len(dedup_parts) == 1:
                self.result.dedup_expression = dedup_parts[0]
            else:
                # Combine multiple fields with separator
                self.result.dedup_expression = (
                    '"-".join([str(x) for x in [' + ", ".join(dedup_parts) + "] if x])"
                )

        # Transform alert context fields
        self.result.alert_context_fields = list(self.analysis.alert_context_fields)

        # Transform eval expressions
        for field_name, expr in self.analysis.eval_expressions.items():
            python_expr = self._transform_eval_expr(expr)
            self.result.helper_expressions[field_name] = python_expr

        # Transform rex patterns
        for field, pattern in self.analysis.rex_patterns:
            var_name = f"rex_match_{self._field_counter}"
            self._field_counter += 1
            self.result.rex_extractions.append((field, pattern, var_name))
            self.result.required_imports.add("re")

        # Generate title expression based on dedup fields
        if self.analysis.dedup_fields:
            # Store just the field name, code generator will build the title method
            self.result.title_expression = self.analysis.dedup_fields[0]

        return self.result

    def _transform_search_term(self, term: SearchTerm) -> str:
        """Transform a search term to Python condition."""
        if isinstance(term, FieldComparison):
            return self._transform_field_comparison(term)

        elif isinstance(term, BooleanExpr):
            return self._transform_boolean_expr(term)

        elif isinstance(term, NotExpr):
            inner = self._transform_search_term(term.operand)
            return f"not ({inner})"

        elif isinstance(term, ParenExpr):
            if term.expr:
                inner = self._transform_search_term(term.expr)
                return f"({inner})"
            return "True"

        elif isinstance(term, FreeTextSearch):
            # Free text search - search in all string values
            escaped_text = term.text.replace('"', '\\"')
            if term.is_quoted:
                # Exact match in any field
                return f'"{escaped_text}" in str(event.values())'
            else:
                # Case-insensitive search
                return f'"{escaped_text.lower()}" in str(event).lower()'

        return "True"

    def _transform_field_comparison(self, comp: FieldComparison) -> str:
        """Transform a field comparison to Python."""
        # Skip metadata fields
        if comp.field.lower() in ("index", "sourcetype", "source"):
            return "True"

        field_access = self._get_field_access(comp.field)
        value = comp.value

        # Handle wildcard patterns
        if comp.is_wildcard:
            self.result.required_imports.add("pattern_match")
            escaped_value = str(value).replace('"', '\\"')
            return f'pattern_match({field_access} or "", "{escaped_value}")'

        # Handle different operators
        if comp.operator == ComparisonOperator.EQ:
            return self._format_equality(field_access, value, True)
        elif comp.operator == ComparisonOperator.NEQ:
            return self._format_equality(field_access, value, False)
        elif comp.operator == ComparisonOperator.LT:
            return f"{field_access} < {self._format_value(value)}"
        elif comp.operator == ComparisonOperator.GT:
            return f"{field_access} > {self._format_value(value)}"
        elif comp.operator == ComparisonOperator.LTE:
            return f"{field_access} <= {self._format_value(value)}"
        elif comp.operator == ComparisonOperator.GTE:
            return f"{field_access} >= {self._format_value(value)}"

        return "True"

    def _transform_boolean_expr(self, expr: BooleanExpr) -> str:
        """Transform a boolean expression to Python."""
        if not expr.operands:
            return "True"

        transformed = [self._transform_search_term(op) for op in expr.operands]
        # Filter out "True" conditions
        transformed = [t for t in transformed if t != "True"]

        if not transformed:
            return "True"

        if expr.operator == BooleanOperator.AND:
            return self._join_conditions(transformed, "and")
        elif expr.operator == BooleanOperator.OR:
            return self._join_conditions(transformed, "or")

        return "True"

    def _transform_eval_expr(self, expr: EvalExpr) -> str:
        """Transform an eval expression to Python."""
        if isinstance(expr, EvalLiteral):
            return self._format_value(expr.value)

        elif isinstance(expr, EvalFieldRef):
            return self._get_field_access(expr.field)

        elif isinstance(expr, EvalBinaryOp):
            left = self._transform_eval_expr(expr.left)
            right = self._transform_eval_expr(expr.right)

            # Map operators
            op_map = {
                "==": "==",
                "=": "==",
                "!=": "!=",
                "<": "<",
                ">": ">",
                "<=": "<=",
                ">=": ">=",
                "+": "+",
                "-": "-",
                "*": "*",
                "/": "/",
                "%": "%",
                ".": "+",  # String concatenation
                "AND": "and",
                "OR": "or",
            }

            py_op = op_map.get(expr.operator.upper(), expr.operator)

            if expr.operator == ".":
                # String concatenation
                return f"str({left}) + str({right})"

            return f"({left} {py_op} {right})"

        elif isinstance(expr, EvalUnaryOp):
            operand = self._transform_eval_expr(expr.operand)
            if expr.operator.upper() == "NOT":
                return f"not ({operand})"
            elif expr.operator == "-":
                return f"-({operand})"
            return operand

        elif isinstance(expr, EvalFunctionCall):
            return self._transform_function_call(expr)

        elif isinstance(expr, EvalConditional):
            condition = self._transform_eval_expr(expr.condition)
            then_expr = self._transform_eval_expr(expr.then_expr)
            else_expr = self._transform_eval_expr(expr.else_expr)
            return f"({then_expr} if {condition} else {else_expr})"

        elif isinstance(expr, EvalCase):
            # case(cond1, val1, cond2, val2, ...) -> chained if-else
            parts = []
            for cond, val in expr.cases:
                cond_str = self._transform_eval_expr(cond)
                val_str = self._transform_eval_expr(val)
                parts.append((cond_str, val_str))

            if not parts:
                return "None"

            # Build chained ternary
            result = parts[-1][1]  # Default to last value
            for cond, val in reversed(parts[:-1]):
                result = f"({val} if {cond} else {result})"
            return result

        return "None"

    def _transform_function_call(self, func: EvalFunctionCall) -> str:
        """Transform a function call to Python."""
        func_name = func.function.lower()
        args = [self._transform_eval_expr(arg) for arg in func.arguments]

        # Map common functions
        if func_name == "len":
            return f"len({args[0]} or '')"

        elif func_name == "lower":
            return f"({args[0]} or '').lower()"

        elif func_name == "upper":
            return f"({args[0]} or '').upper()"

        elif func_name in ("trim", "strip"):
            return f"({args[0]} or '').strip()"

        elif func_name == "ltrim":
            return f"({args[0]} or '').lstrip()"

        elif func_name == "rtrim":
            return f"({args[0]} or '').rstrip()"

        elif func_name == "substr":
            if len(args) >= 3:
                return f"({args[0]} or '')[{args[1]}:{args[1]}+{args[2]}]"
            elif len(args) == 2:
                return f"({args[0]} or '')[{args[1]}:]"
            return f"({args[0]} or '')"

        elif func_name == "replace":
            if len(args) >= 3:
                return f"({args[0]} or '').replace({args[1]}, {args[2]})"
            return args[0] if args else "''"

        elif func_name == "split":
            if len(args) >= 2:
                return f"({args[0]} or '').split({args[1]})"
            return f"({args[0]} or '').split()"

        elif func_name == "mvindex":
            if len(args) >= 2:
                return f"({args[0]} or [])[{args[1]}] if len({args[0]} or []) > {args[1]} else None"
            return args[0] if args else "[]"

        elif func_name == "mvjoin":
            if len(args) >= 2:
                return f"{args[1]}.join([str(x) for x in ({args[0]} or [])])"
            return "''".join(args[0]) if args else "''"

        elif func_name == "mvcount":
            return f"len({args[0]} or [])"

        elif func_name == "abs":
            return f"abs({args[0]})"

        elif func_name == "ceil":
            self.result.required_imports.add("math")
            return f"math.ceil({args[0]})"

        elif func_name == "floor":
            self.result.required_imports.add("math")
            return f"math.floor({args[0]})"

        elif func_name == "round":
            if len(args) >= 2:
                return f"round({args[0]}, {args[1]})"
            return f"round({args[0]})"

        elif func_name == "sqrt":
            self.result.required_imports.add("math")
            return f"math.sqrt({args[0]})"

        elif func_name == "pow":
            if len(args) >= 2:
                return f"pow({args[0]}, {args[1]})"
            return args[0] if args else "0"

        elif func_name == "log":
            self.result.required_imports.add("math")
            if len(args) >= 2:
                return f"math.log({args[0]}, {args[1]})"
            return f"math.log({args[0]})"

        elif func_name == "exp":
            self.result.required_imports.add("math")
            return f"math.exp({args[0]})"

        elif func_name == "now":
            self.result.required_imports.add("time")
            return "time.time()"

        elif func_name == "tonumber":
            return f"float({args[0]}) if {args[0]} else 0"

        elif func_name == "tostring":
            return f"str({args[0]})"

        elif func_name == "isnull":
            return f"({args[0]} is None)"

        elif func_name == "isnotnull":
            return f"({args[0]} is not None)"

        elif func_name == "coalesce":
            return f"next((x for x in [{', '.join(args)}] if x is not None), None)"

        elif func_name == "match":
            self.result.required_imports.add("re")
            if len(args) >= 2:
                return f"bool(re.search({args[1]}, str({args[0]} or '')))"
            return "False"

        elif func_name == "like":
            self.result.required_imports.add("pattern_match")
            if len(args) >= 2:
                return f"pattern_match(str({args[0]} or ''), {args[1]})"
            return "False"

        elif func_name == "cidrmatch":
            self.result.required_imports.add("is_ip_in_network")
            if len(args) >= 2:
                return f"is_ip_in_network(str({args[0]} or ''), {args[1]})"
            return "False"

        elif func_name in ("json_extract", "spath"):
            if len(args) >= 2:
                return f"deep_get({args[0]}, {args[1]})"
            return args[0] if args else "None"

        elif func_name in ("md5", "sha1", "sha256", "sha512"):
            self.result.required_imports.add("hashlib")
            return f"hashlib.{func_name}(str({args[0]} or '').encode()).hexdigest()"

        # Unknown function - generate a placeholder
        args_str = ", ".join(args)
        return f"# TODO: Convert SPL function {func_name}({args_str})"

    def _get_field_access(self, field: str, with_default: str | None = None) -> str:
        """Generate Python code to access a field value."""
        if "." in field:
            # Nested field access - use deep_get
            if with_default:
                return f'deep_get(event, "{field}", {with_default})'
            return f'deep_get(event, "{field}")'
        else:
            # Simple field access
            if with_default:
                return f'event.get("{field}", {with_default})'
            return f'event.get("{field}")'

    def _format_value(self, value: Any) -> str:
        """Format a value as Python literal."""
        if value is None:
            return "None"
        elif isinstance(value, bool):
            return "True" if value else "False"
        elif isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        elif isinstance(value, (int, float)):
            return str(value)
        else:
            return repr(value)

    def _format_equality(self, field_access: str, value: Any, is_equal: bool) -> str:
        """Format an equality comparison."""
        op = "==" if is_equal else "!="
        formatted_value = self._format_value(value)
        return f"{field_access} {op} {formatted_value}"

    def _join_conditions(self, conditions: list[str], operator: str) -> str:
        """Join multiple conditions with an operator."""
        if not conditions:
            return "True"
        if len(conditions) == 1:
            return conditions[0]

        # Format nicely for readability
        separator = f"\n            {operator} "
        joined = separator.join(conditions)
        return f"(\n            {joined}\n        )"
