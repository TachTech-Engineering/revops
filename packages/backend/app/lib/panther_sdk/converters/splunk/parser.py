"""SPL Parser - Recursive descent parser for Splunk Processing Language."""

from __future__ import annotations

from typing import Any

from .ast_nodes import (
    Aggregation,
    AggregationFunction,
    BooleanExpr,
    BooleanOperator,
    Command,
    ComparisonOperator,
    DedupCommand,
    EvalBinaryOp,
    EvalCase,
    EvalCommand,
    EvalConditional,
    EvalExpr,
    EvalFieldRef,
    EvalFunctionCall,
    EvalLiteral,
    EvalUnaryOp,
    FieldComparison,
    FieldsCommand,
    FreeTextSearch,
    HeadCommand,
    JoinCommand,
    LookupCommand,
    MacroReference,
    NotExpr,
    ParenExpr,
    RegexCommand,
    RenameCommand,
    RexCommand,
    SearchCommand,
    SearchTerm,
    SortCommand,
    SPLQuery,
    StatsCommand,
    SubsearchCommand,
    TableCommand,
    TailCommand,
    TimeModifier,
    UnsupportedCommand,
    WhereCommand,
)
from .exceptions import SPLParserError
from .lexer import SPLLexer, Token, TokenType
from .mappings import UNSUPPORTED_COMMANDS


class SPLParser:
    """Recursive descent parser for SPL."""

    def __init__(self, tokens: list[Token]) -> None:
        """
        Initialize the parser.

        Args:
            tokens: List of tokens from the lexer
        """
        self.tokens = tokens
        self.position = 0
        self.raw_spl = ""

    @classmethod
    def from_source(cls, source: str) -> SPLParser:
        """
        Create a parser from SPL source code.

        Args:
            source: SPL source code

        Returns:
            SPLParser instance
        """
        lexer = SPLLexer(source)
        tokens = lexer.tokenize()
        parser = cls(tokens)
        parser.raw_spl = source
        return parser

    def parse(self) -> SPLQuery:
        """
        Parse the token stream into an AST.

        Returns:
            SPLQuery AST node

        Raises:
            SPLParserError: If a syntax error is encountered
        """
        return self._parse_query()

    def _parse_query(self) -> SPLQuery:
        """Parse the top-level query."""
        query = SPLQuery(raw_spl=self.raw_spl)

        # Skip leading newlines
        self._skip_newlines()

        # Parse optional time modifiers at the beginning
        query.time_modifier = self._parse_time_modifiers()

        # Parse search clause (initial search terms before first pipe)
        if not self._check(TokenType.PIPE) and not self._check(TokenType.EOF):
            search_terms = self._parse_search_clause()
            query.search_terms = search_terms

            # Extract index and sourcetype from search terms
            self._extract_metadata(query)

        # Parse commands after pipes
        self._skip_newlines()
        while self._match(TokenType.PIPE):
            self._skip_newlines()
            if self._check(TokenType.EOF):
                break
            command = self._parse_command()
            if command:
                query.commands.append(command)
            # Skip newlines before checking for next pipe
            self._skip_newlines()

        return query

    def _parse_time_modifiers(self) -> TimeModifier | None:
        """Parse time modifiers like earliest=-24h latest=now."""
        time_mod = TimeModifier()
        found = False

        while True:
            if self._check(TokenType.IDENTIFIER):
                current = self._current()
                if current.value.lower() == "earliest":
                    self._advance()
                    self._expect(TokenType.EQUALS)
                    time_mod.earliest = self._parse_time_value()
                    found = True
                elif current.value.lower() == "latest":
                    self._advance()
                    self._expect(TokenType.EQUALS)
                    time_mod.latest = self._parse_time_value()
                    found = True
                else:
                    break
            else:
                break

        return time_mod if found else None

    def _parse_time_value(self) -> str:
        """Parse a time value (could be identifier, number, or string)."""
        if self._check(TokenType.STRING):
            token = self._advance()
            return token.value
        elif self._check(TokenType.NUMBER):
            token = self._advance()
            return token.value
        elif self._check(TokenType.IDENTIFIER):
            token = self._advance()
            return token.value
        elif self._check(TokenType.MINUS):
            self._advance()
            if self._check(TokenType.NUMBER):
                token = self._advance()
                # Check for time unit suffix
                if self._check(TokenType.IDENTIFIER):
                    unit = self._advance()
                    return f"-{token.value}{unit.value}"
                return f"-{token.value}"
        raise SPLParserError("Expected time value", self._current())

    def _parse_search_clause(self) -> SearchTerm | None:
        """Parse the search clause (terms connected by AND/OR)."""
        return self._parse_or_expr()

    def _parse_or_expr(self) -> SearchTerm | None:
        """Parse OR expressions."""
        left = self._parse_and_expr()
        if left is None:
            return None

        while self._match(TokenType.OR):
            right = self._parse_and_expr()
            if right is None:
                raise SPLParserError("Expected search term after OR", self._current())
            left = BooleanExpr(operator=BooleanOperator.OR, operands=[left, right])

        return left

    def _parse_and_expr(self) -> SearchTerm | None:
        """Parse AND expressions (explicit or implicit)."""
        left = self._parse_not_expr()
        if left is None:
            return None

        while True:
            # Explicit AND
            if self._match(TokenType.AND):
                right = self._parse_not_expr()
                if right is None:
                    raise SPLParserError("Expected search term after AND", self._current())
                left = BooleanExpr(operator=BooleanOperator.AND, operands=[left, right])
            # Implicit AND (adjacent terms)
            elif self._is_search_term_start():
                right = self._parse_not_expr()
                if right is None:
                    break
                left = BooleanExpr(operator=BooleanOperator.AND, operands=[left, right])
            else:
                break

        return left

    def _parse_not_expr(self) -> SearchTerm | None:
        """Parse NOT expressions."""
        if self._match(TokenType.NOT):
            operand = self._parse_primary_search()
            if operand is None:
                raise SPLParserError("Expected search term after NOT", self._current())
            return NotExpr(operand=operand)
        return self._parse_primary_search()

    def _parse_primary_search(self) -> SearchTerm | None:
        """Parse primary search terms."""
        # Parenthesized expression
        if self._match(TokenType.LPAREN):
            expr = self._parse_or_expr()
            self._expect(TokenType.RPAREN)
            return ParenExpr(expr=expr) if expr else None

        # Subsearch
        if self._match(TokenType.LBRACKET):
            return self._parse_subsearch()

        # Field comparison or free text
        return self._parse_field_or_text()

    def _parse_field_or_text(self) -> SearchTerm | None:
        """Parse a field comparison or free text search."""
        # Check for comparison operators
        if self._check(TokenType.IDENTIFIER) or self._check(TokenType.STRING):
            # Look ahead for comparison operator
            if self._peek_is_comparison():
                return self._parse_field_comparison()

        # Free text search
        if self._check(TokenType.STRING):
            token = self._advance()
            return FreeTextSearch(text=token.value, is_quoted=True)

        if self._check(TokenType.IDENTIFIER):
            token = self._advance()
            # Check if it's a wildcard pattern
            if "*" in token.value or "?" in token.value:
                return FreeTextSearch(text=token.value, is_quoted=False)
            return FreeTextSearch(text=token.value, is_quoted=False)

        if self._check(TokenType.WILDCARD):
            token = self._advance()
            return FreeTextSearch(text=token.value, is_quoted=False)

        if self._check(TokenType.NUMBER):
            token = self._advance()
            return FreeTextSearch(text=token.value, is_quoted=False)

        return None

    def _parse_field_comparison(self) -> FieldComparison:
        """Parse a field comparison like field=value or field IN (v1, v2)."""
        field_token = self._advance()
        field_name = field_token.value

        # `field IN (v1, v2, ...)` -- value is the list of alternatives.
        if self._check(TokenType.IDENTIFIER) and self._current().value.lower() == "in":
            self._advance()  # consume IN
            values = self._parse_in_list()
            return FieldComparison(
                field=field_name,
                operator=ComparisonOperator.IN,
                value=values,
                is_wildcard=any(isinstance(v, str) and ("*" in v or "?" in v) for v in values),
            )

        # Get comparison operator
        operator = self._parse_comparison_operator()

        # Get value
        value, is_wildcard = self._parse_comparison_value()

        return FieldComparison(
            field=field_name, operator=operator, value=value, is_wildcard=is_wildcard
        )

    def _parse_in_list(self) -> list[Any]:
        """Parse the parenthesized value list of an IN expression."""
        self._expect(TokenType.LPAREN)
        values: list[Any] = []
        while not self._check(TokenType.RPAREN):
            value, _ = self._parse_comparison_value()
            if value is None:
                raise SPLParserError("Expected value in IN list", self._current())
            values.append(value)
            if not self._match(TokenType.COMMA):
                break
        self._expect(TokenType.RPAREN)
        if not values:
            raise SPLParserError("Empty IN list", self._current())
        return values

    def _parse_comparison_operator(self) -> ComparisonOperator:
        """Parse a comparison operator."""
        if self._match(TokenType.EQUALS):
            return ComparisonOperator.EQ
        elif self._match(TokenType.NOT_EQUALS):
            return ComparisonOperator.NEQ
        elif self._match(TokenType.LESS_THAN_EQ):
            return ComparisonOperator.LTE
        elif self._match(TokenType.GREATER_THAN_EQ):
            return ComparisonOperator.GTE
        elif self._match(TokenType.LESS_THAN):
            return ComparisonOperator.LT
        elif self._match(TokenType.GREATER_THAN):
            return ComparisonOperator.GT
        else:
            raise SPLParserError(
                "Expected comparison operator", self._current(), expected="=, !=, <, >"
            )

    def _parse_comparison_value(self) -> tuple[Any, bool]:
        """Parse a comparison value. Returns (value, is_wildcard)."""
        if self._check(TokenType.STRING):
            token = self._advance()
            is_wildcard = "*" in token.value or "?" in token.value
            return token.value, is_wildcard

        if self._check(TokenType.NUMBER):
            token = self._advance()
            # Try to convert to number
            try:
                if "." in token.value:
                    return float(token.value), False
                return int(token.value), False
            except ValueError:
                return token.value, False

        if self._check(TokenType.IDENTIFIER):
            token = self._advance()
            value = token.value
            is_wildcard = "*" in value or "?" in value
            # Check if followed by wildcard character (e.g., admin*)
            if self._check(TokenType.STAR):
                self._advance()
                value += "*"
                is_wildcard = True
            return value, is_wildcard

        if self._check(TokenType.WILDCARD):
            token = self._advance()
            return token.value, True

        if self._check(TokenType.STAR):
            self._advance()
            return "*", True

        raise SPLParserError(
            "Expected value", self._current(), expected="string, number, or identifier"
        )

    def _parse_subsearch(self) -> SubsearchCommand:
        """Parse a subsearch [...] (unsupported but captured)."""
        self._current().position
        depth = 1
        subsearch_text = ""

        while depth > 0 and not self._check(TokenType.EOF):
            if self._check(TokenType.LBRACKET):
                depth += 1
                subsearch_text += "["
            elif self._check(TokenType.RBRACKET):
                depth -= 1
                if depth > 0:
                    subsearch_text += "]"
            else:
                subsearch_text += self._current().value + " "
            self._advance()

        return SubsearchCommand(
            raw_text=f"[{subsearch_text}]", subsearch_text=subsearch_text.strip()
        )

    def _parse_command(self) -> Command | None:
        """Parse a command after a pipe."""
        self._skip_newlines()

        if self._check(TokenType.EOF):
            return None

        # Get command name
        token = self._current()

        # Handle known commands
        if token.type == TokenType.STATS:
            return self._parse_stats_command()
        elif token.type == TokenType.EVAL:
            return self._parse_eval_command()
        elif token.type == TokenType.WHERE:
            return self._parse_where_command()
        elif token.type == TokenType.REX:
            return self._parse_rex_command()
        elif token.type == TokenType.TABLE:
            return self._parse_table_command()
        elif token.type == TokenType.FIELDS:
            return self._parse_fields_command()
        elif token.type == TokenType.SORT:
            return self._parse_sort_command()
        elif token.type == TokenType.HEAD:
            return self._parse_head_command()
        elif token.type == TokenType.TAIL:
            return self._parse_tail_command()
        elif token.type == TokenType.DEDUP:
            return self._parse_dedup_command()
        elif token.type == TokenType.RENAME:
            return self._parse_rename_command()
        elif token.type == TokenType.REGEX:
            return self._parse_regex_command()
        elif token.type == TokenType.SEARCH:
            return self._parse_search_command()
        elif token.type == TokenType.JOIN:
            return self._parse_join_command()
        elif token.type == TokenType.LOOKUP:
            return self._parse_lookup_command()
        elif token.type == TokenType.MACRO:
            return self._parse_macro_reference()
        elif token.type in (
            TokenType.APPEND,
            TokenType.TRANSACTION,
            TokenType.EVENTSTATS,
            TokenType.STREAMSTATS,
            TokenType.TSTATS,
            TokenType.INPUTLOOKUP,
            TokenType.OUTPUTLOOKUP,
            TokenType.TIMECHART,
            TokenType.CHART,
            TokenType.MAP,
            TokenType.FOREACH,
            TokenType.CONVERT,
            TokenType.FILLNULL,
            TokenType.BIN,
            TokenType.BUCKET,
            TokenType.COLLECT,
            TokenType.SENDEMAIL,
        ):
            return self._parse_unsupported_command()
        elif token.type == TokenType.IDENTIFIER:
            # Unknown command - capture it
            return self._parse_unknown_command()

        raise SPLParserError(f"Unexpected token in command: {token.value}", token)

    def _parse_stats_command(self) -> StatsCommand:
        """Parse: stats count by field1, field2."""
        self._expect(TokenType.STATS)

        aggregations: list[Aggregation] = []
        by_fields: list[str] = []

        # Parse aggregations
        while not self._check(TokenType.BY) and not self._is_command_end():
            agg = self._parse_aggregation()
            if agg:
                aggregations.append(agg)

            if self._match(TokenType.COMMA):
                continue
            break

        # Parse BY clause
        if self._match(TokenType.BY):
            by_fields = self._parse_field_list()

        return StatsCommand(aggregations=aggregations, by_fields=by_fields)

    def _parse_aggregation(self) -> Aggregation | None:
        """Parse an aggregation like count, count(field), sum(field) as alias."""
        if not self._check(TokenType.IDENTIFIER):
            return None

        func_name = self._advance().value.lower()

        # Map function name to enum
        try:
            func = AggregationFunction(func_name)
        except ValueError:
            # Unknown aggregation function - treat as count
            func = AggregationFunction.COUNT

        field = None
        alias = None

        # Check for parentheses (field argument)
        if self._match(TokenType.LPAREN):
            if not self._check(TokenType.RPAREN):
                if self._check(TokenType.IDENTIFIER) or self._check(TokenType.STRING):
                    field = self._advance().value
            self._expect(TokenType.RPAREN)

        # Check for AS alias
        if self._match(TokenType.AS):
            if self._check(TokenType.IDENTIFIER) or self._check(TokenType.STRING):
                alias = self._advance().value

        return Aggregation(function=func, field=field, alias=alias)

    def _parse_eval_command(self) -> EvalCommand:
        """Parse: eval field=expression."""
        self._expect(TokenType.EVAL)

        assignments: dict[str, EvalExpr] = {}

        while not self._is_command_end():
            # Parse field name
            if not self._check(TokenType.IDENTIFIER):
                break

            field_name = self._advance().value
            self._expect(TokenType.EQUALS)

            # Parse expression
            expr = self._parse_eval_expression()
            assignments[field_name] = expr

            if not self._match(TokenType.COMMA):
                break

        return EvalCommand(assignments=assignments)

    def _parse_eval_expression(self) -> EvalExpr:
        """Parse an eval expression."""
        return self._parse_eval_or()

    def _parse_eval_or(self) -> EvalExpr:
        """Parse OR in eval expressions."""
        left = self._parse_eval_and()

        while self._match(TokenType.OR):
            right = self._parse_eval_and()
            left = EvalBinaryOp(operator="OR", left=left, right=right)

        return left

    def _parse_eval_and(self) -> EvalExpr:
        """Parse AND in eval expressions."""
        left = self._parse_eval_comparison()

        while self._match(TokenType.AND):
            right = self._parse_eval_comparison()
            left = EvalBinaryOp(operator="AND", left=left, right=right)

        return left

    def _parse_eval_comparison(self) -> EvalExpr:
        """Parse comparison operators in eval expressions."""
        left = self._parse_eval_concat()

        while True:
            if self._match(TokenType.EQUALS):
                right = self._parse_eval_concat()
                left = EvalBinaryOp(operator="==", left=left, right=right)
            elif self._match(TokenType.NOT_EQUALS):
                right = self._parse_eval_concat()
                left = EvalBinaryOp(operator="!=", left=left, right=right)
            elif self._match(TokenType.LESS_THAN_EQ):
                right = self._parse_eval_concat()
                left = EvalBinaryOp(operator="<=", left=left, right=right)
            elif self._match(TokenType.GREATER_THAN_EQ):
                right = self._parse_eval_concat()
                left = EvalBinaryOp(operator=">=", left=left, right=right)
            elif self._match(TokenType.LESS_THAN):
                right = self._parse_eval_concat()
                left = EvalBinaryOp(operator="<", left=left, right=right)
            elif self._match(TokenType.GREATER_THAN):
                right = self._parse_eval_concat()
                left = EvalBinaryOp(operator=">", left=left, right=right)
            else:
                break

        return left

    def _parse_eval_concat(self) -> EvalExpr:
        """Parse string concatenation (.) in eval expressions."""
        left = self._parse_eval_additive()

        while self._match(TokenType.DOT):
            right = self._parse_eval_additive()
            left = EvalBinaryOp(operator=".", left=left, right=right)

        return left

    def _parse_eval_additive(self) -> EvalExpr:
        """Parse + and - in eval expressions."""
        left = self._parse_eval_multiplicative()

        while True:
            if self._match(TokenType.PLUS):
                right = self._parse_eval_multiplicative()
                left = EvalBinaryOp(operator="+", left=left, right=right)
            elif self._match(TokenType.MINUS):
                right = self._parse_eval_multiplicative()
                left = EvalBinaryOp(operator="-", left=left, right=right)
            else:
                break

        return left

    def _parse_eval_multiplicative(self) -> EvalExpr:
        """Parse * and / in eval expressions."""
        left = self._parse_eval_unary()

        while True:
            if self._match(TokenType.STAR):
                right = self._parse_eval_unary()
                left = EvalBinaryOp(operator="*", left=left, right=right)
            elif self._match(TokenType.SLASH):
                right = self._parse_eval_unary()
                left = EvalBinaryOp(operator="/", left=left, right=right)
            elif self._match(TokenType.PERCENT):
                right = self._parse_eval_unary()
                left = EvalBinaryOp(operator="%", left=left, right=right)
            else:
                break

        return left

    def _parse_eval_unary(self) -> EvalExpr:
        """Parse unary operators in eval expressions."""
        if self._match(TokenType.NOT):
            operand = self._parse_eval_unary()
            return EvalUnaryOp(operator="NOT", operand=operand)

        if self._match(TokenType.MINUS):
            operand = self._parse_eval_unary()
            return EvalUnaryOp(operator="-", operand=operand)

        return self._parse_eval_primary()

    def _parse_eval_primary(self) -> EvalExpr:
        """Parse primary eval expressions (literals, fields, functions, parens)."""
        # Parenthesized expression
        if self._match(TokenType.LPAREN):
            expr = self._parse_eval_expression()
            self._expect(TokenType.RPAREN)
            return expr

        # String literal
        if self._check(TokenType.STRING):
            token = self._advance()
            return EvalLiteral(value=token.value, value_type="string")

        # Number literal
        if self._check(TokenType.NUMBER):
            token = self._advance()
            try:
                if "." in token.value:
                    return EvalLiteral(value=float(token.value), value_type="number")
                return EvalLiteral(value=int(token.value), value_type="number")
            except ValueError:
                return EvalLiteral(value=token.value, value_type="string")

        # Identifier (field reference or function call)
        if self._check(TokenType.IDENTIFIER):
            token = self._advance()
            name = token.value

            # Check for special keywords
            if name.lower() == "true":
                return EvalLiteral(value=True, value_type="boolean")
            if name.lower() == "false":
                return EvalLiteral(value=False, value_type="boolean")
            if name.lower() == "null":
                return EvalLiteral(value=None, value_type="null")

            # Check for function call
            if self._match(TokenType.LPAREN):
                return self._parse_eval_function_call(name)

            # Field reference
            return EvalFieldRef(field=name)

        raise SPLParserError(
            "Expected expression", self._current(), expected="literal, field, or function"
        )

    def _parse_eval_function_call(self, func_name: str) -> EvalExpr:
        """Parse a function call in an eval expression."""
        args: list[EvalExpr] = []

        # Special handling for if() function
        if func_name.lower() == "if":
            self._skip_newlines()
            condition = self._parse_eval_expression()
            self._skip_newlines()
            self._expect(TokenType.COMMA)
            self._skip_newlines()
            then_expr = self._parse_eval_expression()
            self._skip_newlines()
            self._expect(TokenType.COMMA)
            self._skip_newlines()
            else_expr = self._parse_eval_expression()
            self._skip_newlines()
            self._expect(TokenType.RPAREN)
            return EvalConditional(condition=condition, then_expr=then_expr, else_expr=else_expr)

        # Special handling for case() function
        if func_name.lower() == "case":
            cases: list[tuple[EvalExpr, EvalExpr]] = []
            self._skip_newlines()
            while not self._check(TokenType.RPAREN):
                self._skip_newlines()
                cond = self._parse_eval_expression()
                self._skip_newlines()
                self._expect(TokenType.COMMA)
                self._skip_newlines()
                val = self._parse_eval_expression()
                cases.append((cond, val))
                self._skip_newlines()
                if not self._match(TokenType.COMMA):
                    break
            self._skip_newlines()
            self._expect(TokenType.RPAREN)
            return EvalCase(cases=cases)

        # Regular function call
        self._skip_newlines()
        if not self._check(TokenType.RPAREN):
            args.append(self._parse_eval_expression())
            self._skip_newlines()
            while self._match(TokenType.COMMA):
                self._skip_newlines()
                args.append(self._parse_eval_expression())
                self._skip_newlines()

        self._expect(TokenType.RPAREN)
        return EvalFunctionCall(function=func_name, arguments=args)

    def _parse_where_command(self) -> WhereCommand:
        """Parse: where condition."""
        self._expect(TokenType.WHERE)
        condition = self._parse_eval_expression()
        return WhereCommand(condition=condition)

    def _parse_rex_command(self) -> RexCommand:
        """Parse: rex field=X "pattern"."""
        self._expect(TokenType.REX)

        field = "_raw"
        pattern = ""
        mode = "extract"
        max_match = None

        # Parse options
        while not self._is_command_end():
            if self._check(TokenType.IDENTIFIER):
                opt_name = self._current().value.lower()

                if opt_name == "field":
                    self._advance()
                    self._expect(TokenType.EQUALS)
                    field = self._advance().value
                elif opt_name == "mode":
                    self._advance()
                    self._expect(TokenType.EQUALS)
                    mode = self._advance().value
                elif opt_name == "max_match":
                    self._advance()
                    self._expect(TokenType.EQUALS)
                    max_match = int(self._advance().value)
                else:
                    break
            elif self._check(TokenType.STRING):
                pattern = self._advance().value
                break
            else:
                break

        return RexCommand(field=field, pattern=pattern, mode=mode, max_match=max_match)

    def _parse_table_command(self) -> TableCommand:
        """Parse: table field1, field2, ..."""
        self._expect(TokenType.TABLE)
        fields = self._parse_field_list()
        return TableCommand(fields=fields)

    def _parse_fields_command(self) -> FieldsCommand:
        """Parse: fields [+|-] field1, field2, ..."""
        self._expect(TokenType.FIELDS)

        include = True
        if self._match(TokenType.PLUS):
            include = True
        elif self._match(TokenType.MINUS):
            include = False

        fields = self._parse_field_list()
        return FieldsCommand(fields=fields, include=include)

    def _parse_sort_command(self) -> SortCommand:
        """Parse: sort [+|-]field1, [+|-]field2, ..."""
        self._expect(TokenType.SORT)

        sort_fields: list[tuple[str, bool]] = []

        while not self._is_command_end():
            ascending = True
            if self._match(TokenType.PLUS):
                ascending = True
            elif self._match(TokenType.MINUS):
                ascending = False

            if self._check(TokenType.IDENTIFIER) or self._check(TokenType.STRING):
                field = self._advance().value
                sort_fields.append((field, ascending))

            if not self._match(TokenType.COMMA):
                break

        return SortCommand(sort_fields=sort_fields)

    def _parse_head_command(self) -> HeadCommand:
        """Parse: head N."""
        self._expect(TokenType.HEAD)

        count = 10
        if self._check(TokenType.NUMBER):
            count = int(self._advance().value)

        return HeadCommand(count=count)

    def _parse_tail_command(self) -> TailCommand:
        """Parse: tail N."""
        self._expect(TokenType.TAIL)

        count = 10
        if self._check(TokenType.NUMBER):
            count = int(self._advance().value)

        return TailCommand(count=count)

    def _parse_dedup_command(self) -> DedupCommand:
        """Parse: dedup field1, field2, ..."""
        self._expect(TokenType.DEDUP)
        fields = self._parse_field_list()
        return DedupCommand(fields=fields)

    def _parse_rename_command(self) -> RenameCommand:
        """Parse: rename field1 AS alias1, field2 AS alias2."""
        self._expect(TokenType.RENAME)

        renames: dict[str, str] = {}

        while not self._is_command_end():
            if not self._check(TokenType.IDENTIFIER) and not self._check(TokenType.STRING):
                break

            old_name = self._advance().value
            self._expect(TokenType.AS)

            if not self._check(TokenType.IDENTIFIER) and not self._check(TokenType.STRING):
                raise SPLParserError("Expected alias name", self._current())

            new_name = self._advance().value
            renames[old_name] = new_name

            if not self._match(TokenType.COMMA):
                break

        return RenameCommand(renames=renames)

    def _parse_regex_command(self) -> RegexCommand:
        """Parse: regex field=pattern."""
        self._expect(TokenType.REGEX)

        field = ""
        pattern = ""
        negate = False

        if self._check(TokenType.IDENTIFIER):
            field = self._advance().value
            if self._match(TokenType.NOT_EQUALS):
                negate = True
            else:
                self._expect(TokenType.EQUALS)

            if self._check(TokenType.STRING):
                pattern = self._advance().value
            elif self._check(TokenType.IDENTIFIER):
                pattern = self._advance().value

        return RegexCommand(field=field, pattern=pattern, negate=negate)

    def _parse_search_command(self) -> SearchCommand:
        """Parse: search <search_terms>."""
        self._expect(TokenType.SEARCH)
        search_terms = self._parse_search_clause()
        return SearchCommand(search_terms=search_terms)

    def _parse_join_command(self) -> JoinCommand:
        """Parse join command (unsupported)."""
        raw_text = self._capture_until_pipe_or_end()
        return JoinCommand(raw_text=raw_text)

    def _parse_lookup_command(self) -> LookupCommand:
        """Parse lookup command (unsupported)."""
        raw_text = self._capture_until_pipe_or_end()
        return LookupCommand(raw_text=raw_text)

    def _parse_macro_reference(self) -> MacroReference:
        """Parse a macro reference (unsupported)."""
        token = self._advance()
        return MacroReference(raw_text=f"`{token.value}`", macro_name=token.value)

    def _parse_unsupported_command(self) -> UnsupportedCommand:
        """Parse an unsupported command."""
        token = self._advance()
        command_name = token.value.lower()
        raw_text = self._capture_until_pipe_or_end()
        suggestion = UNSUPPORTED_COMMANDS.get(command_name)
        return UnsupportedCommand(
            name=command_name, raw_text=f"{token.value} {raw_text}", suggestion=suggestion
        )

    def _parse_unknown_command(self) -> UnsupportedCommand:
        """Parse an unknown command."""
        token = self._advance()
        raw_text = self._capture_until_pipe_or_end()
        return UnsupportedCommand(
            name=token.value,
            raw_text=f"{token.value} {raw_text}",
            suggestion="Unknown command - manual conversion required",
        )

    def _parse_field_list(self) -> list[str]:
        """Parse a comma-separated list of field names."""
        fields: list[str] = []

        while not self._is_command_end():
            if self._check(TokenType.IDENTIFIER) or self._check(TokenType.STRING):
                fields.append(self._advance().value)
            else:
                break

            if not self._match(TokenType.COMMA):
                break

        return fields

    def _capture_until_pipe_or_end(self) -> str:
        """Capture all text until the next pipe or end of query."""
        parts: list[str] = []
        while not self._is_command_end():
            parts.append(self._current().value)
            self._advance()
        return " ".join(parts)

    def _extract_metadata(self, query: SPLQuery) -> None:
        """Extract index and sourcetype from search terms."""

        def extract_from_term(term: SearchTerm) -> None:
            if isinstance(term, FieldComparison):
                if term.field.lower() == "index":
                    query.index = str(term.value)
                elif term.field.lower() == "sourcetype":
                    query.sourcetype = str(term.value)
                elif term.field.lower() == "source":
                    query.source = str(term.value)
            elif isinstance(term, BooleanExpr):
                for operand in term.operands:
                    extract_from_term(operand)
            elif isinstance(term, ParenExpr) and term.expr:
                extract_from_term(term.expr)
            elif isinstance(term, NotExpr) and term.operand:
                extract_from_term(term.operand)

        if query.search_terms:
            extract_from_term(query.search_terms)

    # Helper methods

    def _current(self) -> Token:
        """Get the current token."""
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return self.tokens[-1]  # EOF token

    def _peek(self, offset: int = 1) -> Token:
        """Peek at a future token."""
        pos = self.position + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return self.tokens[-1]

    def _advance(self) -> Token:
        """Advance to the next token and return the current one."""
        token = self._current()
        if self.position < len(self.tokens) - 1:
            self.position += 1
        return token

    def _check(self, token_type: TokenType) -> bool:
        """Check if the current token is of the given type."""
        return self._current().type == token_type

    def _match(self, token_type: TokenType) -> bool:
        """Check and advance if the current token matches."""
        if self._check(token_type):
            self._advance()
            return True
        return False

    def _expect(self, token_type: TokenType) -> Token:
        """Expect and consume a token of the given type."""
        if not self._check(token_type):
            raise SPLParserError(
                f"Expected {token_type.name}", self._current(), expected=token_type.name
            )
        return self._advance()

    def _skip_newlines(self) -> None:
        """Skip newline tokens."""
        while self._check(TokenType.NEWLINE):
            self._advance()

    def _is_command_end(self) -> bool:
        """Check if we're at the end of a command."""
        # Skip newlines first to check what's after them
        while self._check(TokenType.NEWLINE):
            self._advance()
        return self._check(TokenType.PIPE) or self._check(TokenType.EOF)

    def _is_search_term_start(self) -> bool:
        """Check if the current token could start a search term."""
        return self._current().type in (
            TokenType.IDENTIFIER,
            TokenType.STRING,
            TokenType.NUMBER,
            TokenType.WILDCARD,
            TokenType.LPAREN,
            TokenType.NOT,
            TokenType.LBRACKET,
        )

    def _peek_is_comparison(self) -> bool:
        """Check if the next token is a comparison operator."""
        next_token = self._peek()
        if next_token.type in (
            TokenType.EQUALS,
            TokenType.NOT_EQUALS,
            TokenType.LESS_THAN,
            TokenType.GREATER_THAN,
            TokenType.LESS_THAN_EQ,
            TokenType.GREATER_THAN_EQ,
        ):
            return True
        # `field IN (v1, v2, ...)` -- IN lexes as an IDENTIFIER (it is only a
        # keyword in this position), so require the following LPAREN to avoid
        # swallowing a free-text term that happens to be the word "in".
        return (
            next_token.type == TokenType.IDENTIFIER
            and next_token.value.lower() == "in"
            and self._peek(2).type == TokenType.LPAREN
        )
