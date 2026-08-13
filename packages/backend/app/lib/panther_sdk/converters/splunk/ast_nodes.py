"""AST node definitions for Splunk SPL."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class BooleanOperator(Enum):
    """Boolean operators in SPL."""

    AND = auto()
    OR = auto()
    NOT = auto()


class ComparisonOperator(Enum):
    """Comparison operators in SPL."""

    EQ = "="
    NEQ = "!="
    LT = "<"
    GT = ">"
    LTE = "<="
    GTE = ">="
    LIKE = "LIKE"
    IN = "IN"  # field IN (v1, v2, ...); value is a list


class AggregationFunction(Enum):
    """Aggregation functions in SPL stats command."""

    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    DC = "dc"  # distinct count
    VALUES = "values"
    LIST = "list"
    FIRST = "first"
    LAST = "last"
    EARLIEST = "earliest"
    LATEST = "latest"
    STDEV = "stdev"
    STDEVP = "stdevp"
    VAR = "var"
    VARP = "varp"
    MEDIAN = "median"
    PERCENTILE = "perc"  # perc<N>(field) or percentile
    RANGE = "range"
    MODE = "mode"


# Base AST Node
@dataclass
class ASTNode:
    """Base class for all AST nodes."""

    pass


# Search Terms
@dataclass
class SearchTerm(ASTNode):
    """Base class for search terms."""

    pass


@dataclass
class FieldComparison(SearchTerm):
    """A field comparison like field=value or field!=value."""

    field: str
    operator: ComparisonOperator
    value: Any
    is_wildcard: bool = False


@dataclass
class FreeTextSearch(SearchTerm):
    """A free text search term."""

    text: str
    is_quoted: bool = False


@dataclass
class BooleanExpr(SearchTerm):
    """A boolean expression combining search terms."""

    operator: BooleanOperator
    operands: list[SearchTerm] = field(default_factory=list)


@dataclass
class NotExpr(SearchTerm):
    """A NOT expression."""

    operand: SearchTerm


@dataclass
class ParenExpr(SearchTerm):
    """A parenthesized expression."""

    expr: SearchTerm


# Eval Expressions
@dataclass
class EvalExpr(ASTNode):
    """Base class for eval expressions."""

    pass


@dataclass
class EvalFieldRef(EvalExpr):
    """Reference to a field in an eval expression."""

    field: str


@dataclass
class EvalLiteral(EvalExpr):
    """A literal value in an eval expression."""

    value: Any
    value_type: str  # "string", "number", "boolean", "null"


@dataclass
class EvalBinaryOp(EvalExpr):
    """A binary operation in an eval expression."""

    operator: str  # +, -, *, /, ., ==, !=, <, >, <=, >=, AND, OR
    left: EvalExpr
    right: EvalExpr


@dataclass
class EvalUnaryOp(EvalExpr):
    """A unary operation in an eval expression."""

    operator: str  # NOT, -
    operand: EvalExpr


@dataclass
class EvalFunctionCall(EvalExpr):
    """A function call in an eval expression."""

    function: str
    arguments: list[EvalExpr] = field(default_factory=list)


@dataclass
class EvalConditional(EvalExpr):
    """An if-then-else conditional in eval (if(cond, then, else))."""

    condition: EvalExpr
    then_expr: EvalExpr
    else_expr: EvalExpr


@dataclass
class EvalCase(EvalExpr):
    """A case expression in eval (case(cond1, val1, cond2, val2, ...))."""

    cases: list[tuple[EvalExpr, EvalExpr]] = field(default_factory=list)


# Aggregations
@dataclass
class Aggregation(ASTNode):
    """An aggregation in stats command."""

    function: AggregationFunction
    field: str | None = None  # None for count()
    alias: str | None = None


# Commands
@dataclass
class Command(ASTNode):
    """Base class for SPL commands."""

    name: str


@dataclass
class StatsCommand(Command):
    """stats command: stats count by X."""

    aggregations: list[Aggregation] = field(default_factory=list)
    by_fields: list[str] = field(default_factory=list)

    def __init__(
        self,
        aggregations: list[Aggregation] | None = None,
        by_fields: list[str] | None = None,
    ) -> None:
        super().__init__(name="stats")
        self.aggregations = aggregations or []
        self.by_fields = by_fields or []


@dataclass
class EvalCommand(Command):
    """eval command: eval field=expr."""

    assignments: dict[str, EvalExpr] = field(default_factory=dict)

    def __init__(self, assignments: dict[str, EvalExpr] | None = None) -> None:
        super().__init__(name="eval")
        self.assignments = assignments or {}


@dataclass
class WhereCommand(Command):
    """where command: where condition."""

    condition: EvalExpr | None = None

    def __init__(self, condition: EvalExpr | None = None) -> None:
        super().__init__(name="where")
        self.condition = condition


@dataclass
class RexCommand(Command):
    """rex command: rex field=X "pattern"."""

    field: str = ""
    pattern: str = ""
    mode: str = "sed"  # "sed" or "extract"
    max_match: int | None = None

    def __init__(
        self,
        field: str = "",
        pattern: str = "",
        mode: str = "sed",
        max_match: int | None = None,
    ) -> None:
        super().__init__(name="rex")
        self.field = field
        self.pattern = pattern
        self.mode = mode
        self.max_match = max_match


@dataclass
class TableCommand(Command):
    """table command: table field1, field2, ..."""

    fields: list[str] = field(default_factory=list)

    def __init__(self, fields: list[str] | None = None) -> None:
        super().__init__(name="table")
        self.fields = fields or []


@dataclass
class FieldsCommand(Command):
    """fields command: fields [+|-] field1, field2, ..."""

    fields: list[str] = field(default_factory=list)
    include: bool = True  # True for include (+), False for exclude (-)

    def __init__(self, fields: list[str] | None = None, include: bool = True) -> None:
        super().__init__(name="fields")
        self.fields = fields or []
        self.include = include


@dataclass
class SortCommand(Command):
    """sort command: sort [+|-]field1, [+|-]field2, ..."""

    sort_fields: list[tuple[str, bool]] = field(default_factory=list)  # (field, ascending)

    def __init__(self, sort_fields: list[tuple[str, bool]] | None = None) -> None:
        super().__init__(name="sort")
        self.sort_fields = sort_fields or []


@dataclass
class HeadCommand(Command):
    """head command: head N."""

    count: int = 10

    def __init__(self, count: int = 10) -> None:
        super().__init__(name="head")
        self.count = count


@dataclass
class TailCommand(Command):
    """tail command: tail N."""

    count: int = 10

    def __init__(self, count: int = 10) -> None:
        super().__init__(name="tail")
        self.count = count


@dataclass
class DedupCommand(Command):
    """dedup command: dedup field1, field2, ..."""

    fields: list[str] = field(default_factory=list)
    consecutive: bool = False
    keep_events: bool = True

    def __init__(
        self,
        fields: list[str] | None = None,
        consecutive: bool = False,
        keep_events: bool = True,
    ) -> None:
        super().__init__(name="dedup")
        self.fields = fields or []
        self.consecutive = consecutive
        self.keep_events = keep_events


@dataclass
class SearchCommand(Command):
    """search command: search <search_terms>."""

    search_terms: SearchTerm | None = None

    def __init__(self, search_terms: SearchTerm | None = None) -> None:
        super().__init__(name="search")
        self.search_terms = search_terms


@dataclass
class RenameCommand(Command):
    """rename command: rename field1 AS alias1, field2 AS alias2."""

    renames: dict[str, str] = field(default_factory=dict)  # old_name -> new_name

    def __init__(self, renames: dict[str, str] | None = None) -> None:
        super().__init__(name="rename")
        self.renames = renames or {}


@dataclass
class RegexCommand(Command):
    """regex command: regex field=pattern."""

    field: str = ""
    pattern: str = ""
    negate: bool = False

    def __init__(self, field: str = "", pattern: str = "", negate: bool = False) -> None:
        super().__init__(name="regex")
        self.field = field
        self.pattern = pattern
        self.negate = negate


# Unsupported commands (stored for TODO comments)
@dataclass
class UnsupportedCommand(Command):
    """Represents an unsupported SPL command."""

    raw_text: str = ""
    suggestion: str | None = None

    def __init__(self, name: str, raw_text: str = "", suggestion: str | None = None) -> None:
        super().__init__(name=name)
        self.raw_text = raw_text
        self.suggestion = suggestion


@dataclass
class JoinCommand(UnsupportedCommand):
    """join command (unsupported)."""

    join_type: str = "inner"
    join_fields: list[str] = field(default_factory=list)

    def __init__(
        self,
        raw_text: str = "",
        join_type: str = "inner",
        join_fields: list[str] | None = None,
    ) -> None:
        super().__init__(
            name="join",
            raw_text=raw_text,
            suggestion="Consider using scheduled queries with correlation or multiple rules",
        )
        self.join_type = join_type
        self.join_fields = join_fields or []


@dataclass
class LookupCommand(UnsupportedCommand):
    """lookup command (unsupported)."""

    lookup_name: str = ""
    lookup_fields: list[str] = field(default_factory=list)

    def __init__(
        self,
        raw_text: str = "",
        lookup_name: str = "",
        lookup_fields: list[str] | None = None,
    ) -> None:
        super().__init__(
            name="lookup",
            raw_text=raw_text,
            suggestion="Use Panther lookup tables with p_lookup() helper",
        )
        self.lookup_name = lookup_name
        self.lookup_fields = lookup_fields or []


@dataclass
class SubsearchCommand(UnsupportedCommand):
    """Subsearch [...] (unsupported)."""

    subsearch_text: str = ""

    def __init__(self, raw_text: str = "", subsearch_text: str = "") -> None:
        super().__init__(
            name="subsearch",
            raw_text=raw_text,
            suggestion="Consider using scheduled queries or correlation rules",
        )
        self.subsearch_text = subsearch_text


@dataclass
class MacroReference(UnsupportedCommand):
    """Macro reference `macro_name` (unsupported)."""

    macro_name: str = ""

    def __init__(self, raw_text: str = "", macro_name: str = "") -> None:
        super().__init__(
            name="macro",
            raw_text=raw_text,
            suggestion="Expand the macro and include the expanded SPL",
        )
        self.macro_name = macro_name


@dataclass
class TransactionCommand(UnsupportedCommand):
    """transaction command (unsupported) - groups events into transactions."""

    fields: list[str] = field(default_factory=list)
    maxspan: str | None = None
    maxpause: str | None = None

    def __init__(
        self,
        raw_text: str = "",
        fields: list[str] | None = None,
        maxspan: str | None = None,
        maxpause: str | None = None,
    ) -> None:
        super().__init__(
            name="transaction",
            raw_text=raw_text,
            suggestion="Consider using scheduled queries for session/sequence analysis",
        )
        self.fields = fields or []
        self.maxspan = maxspan
        self.maxpause = maxpause


# Time Modifiers
@dataclass
class TimeModifier(ASTNode):
    """Time modifiers like earliest=-24h latest=now."""

    earliest: str | None = None
    latest: str | None = None


# Top-level Query
@dataclass
class SPLQuery(ASTNode):
    """Top-level SPL query representation."""

    search_terms: SearchTerm | None = None
    commands: list[Command] = field(default_factory=list)
    time_modifier: TimeModifier | None = None
    index: str | None = None
    sourcetype: str | None = None
    source: str | None = None
    raw_spl: str = ""
