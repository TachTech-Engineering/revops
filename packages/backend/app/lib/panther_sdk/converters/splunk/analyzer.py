"""SPL Semantic Analyzer - Analyzes SPL AST for conversion."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .ast_nodes import (
    AggregationFunction,
    BooleanExpr,
    Command,
    EvalCommand,
    FieldComparison,
    FieldsCommand,
    NotExpr,
    ParenExpr,
    RexCommand,
    SearchTerm,
    SPLQuery,
    StatsCommand,
    SubsearchCommand,
    TableCommand,
    UnsupportedCommand,
    WhereCommand,
)
from .mappings import (
    DEFAULT_DEDUP_PERIOD_MINUTES,
    DEFAULT_SEVERITY,
    get_log_type,
    get_severity,
)


class RecommendedDetectionType(Enum):
    """Recommended Panther detection type based on SPL analysis."""

    STREAMING = "streaming"  # Real-time Python rule
    SCHEDULED = "scheduled"  # Scheduled SQL query


@dataclass
class UnsupportedFeature:
    """Represents an unsupported feature that needs a TODO comment."""

    feature_type: str  # "command", "subsearch", "macro", "pattern"
    description: str
    raw_text: str
    suggestion: str | None = None
    line_number: int | None = None


@dataclass
class ThresholdPattern:
    """Detected threshold pattern from stats count + where count > N."""

    threshold: int
    dedup_field: str | None = None
    aggregation_type: str = "count"


@dataclass
class AnalysisResult:
    """Result of semantic analysis on an SPL query."""

    # Inferred metadata
    log_type: str | None = None
    severity: str = DEFAULT_SEVERITY
    dedup_period_minutes: int = DEFAULT_DEDUP_PERIOD_MINUTES

    # Detected patterns
    threshold_pattern: ThresholdPattern | None = None
    dedup_fields: list[str] = field(default_factory=list)
    alert_context_fields: list[str] = field(default_factory=list)

    # Search conditions (for rule() method)
    search_conditions: list[SearchTerm] = field(default_factory=list)

    # Eval expressions to apply
    eval_expressions: dict[str, Any] = field(default_factory=dict)

    # Rex patterns for extraction
    rex_patterns: list[tuple[str, str]] = field(default_factory=list)  # (field, pattern)

    # Unsupported features
    unsupported_features: list[UnsupportedFeature] = field(default_factory=list)

    # Field renames
    field_renames: dict[str, str] = field(default_factory=dict)

    # Original query for documentation
    original_spl: str = ""

    # Whether this is a threshold/aggregation rule
    is_threshold_rule: bool = False

    # Fields referenced in the query
    referenced_fields: set[str] = field(default_factory=set)

    # Raw index/sourcetype values
    index: str | None = None
    sourcetype: str | None = None

    # Recommendation for detection type
    recommended_type: RecommendedDetectionType = RecommendedDetectionType.STREAMING
    recommendation_reasons: list[str] = field(default_factory=list)


class SPLAnalyzer:
    """Semantic analyzer for SPL queries."""

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self.result: AnalysisResult | None = None

    def analyze(self, query: SPLQuery) -> AnalysisResult:
        """
        Analyze an SPL query AST.

        Args:
            query: Parsed SPL query AST

        Returns:
            AnalysisResult with inferred metadata and patterns
        """
        self.result = AnalysisResult(original_spl=query.raw_spl)

        # Store raw metadata
        self.result.index = query.index
        self.result.sourcetype = query.sourcetype

        # Infer log type from sourcetype/index
        self.result.log_type = get_log_type(query.sourcetype, query.index)

        # Analyze search terms
        if query.search_terms:
            self._analyze_search_terms(query.search_terms)

        # Analyze commands
        self._analyze_commands(query.commands)

        # Detect threshold pattern (stats count ... where count > N)
        self._detect_threshold_pattern(query.commands)

        # Determine recommended detection type
        self._determine_recommended_type(query)

        return self.result

    def _analyze_search_terms(self, term: SearchTerm) -> None:
        """Analyze search terms and extract conditions."""
        if term is None:
            return

        # Add to search conditions (will be converted to rule() logic)
        self.result.search_conditions.append(term)

        # Extract referenced fields
        self._extract_fields_from_term(term)

    def _extract_fields_from_term(self, term: SearchTerm) -> None:
        """Extract field names referenced in search terms."""
        if isinstance(term, FieldComparison):
            # Don't add metadata fields to referenced fields
            if term.field.lower() not in ("index", "sourcetype", "source", "host"):
                self.result.referenced_fields.add(term.field)

        elif isinstance(term, BooleanExpr):
            for operand in term.operands:
                self._extract_fields_from_term(operand)

        elif isinstance(term, ParenExpr) and term.expr:
            self._extract_fields_from_term(term.expr)

        elif isinstance(term, NotExpr) and term.operand:
            self._extract_fields_from_term(term.operand)

    def _analyze_commands(self, commands: list[Command]) -> None:
        """Analyze command pipeline."""
        for command in commands:
            if isinstance(command, StatsCommand):
                self._analyze_stats_command(command)

            elif isinstance(command, EvalCommand):
                self._analyze_eval_command(command)

            elif isinstance(command, WhereCommand):
                self._analyze_where_command(command)

            elif isinstance(command, RexCommand):
                self._analyze_rex_command(command)

            elif isinstance(command, TableCommand):
                self._analyze_table_command(command)

            elif isinstance(command, FieldsCommand):
                self._analyze_fields_command(command)

            elif isinstance(command, UnsupportedCommand):
                self._add_unsupported_feature(command)

            elif isinstance(command, SubsearchCommand):
                self.result.unsupported_features.append(
                    UnsupportedFeature(
                        feature_type="subsearch",
                        description="Subsearch",
                        raw_text=command.raw_text,
                        suggestion=command.suggestion,
                    )
                )

    def _analyze_stats_command(self, command: StatsCommand) -> None:
        """Analyze a stats command."""
        # Check for count aggregation
        has_count = any(agg.function == AggregationFunction.COUNT for agg in command.aggregations)

        if has_count:
            self.result.is_threshold_rule = True

        # Capture BY fields for dedup
        if command.by_fields:
            self.result.dedup_fields.extend(command.by_fields)
            for field in command.by_fields:
                self.result.referenced_fields.add(field)

    def _analyze_eval_command(self, command: EvalCommand) -> None:
        """Analyze an eval command."""
        self.result.eval_expressions.update(command.assignments)

        # Extract referenced fields from eval expressions
        for field_name in command.assignments:
            self.result.referenced_fields.add(field_name)

    def _analyze_where_command(self, command: WhereCommand) -> None:
        """Analyze a where command."""
        # Where commands after stats often define thresholds
        # This is handled in _detect_threshold_pattern
        pass

    def _analyze_rex_command(self, command: RexCommand) -> None:
        """Analyze a rex command."""
        if command.pattern:
            self.result.rex_patterns.append((command.field, command.pattern))
            self.result.referenced_fields.add(command.field)

    def _analyze_table_command(self, command: TableCommand) -> None:
        """Analyze a table command."""
        # Table fields become alert_context fields
        self.result.alert_context_fields.extend(command.fields)
        for field_name in command.fields:
            self.result.referenced_fields.add(field_name)

    def _analyze_fields_command(self, command: FieldsCommand) -> None:
        """Analyze a fields command."""
        if command.include:
            # Fields to include become alert_context candidates
            self.result.alert_context_fields.extend(command.fields)
        for field_name in command.fields:
            self.result.referenced_fields.add(field_name)

    def _detect_threshold_pattern(self, commands: list[Command]) -> None:
        """
        Detect threshold pattern: stats count by X | where count > N.

        This is a common pattern for brute force, failed login detection, etc.
        """
        stats_cmd: StatsCommand | None = None
        where_cmd: WhereCommand | None = None

        # Find stats followed by where
        for i, cmd in enumerate(commands):
            if isinstance(cmd, StatsCommand):
                stats_cmd = cmd
            elif isinstance(cmd, WhereCommand) and stats_cmd:
                where_cmd = cmd
                break

        if not stats_cmd or not where_cmd:
            return

        # Check if stats has a count aggregation
        count_agg = None
        for agg in stats_cmd.aggregations:
            if agg.function == AggregationFunction.COUNT:
                count_agg = agg
                break

        if not count_agg:
            return

        # Try to extract threshold from where condition
        threshold = self._extract_threshold_from_where(where_cmd, count_agg)

        if threshold is not None:
            self.result.threshold_pattern = ThresholdPattern(
                threshold=threshold,
                dedup_field=stats_cmd.by_fields[0] if stats_cmd.by_fields else None,
                aggregation_type="count",
            )
            self.result.is_threshold_rule = True

    def _extract_threshold_from_where(self, where_cmd: WhereCommand, count_agg) -> int | None:
        """Extract threshold value from where condition."""
        from .ast_nodes import EvalBinaryOp, EvalFieldRef, EvalLiteral

        if not where_cmd.condition:
            return None

        condition = where_cmd.condition

        # Look for pattern: count > N or count >= N
        if isinstance(condition, EvalBinaryOp):
            if condition.operator in (">", ">="):
                # Check if left side is count field
                if isinstance(condition.left, EvalFieldRef):
                    field_name = condition.left.field.lower()
                    alias = (count_agg.alias or "count").lower()
                    if field_name == "count" or field_name == alias:
                        # Right side should be a number
                        if isinstance(condition.right, EvalLiteral):
                            if isinstance(condition.right.value, (int, float)):
                                return int(condition.right.value)

        return None

    def _add_unsupported_feature(self, command: UnsupportedCommand) -> None:
        """Add an unsupported command to the results."""
        self.result.unsupported_features.append(
            UnsupportedFeature(
                feature_type="command",
                description=f"Unsupported command: {command.name}",
                raw_text=command.raw_text,
                suggestion=command.suggestion,
            )
        )

    def set_severity(self, severity: int | str | None) -> None:
        """Set the severity for the rule."""
        if self.result:
            self.result.severity = get_severity(severity)

    def _determine_recommended_type(self, query: SPLQuery) -> None:
        """
        Determine whether this SPL is better suited for streaming or scheduled detection.

        Patterns that suggest scheduled queries:
        - Join commands (correlating multiple data sources)
        - Lookup commands (enrichment from reference tables)
        - Subsearches (nested queries)
        - Large time windows (earliest=-7d or more)
        - Complex aggregations (multiple stats, dc, avg, stdev, percentile)
        - Transaction commands (session analysis)
        - Append/appendpipe commands (combining results)
        """
        from .ast_nodes import (
            JoinCommand,
            LookupCommand,
            MacroReference,
            TransactionCommand,
        )

        reasons: list[str] = []

        # Check for join commands
        for cmd in query.commands:
            if isinstance(cmd, JoinCommand):
                reasons.append("Contains JOIN - correlates multiple data sources")

            elif isinstance(cmd, LookupCommand):
                reasons.append("Contains LOOKUP - requires reference table enrichment")

            elif isinstance(cmd, SubsearchCommand):
                reasons.append("Contains subsearch - nested query pattern")

            elif isinstance(cmd, MacroReference):
                reasons.append(f"Contains macro `{cmd.name}` - may expand to complex logic")

            elif isinstance(cmd, TransactionCommand):
                reasons.append("Contains TRANSACTION - session/sequence analysis")

            elif isinstance(cmd, StatsCommand):
                # Check for complex aggregations
                for agg in cmd.aggregations:
                    if agg.function in (
                        AggregationFunction.DC,  # distinct count
                        AggregationFunction.AVG,
                        AggregationFunction.STDEV,
                        AggregationFunction.PERCENTILE,
                        AggregationFunction.MEDIAN,
                    ):
                        reasons.append(
                            f"Contains {agg.function.value}() aggregation - "
                            "statistical analysis over time window"
                        )
                        break

        # Check for large time windows
        if query.time_modifier:
            large_window = self._is_large_time_window(query.time_modifier)
            if large_window:
                reasons.append(
                    f"Large time window ({query.time_modifier.earliest} to "
                    f"{query.time_modifier.latest or 'now'}) - better suited for batch analysis"
                )

        # Check for multiple data sources via sourcetype patterns
        # (This is a heuristic - if they're doing OR on sourcetypes, likely needs correlation)
        if self._has_multiple_sourcetypes(query):
            reasons.append("References multiple sourcetypes - may need cross-source correlation")

        # Set recommendation
        if reasons:
            self.result.recommended_type = RecommendedDetectionType.SCHEDULED
            self.result.recommendation_reasons = reasons
        else:
            self.result.recommended_type = RecommendedDetectionType.STREAMING
            self.result.recommendation_reasons = []

    def _is_large_time_window(self, time_modifier) -> bool:
        """Check if the time window is large (> 24 hours)."""
        if not time_modifier or not time_modifier.earliest:
            return False

        earliest = time_modifier.earliest.lower()

        # Parse relative time like -7d, -24h, -1w
        large_patterns = [
            "-7d",
            "-1w",
            "-30d",
            "-1mon",
            "-1y",
            "-2d",
            "-3d",
            "-4d",
            "-5d",
            "-6d",
            "-48h",
            "-72h",
        ]

        for pattern in large_patterns:
            if earliest.startswith(pattern.replace("-", "-")):
                return True

        # Check for day/week/month patterns
        if any(x in earliest for x in ["d@", "w@", "mon@"]):
            return True

        return False

    def _has_multiple_sourcetypes(self, query: SPLQuery) -> bool:
        """Check if query references multiple sourcetypes."""
        from .ast_nodes import BooleanExpr, BooleanOperator

        if not query.search_terms:
            return False

        # Look for OR conditions on sourcetype
        def check_for_sourcetype_or(term: SearchTerm) -> bool:
            if isinstance(term, BooleanExpr) and term.operator == BooleanOperator.OR:
                sourcetype_count = 0
                for operand in term.operands:
                    if isinstance(operand, FieldComparison):
                        if operand.field.lower() == "sourcetype":
                            sourcetype_count += 1
                if sourcetype_count > 1:
                    return True
                # Recurse
                for operand in term.operands:
                    if check_for_sourcetype_or(operand):
                        return True

            elif isinstance(term, ParenExpr) and term.expr:
                return check_for_sourcetype_or(term.expr)

            return False

        return check_for_sourcetype_or(query.search_terms)
