"""
Splunk SPL to Panther Detection Converter.

This module converts Splunk SPL (Search Processing Language) detection rules
into Panther detection rules written in Python.

Example usage:
    ```python
    from panther_sdk.converters.splunk import SPLToPantherConverter

    converter = SPLToPantherConverter()

    spl = '''
    index=okta sourcetype=okta:im:log eventType="user.session.start" outcome.result=FAILURE
    | stats count by actor.alternateId
    | where count > 5
    '''

    result = converter.convert(spl, rule_id="Custom.Okta.BruteForceLogin")

    print(result.source_code)
    ```
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .analyzer import AnalysisResult, RecommendedDetectionType, SPLAnalyzer
from .code_generator import GeneratedRule, PantherCodeGenerator
from .exceptions import (
    SPLCodeGenerationError,
    SPLConversionError,
    SPLLexerError,
    SPLParserError,
    SPLSemanticError,
    SPLTransformError,
    SPLUnsupportedFeatureError,
)
from .lexer import SPLLexer, Token, TokenType
from .parser import SPLParser
from .transformer import SPLToPythonTransformer, TransformResult


@dataclass
class ScheduledRuleRecommendation:
    """A recommendation for a rule that should be a scheduled query."""

    rule_id: str
    class_name: str
    reasons: list[str]
    original_spl: str = ""


@dataclass
class BatchConversionResult:
    """Result of batch conversion with recommendations summary."""

    # All converted rules
    rules: list[GeneratedRule] = field(default_factory=list)

    # Rules recommended for streaming (real-time Python rules)
    streaming_rules: list[GeneratedRule] = field(default_factory=list)

    # Rules recommended for scheduled queries
    scheduled_recommendations: list[ScheduledRuleRecommendation] = field(
        default_factory=list
    )

    # Conversion errors (if any, when fail_fast=False)
    errors: list[str] = field(default_factory=list)

    def get_summary(self) -> str:
        """Get a human-readable summary of the conversion results."""
        lines = [
            f"Converted {len(self.rules)} rules:",
            f"  - Streaming (real-time): {len(self.streaming_rules)}",
            f"  - Recommended for scheduled queries: {len(self.scheduled_recommendations)}",
        ]

        if self.scheduled_recommendations:
            lines.append("")
            lines.append("Rules recommended for SCHEDULED QUERIES:")
            lines.append("-" * 50)
            for rec in self.scheduled_recommendations:
                lines.append(f"  {rec.rule_id} ({rec.class_name})")
                for reason in rec.reasons:
                    lines.append(f"    - {reason}")
                lines.append("")

        if self.errors:
            lines.append("")
            lines.append(f"Errors ({len(self.errors)}):")
            for error in self.errors:
                lines.append(f"  - {error}")

        return "\n".join(lines)


class SPLToPantherConverter:
    """
    Converts Splunk SPL queries to Panther detection rules.

    This is the main entry point for the converter. It orchestrates the
    lexing, parsing, analysis, transformation, and code generation steps.
    """

    def __init__(self, severity: int | str | None = None) -> None:
        """
        Initialize the converter.

        Args:
            severity: Optional default severity for generated rules.
                     Can be an integer (1-6 Splunk scale) or string
                     ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL").
        """
        self.default_severity = severity

    def convert(
        self,
        spl: str,
        rule_id: str,
        class_name: str | None = None,
        severity: int | str | None = None,
    ) -> GeneratedRule:
        """
        Convert an SPL query to a Panther detection rule.

        Args:
            spl: The SPL query string
            rule_id: The Panther rule ID (e.g., "Custom.AWS.SuspiciousActivity")
            class_name: Optional class name for the rule (derived from rule_id if not provided)
            severity: Optional severity override for this specific rule

        Returns:
            GeneratedRule containing the Python source code and metadata

        Raises:
            SPLLexerError: If tokenization fails
            SPLParserError: If parsing fails
            SPLSemanticError: If semantic analysis fails
            SPLTransformError: If transformation fails
            SPLCodeGenerationError: If code generation fails
        """
        try:
            # Step 1: Tokenize
            lexer = SPLLexer(spl)
            tokens = lexer.tokenize()

            # Step 2: Parse
            parser = SPLParser(tokens)
            parser.raw_spl = spl
            ast = parser.parse()

            # Step 3: Analyze
            analyzer = SPLAnalyzer()
            analysis = analyzer.analyze(ast)

            # Apply severity override
            effective_severity = severity or self.default_severity
            if effective_severity is not None:
                analyzer.set_severity(effective_severity)

            # Step 4: Transform
            transformer = SPLToPythonTransformer(analysis)
            transformed = transformer.transform()

            # Step 5: Generate code
            generator = PantherCodeGenerator(analysis, transformed)
            return generator.generate(rule_id, class_name)

        except SPLConversionError:
            raise
        except Exception as e:
            raise SPLConversionError(f"Conversion failed: {e}") from e

    def convert_batch(
        self,
        rules: list[dict[str, Any]],
        fail_fast: bool = False,
    ) -> BatchConversionResult:
        """
        Convert multiple SPL queries to Panther rules.

        Args:
            rules: List of dicts with keys:
                - spl: The SPL query string
                - rule_id: The Panther rule ID
                - class_name: Optional class name
                - severity: Optional severity
            fail_fast: If True, raise on first error. If False, collect errors
                      and continue processing remaining rules.

        Returns:
            BatchConversionResult containing all rules and recommendations summary

        Raises:
            SPLConversionError: If fail_fast=True and any conversion fails
        """
        result = BatchConversionResult()

        for i, rule_def in enumerate(rules):
            try:
                converted = self.convert(
                    spl=rule_def["spl"],
                    rule_id=rule_def["rule_id"],
                    class_name=rule_def.get("class_name"),
                    severity=rule_def.get("severity"),
                )
                result.rules.append(converted)

                # Categorize by recommendation
                if converted.recommended_type == RecommendedDetectionType.SCHEDULED:
                    result.scheduled_recommendations.append(
                        ScheduledRuleRecommendation(
                            rule_id=converted.rule_id,
                            class_name=converted.class_name,
                            reasons=converted.recommendation_reasons,
                            original_spl=rule_def["spl"],
                        )
                    )
                else:
                    result.streaming_rules.append(converted)

            except SPLConversionError as e:
                error_msg = f"Rule {i} ({rule_def.get('rule_id', 'unknown')}): {e}"
                if fail_fast:
                    raise SPLConversionError(error_msg) from e
                result.errors.append(error_msg)

        return result


# Convenience function for quick conversions
def convert_spl(
    spl: str,
    rule_id: str,
    class_name: str | None = None,
    severity: int | str | None = None,
) -> GeneratedRule:
    """
    Convert an SPL query to a Panther detection rule.

    This is a convenience function that creates a converter and calls convert().

    Args:
        spl: The SPL query string
        rule_id: The Panther rule ID (e.g., "Custom.AWS.SuspiciousActivity")
        class_name: Optional class name for the rule
        severity: Optional severity for the rule

    Returns:
        GeneratedRule containing the Python source code and metadata
    """
    converter = SPLToPantherConverter(severity=severity)
    return converter.convert(spl, rule_id, class_name)


__all__ = [
    # Main converter
    "SPLToPantherConverter",
    "convert_spl",
    # Result types
    "GeneratedRule",
    "BatchConversionResult",
    "ScheduledRuleRecommendation",
    "RecommendedDetectionType",
    "AnalysisResult",
    "TransformResult",
    # Exceptions
    "SPLConversionError",
    "SPLLexerError",
    "SPLParserError",
    "SPLSemanticError",
    "SPLTransformError",
    "SPLCodeGenerationError",
    "SPLUnsupportedFeatureError",
    # Components (for advanced usage)
    "SPLLexer",
    "SPLParser",
    "SPLAnalyzer",
    "SPLToPythonTransformer",
    "PantherCodeGenerator",
    "Token",
    "TokenType",
]
