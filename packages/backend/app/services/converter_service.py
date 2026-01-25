"""Service for Splunk SPL (Search Processing Language) to Panther rule conversion.

Converts Splunk queries into Panther detection rules, supporting both streaming
rules (real-time detection) and scheduled rules (periodic aggregation queries).
"""
import logging
from typing import Any, Optional

from app.services.spl_enhanced_converter import EnhancedSPLConverter, RuleType

logger = logging.getLogger(__name__)

# Try to import the Panther SDK converter
try:
    from panther_sdk.converters.splunk import (
        SPLToPantherConverter,
        SPLConversionError,
    )
    HAS_PANTHER_SDK = True
except ImportError:
    HAS_PANTHER_SDK = False
    SPLConversionError = Exception
    logger.warning("Panther SDK not available, using enhanced fallback converter only")


class ConverterService:
    """Service for Splunk SPL to Panther rule conversion.

    Uses the Panther SDK converter when available, with fallback to an enhanced
    converter for complex Splunk queries with advanced commands like eval, stats,
    bin, timechart, etc.
    """

    def __init__(self) -> None:
        if HAS_PANTHER_SDK:
            self._converter = SPLToPantherConverter()
        else:
            self._converter = None
        self._enhanced_converter = EnhancedSPLConverter()

    async def convert(
        self,
        spl: str,
        rule_id: str,
        class_name: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Convert a single SPL query to a Panther rule.

        Returns the generated rule with source code and metadata.
        Uses SDK converter first, falls back to enhanced converter for complex queries.
        """
        sdk_result = None
        sdk_error = None

        # Try SDK converter first if available
        if self._converter is not None:
            try:
                result = self._converter.convert(
                    spl=spl,
                    rule_id=rule_id,
                    class_name=class_name,
                    severity=severity,
                )
                sdk_result = {
                    "sourceCode": result.source_code,
                    "ruleId": result.rule_id,
                    "className": result.class_name,
                    "logTypes": result.log_types,
                    "severity": result.severity,
                    "isThresholdRule": result.is_threshold_rule,
                    "threshold": result.threshold,
                    "todos": result.todos,
                    "testCode": result.test_code,
                    "recommendedType": result.recommended_type.value,
                    "recommendationReasons": result.recommendation_reasons,
                }

                # If SDK produced good results with few TODOs, return it
                if len(sdk_result.get("todos", [])) <= 2:
                    return sdk_result

                logger.info(f"SDK produced {len(sdk_result.get('todos', []))} TODOs, trying enhanced converter")

            except SPLConversionError as e:
                sdk_error = str(e)
                logger.info(f"SDK conversion failed: {sdk_error}, using enhanced converter")
            except Exception as e:
                sdk_error = str(e)
                logger.warning(f"SDK conversion exception: {sdk_error}, using enhanced converter")

        # Use enhanced converter for complex queries or as fallback
        try:
            enhanced_result = self._enhanced_converter.convert(
                spl=spl,
                rule_id=rule_id,
                class_name=class_name,
                severity=severity,
            )

            result_dict = {
                "sourceCode": enhanced_result.source_code,
                "ruleId": enhanced_result.rule_id,
                "className": enhanced_result.class_name,
                "logTypes": enhanced_result.log_types,
                "severity": enhanced_result.severity,
                "isThresholdRule": enhanced_result.is_threshold_rule,
                "threshold": enhanced_result.threshold,
                "todos": enhanced_result.todos,
                "testCode": enhanced_result.test_code,
                "recommendedType": enhanced_result.recommended_type.value,
                "recommendationReasons": enhanced_result.recommendation_reasons,
            }

            # If we have SDK result, compare and pick the better one
            if sdk_result is not None:
                sdk_todo_count = len(sdk_result.get("todos", []))
                enhanced_todo_count = len(result_dict.get("todos", []))

                # Use SDK result if it has fewer TODOs
                if sdk_todo_count < enhanced_todo_count:
                    logger.info(f"Using SDK result ({sdk_todo_count} TODOs vs {enhanced_todo_count})")
                    return sdk_result
                else:
                    logger.info(f"Using enhanced result ({enhanced_todo_count} TODOs vs {sdk_todo_count})")

            return result_dict

        except Exception as e:
            # If enhanced converter also fails and we have SDK result, return that
            if sdk_result is not None:
                logger.warning(f"Enhanced converter failed: {e}, returning SDK result")
                return sdk_result
            raise ValueError(f"Conversion error: {sdk_error or str(e)}") from e

    async def convert_batch(
        self,
        rules: list[dict[str, Any]],
        fail_fast: bool = False,
    ) -> dict[str, Any]:
        """
        Convert multiple SPL queries.

        Returns all results with summary statistics.
        """
        # Try SDK batch conversion first if available
        if self._converter is not None:
            try:
                result = self._converter.convert_batch(
                    rules=rules,
                    fail_fast=fail_fast,
                )
                return {
                    "rules": [
                        {
                            "sourceCode": r.source_code,
                            "ruleId": r.rule_id,
                            "className": r.class_name,
                            "logTypes": r.log_types,
                            "severity": r.severity,
                            "todos": r.todos,
                            "recommendedType": r.recommended_type.value,
                        }
                        for r in result.rules
                    ],
                    "streamingRulesCount": len(result.streaming_rules),
                    "scheduledRecommendations": [
                        {
                            "ruleId": rec.rule_id,
                            "className": rec.class_name,
                            "reasons": rec.reasons,
                        }
                        for rec in result.scheduled_recommendations
                    ],
                    "errors": result.errors,
                    "summary": result.get_summary(),
                }
            except SPLConversionError as e:
                logger.warning(f"SDK batch conversion failed: {e}, using enhanced converter")
            except Exception as e:
                logger.warning(f"SDK batch conversion exception: {e}, using enhanced converter")

        # Fallback to enhanced converter for batch
        converted_rules = []
        errors = []
        streaming_count = 0
        scheduled_recommendations = []

        for rule_data in rules:
            try:
                spl = rule_data.get("spl", "")
                rule_id = rule_data.get("rule_id", rule_data.get("ruleId", "Custom.Rule"))
                severity = rule_data.get("severity", "MEDIUM")

                result = self._enhanced_converter.convert(
                    spl=spl,
                    rule_id=rule_id,
                    severity=severity,
                )

                converted_rules.append({
                    "sourceCode": result.source_code,
                    "ruleId": result.rule_id,
                    "className": result.class_name,
                    "logTypes": result.log_types,
                    "severity": result.severity,
                    "todos": result.todos,
                    "recommendedType": result.recommended_type.value,
                })

                if result.recommended_type == RuleType.STREAMING:
                    streaming_count += 1
                else:
                    scheduled_recommendations.append({
                        "ruleId": result.rule_id,
                        "className": result.class_name,
                        "reasons": result.recommendation_reasons,
                    })

            except Exception as e:
                if fail_fast:
                    raise ValueError(f"Batch conversion error: {e}") from e
                errors.append(f"Rule {rule_data.get('rule_id', 'unknown')}: {str(e)}")

        return {
            "rules": converted_rules,
            "streamingRulesCount": streaming_count,
            "scheduledRecommendations": scheduled_recommendations,
            "errors": errors,
            "summary": f"Converted {len(converted_rules)} rules, {len(errors)} errors",
        }

    async def validate(self, spl: str) -> dict[str, Any]:
        """
        Validate SPL syntax without full conversion.

        Returns analysis of the query.
        """
        # Try SDK validation first if available
        if HAS_PANTHER_SDK:
            try:
                from panther_sdk.converters.splunk.lexer import SPLLexer
                from panther_sdk.converters.splunk.parser import SPLParser
                from panther_sdk.converters.splunk.analyzer import SPLAnalyzer

                lexer = SPLLexer(spl)
                tokens = lexer.tokenize()

                parser = SPLParser(tokens)
                parser.raw_spl = spl
                ast = parser.parse()

                analyzer = SPLAnalyzer()
                analysis = analyzer.analyze(ast)

                return {
                    "valid": True,
                    "logType": analysis.log_type,
                    "severity": analysis.severity,
                    "isThresholdRule": analysis.is_threshold_rule,
                    "recommendedType": analysis.recommended_type.value,
                    "recommendationReasons": analysis.recommendation_reasons,
                }
            except Exception as e:
                logger.info(f"SDK validation failed: {e}, using enhanced parser")

        # Fallback to enhanced parser
        try:
            parsed = self._enhanced_converter.parse_spl(spl)
            return {
                "valid": True,
                "logType": self._enhanced_converter._infer_log_type(parsed),
                "severity": "MEDIUM",
                "isThresholdRule": parsed.is_threshold_rule,
                "recommendedType": parsed.recommended_type.value,
                "recommendationReasons": [
                    "Contains stats/aggregation commands" if parsed.is_threshold_rule else "No aggregation commands found"
                ],
                "parseDetails": {
                    "index": parsed.index,
                    "sourcetype": parsed.sourcetype,
                    "evalFields": len(parsed.eval_fields),
                    "statsCommands": len(parsed.stats_aggregations),
                    "whereConditions": len(parsed.where_conditions),
                },
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
            }
