"""Service for detection rule conversion to Panther.

Converts detection rules from various formats into Panther Python detection rules:
- Splunk SPL (Search Processing Language)
- Google SecOps YARA-L
- IBM QRadar AQL (Ariel Query Language)

Supports both streaming rules (real-time detection) and scheduled rules
(periodic aggregation queries).
"""
import logging
from typing import Any, Optional
from enum import Enum

from app.services.spl_enhanced_converter import EnhancedSPLConverter, RuleType
from app.services.yaral_converter import YARALConverter, yaral_converter
from app.services.aql_converter import AQLConverter, AQLTargetFormat, aql_converter


class SourceFormat(str, Enum):
    """Supported source formats for conversion."""
    SPL = "spl"
    YARAL = "yaral"
    AQL = "aql"

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
    """Service for detection rule conversion to Panther.

    Supports multiple source formats:
    - SPL: Uses Panther SDK converter when available, with fallback to enhanced converter
    - YARA-L: Uses custom YARA-L converter for Google SecOps migration

    """

    def __init__(self) -> None:
        if HAS_PANTHER_SDK:
            self._converter = SPLToPantherConverter()
        else:
            self._converter = None
        self._enhanced_converter = EnhancedSPLConverter()
        self._yaral_converter = yaral_converter
        self._aql_converter = aql_converter

    async def convert(
        self,
        spl: str,
        rule_id: str,
        class_name: Optional[str] = None,
        severity: Optional[str] = None,
        source_format: SourceFormat = SourceFormat.SPL,
        target_format: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Convert a detection rule to a Panther rule.

        Args:
            spl: The source rule (SPL query, YARA-L rule, or AQL query)
            rule_id: Identifier for the generated rule
            class_name: Optional class name for the rule
            severity: Optional severity level
            source_format: Source format (spl, yaral, or aql)
            target_format: Target output format (python or sql) - only used for AQL

        Returns the generated rule with source code and metadata.
        """
        # Handle YARA-L conversion
        if source_format == SourceFormat.YARAL:
            return await self._convert_yaral(spl, rule_id, class_name, severity)

        # Handle AQL conversion
        if source_format == SourceFormat.AQL:
            return await self._convert_aql(spl, rule_id, class_name, severity, target_format)

        # SPL conversion
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

    async def _convert_yaral(
        self,
        yaral: str,
        rule_id: str,
        class_name: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> dict[str, Any]:
        """Convert a YARA-L rule to a Panther rule."""
        try:
            result = self._yaral_converter.convert(
                yaral=yaral,
                rule_id=rule_id,
                class_name=class_name,
                severity=severity,
            )

            return {
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
        except Exception as e:
            raise ValueError(f"YARA-L conversion error: {str(e)}") from e

    async def validate_yaral(self, yaral: str) -> dict[str, Any]:
        """Validate YARA-L syntax."""
        try:
            parsed = self._yaral_converter.parse_yaral(yaral)
            return {
                "valid": True,
                "ruleName": parsed.rule_name,
                "logTypes": parsed.log_types,
                "severity": parsed.meta.get("severity", "MEDIUM"),
                "isMultiEvent": parsed.is_multi_event,
                "recommendedType": parsed.recommended_type.value,
                "recommendationReasons": [
                    "Multi-event correlation" if parsed.is_multi_event else "Single event rule"
                ],
                "parseDetails": {
                    "meta": parsed.meta,
                    "eventCount": len(parsed.events),
                    "hasMatch": bool(parsed.match_section),
                    "hasOutcome": bool(parsed.outcome_section),
                },
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
            }

    async def _convert_aql(
        self,
        aql: str,
        rule_id: str,
        class_name: Optional[str] = None,
        severity: Optional[str] = None,
        target_format: Optional[str] = None,
    ) -> dict[str, Any]:
        """Convert an IBM QRadar AQL query to Python/Panther or SQL."""
        try:
            # Determine target format
            aql_target = AQLTargetFormat.SQL if target_format == "sql" else AQLTargetFormat.PYTHON

            result = self._aql_converter.convert(
                aql=aql,
                rule_id=rule_id,
                class_name=class_name,
                severity=severity,
                target_format=aql_target,
            )

            return {
                "sourceCode": result.source_code,
                "ruleId": result.rule_id,
                "className": result.class_name,
                "logTypes": result.log_types,
                "severity": result.severity,
                "isThresholdRule": result.is_aggregation_rule,
                "threshold": None,
                "todos": result.todos,
                "testCode": "",
                "recommendedType": "SCHEDULED" if result.is_aggregation_rule else "STREAMING",
                "recommendationReasons": [
                    "Aggregation query detected" if result.is_aggregation_rule else "Simple filter query"
                ],
                "targetFormat": result.target_format.value,
                "originalAql": result.original_aql,
            }
        except Exception as e:
            raise ValueError(f"AQL conversion error: {str(e)}") from e

    async def validate_aql(self, aql: str) -> dict[str, Any]:
        """Validate AQL syntax."""
        try:
            parsed = self._aql_converter.parse(aql)
            return {
                "valid": True,
                "fromTable": parsed.from_table,
                "selectFields": parsed.select_fields,
                "isAggregation": parsed.is_aggregation_query,
                "recommendedType": "SCHEDULED" if parsed.is_aggregation_query else "STREAMING",
                "recommendationReasons": [
                    "Contains aggregation functions" if parsed.is_aggregation_query else "Simple filter query"
                ],
                "parseDetails": {
                    "whereConditions": len(parsed.where_conditions),
                    "groupBy": parsed.group_by,
                    "orderBy": parsed.order_by,
                    "timeRange": parsed.time_range,
                    "referenceSets": parsed.reference_sets,
                    "qradarFunctions": parsed.qradar_functions,
                },
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
            }

    def get_supported_formats(self) -> list[dict[str, Any]]:
        """Get list of supported source formats."""
        return [
            {
                "id": "spl",
                "name": "Splunk SPL",
                "description": "Splunk Search Processing Language queries",
                "fileExtensions": [".spl", ".txt"],
                "example": 'index=main sourcetype=access_combined status>=400 | stats count by src_ip',
                "targetFormats": ["python"],
            },
            {
                "id": "yaral",
                "name": "Google SecOps YARA-L",
                "description": "YARA-L detection rules from Google Chronicle/SecOps",
                "fileExtensions": [".yaral", ".yar"],
                "example": '''rule suspicious_login {
  meta:
    description = "Detects suspicious login attempts"
    severity = "HIGH"
  events:
    $login.metadata.event_type = "USER_LOGIN"
    $login.security_result.action = "BLOCK"
  condition:
    $login
}''',
                "targetFormats": ["python"],
            },
            {
                "id": "aql",
                "name": "IBM QRadar AQL",
                "description": "Ariel Query Language from IBM QRadar SIEM",
                "fileExtensions": [".aql", ".txt"],
                "example": "SELECT sourceip, destinationip, username, COUNT(*) FROM events WHERE category = 'Authentication' AND LOGSOURCETYPENAME(logsourceid) ILIKE '%firewall%' GROUP BY sourceip, destinationip, username LAST 24 HOURS",
                "targetFormats": ["python", "sql"],
            },
        ]
