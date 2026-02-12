"""Detection framework for the Panther SDK."""

from ..models.common import LogType, Severity
from .helpers import (
    aws_cloudtrail_success,
    aws_guardduty_context,
    box_event_type_match,
    deep_get,
    extract_domain,
    get_val,
    is_aws_account_id,
    is_aws_arn,
    is_ip_in_network,
    is_private_ip,
    is_public_ip,
    okta_actor,
    okta_event_outcome,
    pattern_match,
    pattern_match_list,
)
from .policy import Policy
from .rule import Rule
from .scheduled_rule import ScheduledRule
from .testing import (
    DetectionTester,
    TestCase,
    TestResult,
    run_policy_tests,
    run_rule_tests,
    test_with_mocks,
)

__all__ = [
    # Base classes
    "Rule",
    "Policy",
    "ScheduledRule",
    # Enums
    "Severity",
    "LogType",
    # Testing
    "DetectionTester",
    "TestCase",
    "TestResult",
    "run_rule_tests",
    "run_policy_tests",
    "test_with_mocks",
    # Helpers
    "deep_get",
    "get_val",
    "is_ip_in_network",
    "is_private_ip",
    "is_public_ip",
    "pattern_match",
    "pattern_match_list",
    "extract_domain",
    "is_aws_account_id",
    "is_aws_arn",
    "aws_cloudtrail_success",
    "aws_guardduty_context",
    "okta_event_outcome",
    "okta_actor",
    "box_event_type_match",
]
