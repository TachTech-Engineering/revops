"""Testing utilities for detection rules and policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..exceptions import DetectionTestError
from .policy import Policy
from .rule import Rule


@dataclass
class TestCase:
    """A test case for a detection rule or policy."""

    name: str
    data: dict[str, Any]
    expected_result: bool
    expected_title: str | None = None
    expected_dedup: str | None = None
    expected_severity: str | None = None
    mocks: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Result of running a test case."""

    name: str
    passed: bool
    expected_result: bool
    actual_result: bool
    error: str | None = None
    title_match: bool | None = None
    dedup_match: bool | None = None
    severity_match: bool | None = None


class DetectionTester:
    """
    Testing utility for detection rules and policies.

    Example:
        ```python
        from panther_sdk.detections import Rule, Severity, LogType
        from panther_sdk.detections.testing import DetectionTester, TestCase

        class MyRule(Rule):
            id = "Custom.MyRule"
            log_types = [LogType.AWS_CLOUDTRAIL]
            severity = Severity.MEDIUM

            def rule(self, event):
                return event.get("eventName") == "DeleteBucket"

            def title(self, event):
                return f"Bucket deleted: {event.get('requestParameters', {}).get('bucketName')}"

        # Create test cases
        tests = [
            TestCase(
                name="Should alert on DeleteBucket",
                data={"eventName": "DeleteBucket", "requestParameters": {"bucketName": "my-bucket"}},
                expected_result=True,
                expected_title="Bucket deleted: my-bucket",
            ),
            TestCase(
                name="Should not alert on CreateBucket",
                data={"eventName": "CreateBucket"},
                expected_result=False,
            ),
        ]

        # Run tests
        tester = DetectionTester(MyRule())
        results = tester.run_tests(tests)

        for result in results:
            print(f"{result.name}: {'PASS' if result.passed else 'FAIL'}")
        ```
    """

    def __init__(self, detection: Rule | Policy) -> None:
        """
        Initialize the tester with a detection.

        Args:
            detection: The rule or policy to test
        """
        self.detection = detection
        self.is_rule = isinstance(detection, Rule)

    def run_test(self, test: TestCase) -> TestResult:
        """
        Run a single test case.

        Args:
            test: The test case to run

        Returns:
            TestResult with pass/fail status
        """
        try:
            # Run the detection logic
            if self.is_rule:
                actual_result = self.detection.rule(test.data)
            else:
                actual_result = self.detection.policy(test.data)

            # Check the main result
            passed = actual_result == test.expected_result

            result = TestResult(
                name=test.name,
                passed=passed,
                expected_result=test.expected_result,
                actual_result=actual_result,
            )

            # Check optional assertions if the detection matched
            if actual_result and passed:
                if test.expected_title is not None:
                    actual_title = self.detection.title(test.data)
                    result.title_match = actual_title == test.expected_title
                    if not result.title_match:
                        result.passed = False
                        result.error = f"Title mismatch: expected '{test.expected_title}', got '{actual_title}'"

                if test.expected_dedup is not None:
                    actual_dedup = self.detection.dedup(test.data)
                    result.dedup_match = actual_dedup == test.expected_dedup
                    if not result.dedup_match:
                        result.passed = False
                        result.error = f"Dedup mismatch: expected '{test.expected_dedup}', got '{actual_dedup}'"

                if test.expected_severity is not None:
                    actual_severity = self.detection.severity_override(test.data)
                    if actual_severity is None:
                        actual_severity = (
                            self.detection.severity
                            if isinstance(self.detection.severity, str)
                            else self.detection.severity.value
                        )
                    result.severity_match = str(actual_severity) == test.expected_severity
                    if not result.severity_match:
                        result.passed = False
                        result.error = f"Severity mismatch: expected '{test.expected_severity}', got '{actual_severity}'"

            return result

        except Exception as e:
            return TestResult(
                name=test.name,
                passed=False,
                expected_result=test.expected_result,
                actual_result=False,
                error=str(e),
            )

    def run_tests(self, tests: list[TestCase]) -> list[TestResult]:
        """
        Run multiple test cases.

        Args:
            tests: List of test cases

        Returns:
            List of TestResult objects
        """
        return [self.run_test(test) for test in tests]

    def assert_tests(self, tests: list[TestCase]) -> None:
        """
        Run tests and raise an exception if any fail.

        Args:
            tests: List of test cases

        Raises:
            DetectionTestError: If any test fails
        """
        results = self.run_tests(tests)
        failed = [r for r in results if not r.passed]

        if failed:
            errors = []
            for result in failed:
                error_msg = f"Test '{result.name}': expected {result.expected_result}, got {result.actual_result}"
                if result.error:
                    error_msg += f" ({result.error})"
                errors.append(error_msg)

            raise DetectionTestError(
                test_name=f"{len(failed)} test(s) failed",
                expected=True,
                actual=False,
                details={"errors": errors},
            )


def run_rule_tests(rule: Rule, tests: list[TestCase] | None = None) -> list[TestResult]:
    """
    Convenience function to run tests on a rule.

    Args:
        rule: The rule to test
        tests: Optional list of test cases. If not provided, uses rule.unit_tests

    Returns:
        List of TestResult objects
    """
    if tests is None:
        tests = [
            TestCase(
                name=t.get("name", f"Test {i}"),
                data=t.get("log", {}),
                expected_result=t.get("expectedResult", False),
            )
            for i, t in enumerate(rule.unit_tests)
        ]

    tester = DetectionTester(rule)
    return tester.run_tests(tests)


def run_policy_tests(policy: Policy, tests: list[TestCase] | None = None) -> list[TestResult]:
    """
    Convenience function to run tests on a policy.

    Args:
        policy: The policy to test
        tests: Optional list of test cases. If not provided, uses policy.unit_tests

    Returns:
        List of TestResult objects
    """
    if tests is None:
        tests = [
            TestCase(
                name=t.get("name", f"Test {i}"),
                data=t.get("resource", {}),
                expected_result=t.get("expectedResult", False),
            )
            for i, t in enumerate(policy.unit_tests)
        ]

    tester = DetectionTester(policy)
    return tester.run_tests(tests)


def test_with_mocks(
    detection: Rule | Policy,
    data: dict[str, Any],
    mocks: dict[str, Any] | None = None,
) -> bool:
    """
    Test a detection with optional mock values.

    This is useful for testing detections that use external helpers
    or lookups that need to be mocked.

    Args:
        detection: The rule or policy to test
        data: The event or resource data
        mocks: Dictionary of mock values (not implemented yet)

    Returns:
        Detection result (True/False)
    """
    # Note: Mock injection would require more complex setup
    # This is a simplified version
    if isinstance(detection, Rule):
        return detection.rule(data)
    return detection.policy(data)
