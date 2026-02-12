"""
Converters module for the Panther SDK.

This module provides converters for transforming detection rules from
other SIEM platforms into Panther detection rules.

Currently supported converters:
- Splunk SPL: Convert Splunk Processing Language queries to Panther rules

Example:
    ```python
    from panther_sdk.converters.splunk import SPLToPantherConverter

    converter = SPLToPantherConverter()
    result = converter.convert(
        spl='eventName=DeleteBucket',
        rule_id='Custom.AWS.DeleteBucket'
    )
    print(result.source_code)
    ```
"""

from .splunk import (
    SPLToPantherConverter,
    convert_spl,
    GeneratedRule,
    SPLConversionError,
)

__all__ = [
    "SPLToPantherConverter",
    "convert_spl",
    "GeneratedRule",
    "SPLConversionError",
]
