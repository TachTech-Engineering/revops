"""AI-Assisted Detection Rule Converter using LLM APIs.

Uses Anthropic or OpenAI to intelligently convert detection rules between SIEM formats,
understanding context, handling edge cases, and generating accurate code.
"""

import logging
from typing import Optional
from enum import Enum

from app.config import settings

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


class ConversionFormat(str, Enum):
    """Supported conversion formats."""
    SIGMA = "sigma"
    SPL = "spl"
    YARAL = "yaral"
    AQL = "aql"
    KQL = "kql"
    EQL = "eql"
    ESQL = "esql"
    PANTHER = "panther"
    SQL = "sql"


FORMAT_DESCRIPTIONS = {
    ConversionFormat.SIGMA: "Sigma - Universal YAML-based detection format",
    ConversionFormat.SPL: "SPL - Splunk Search Processing Language",
    ConversionFormat.YARAL: "YARA-L - Google SecOps/Chronicle rule language",
    ConversionFormat.AQL: "AQL - IBM QRadar Ariel Query Language",
    ConversionFormat.KQL: "KQL - Microsoft Sentinel Kusto Query Language",
    ConversionFormat.EQL: "EQL - Elastic Event Query Language",
    ConversionFormat.ESQL: "ES|QL - Elastic's new query language",
    ConversionFormat.PANTHER: "Python - Panther SIEM detection rules",
    ConversionFormat.SQL: "SQL - Standard SQL query",
}


CONVERSION_SYSTEM_PROMPT = """You are an expert security detection engineer specializing in converting detection rules between different SIEM platforms.

Your task is to convert detection rules accurately while:
1. Preserving the detection logic and intent
2. Using idiomatic syntax for the target format
3. Handling platform-specific functions and field mappings
4. Adding helpful comments for anything that needs manual review
5. For aggregation queries, using the appropriate pattern (scheduled rules for Panther, etc.)

Important guidelines:
- If exact conversion isn't possible, provide the closest equivalent with TODO comments
- Preserve time ranges, limits, and thresholds
- Map field names to the target platform's conventions
- For Panther Python rules, use the standard format with rule(), title(), and severity() functions
- For Panther aggregation queries, generate Scheduled Rule templates with SQL and Python
- Always output ONLY the converted code, no explanations before or after

Field mapping hints:
- sourceip/src_ip → source.ip, sourceAddress, src
- destinationip/dst_ip → destination.ip, destinationAddress, dst
- username → user.name, userName, user
- process/image → process.name, process.executable.name
- commandline → process.command_line, cmdline
- hostname → host.name, computer_name
"""


# Model configurations
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
OPENAI_MODEL = "gpt-4o"


class AIConverterService:
    """AI-powered detection rule converter using Anthropic or OpenAI."""

    def __init__(self):
        self._anthropic_client = None
        self._openai_client = None

    def _get_anthropic_client(self):
        """Lazy initialization of Anthropic client."""
        if self._anthropic_client is None:
            import anthropic
            api_key = getattr(settings, 'anthropic_api_key', None)
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not configured")
            self._anthropic_client = anthropic.Anthropic(api_key=api_key)
        return self._anthropic_client

    def _get_openai_client(self):
        """Lazy initialization of OpenAI client."""
        if self._openai_client is None:
            import openai
            api_key = getattr(settings, 'openai_api_key', None)
            if not api_key:
                raise ValueError("OPENAI_API_KEY not configured")
            self._openai_client = openai.OpenAI(api_key=api_key)
        return self._openai_client

    def get_available_providers(self, org_has_anthropic: bool = False, org_has_openai: bool = False) -> list[dict]:
        """Get list of available LLM providers based on configured API keys.

        Args:
            org_has_anthropic: Whether the organization has configured an Anthropic key
            org_has_openai: Whether the organization has configured an OpenAI key
        """
        providers = []
        if getattr(settings, 'anthropic_api_key', None) or org_has_anthropic:
            providers.append({
                "id": LLMProvider.ANTHROPIC.value,
                "name": "Anthropic",
                "model": ANTHROPIC_MODEL,
                "description": "Anthropic Sonnet 4 - excellent at code generation",
            })
        if getattr(settings, 'openai_api_key', None) or org_has_openai:
            providers.append({
                "id": LLMProvider.OPENAI.value,
                "name": "OpenAI",
                "model": OPENAI_MODEL,
                "description": "OpenAI GPT-4o - fast and capable",
            })
        return providers

    def _call_llm(
        self,
        provider: LLMProvider,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        messages: Optional[list[dict]] = None,
        api_key: Optional[str] = None,
        model_override: Optional[str] = None,
    ) -> dict | str:
        """
        Call the specified LLM provider.

        Args:
            provider: LLM provider to use
            system_prompt: System prompt for the model
            user_prompt: User prompt (used if messages is None)
            max_tokens: Maximum tokens in response
            messages: Optional conversation history (for chat mode)
            api_key: Optional API key (uses org key if provided, else env key)
            model_override: Optional model to use instead of default

        Returns:
            dict with 'content' and 'model' keys if messages provided,
            otherwise returns just the content string for backward compatibility
        """
        if provider == LLMProvider.ANTHROPIC:
            import anthropic
            try:
                # Use provided API key or fall back to cached client
                if api_key:
                    client = anthropic.Anthropic(api_key=api_key)
                else:
                    client = self._get_anthropic_client()

                model = model_override or ANTHROPIC_MODEL

                # Build messages list
                if messages:
                    msg_list = messages
                else:
                    msg_list = [{"role": "user", "content": user_prompt}]

                response = client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    messages=msg_list
                )
                content = response.content[0].text.strip()

                # Return dict for chat mode, string for backward compatibility
                if messages:
                    return {"content": content, "model": model}
                return content

            except anthropic.APIError as e:
                logger.error(f"Anthropic API error: {e}")
                raise

        elif provider == LLMProvider.OPENAI:
            import openai
            try:
                # Use provided API key or fall back to cached client
                if api_key:
                    client = openai.OpenAI(api_key=api_key)
                else:
                    client = self._get_openai_client()

                model = model_override or OPENAI_MODEL

                # Build messages list
                if messages:
                    msg_list = [{"role": "system", "content": system_prompt}] + messages
                else:
                    msg_list = [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ]

                response = client.chat.completions.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=msg_list
                )
                content = response.choices[0].message.content.strip()

                # Return dict for chat mode, string for backward compatibility
                if messages:
                    return {"content": content, "model": model}
                return content

            except openai.APIError as e:
                logger.error(f"OpenAI API error: {e}")
                raise

        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def convert(
        self,
        source_code: str,
        source_format: ConversionFormat,
        target_format: ConversionFormat,
        context: Optional[str] = None,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
        api_key: Optional[str] = None,
        model_override: Optional[str] = None,
    ) -> dict:
        """
        Convert a detection rule using AI.

        Args:
            source_code: The original detection rule code
            source_format: Source SIEM format
            target_format: Target SIEM format
            context: Optional additional context about the rule
            provider: LLM provider to use (anthropic or openai)
            api_key: Optional API key (uses org key if provided)
            model_override: Optional model to use instead of default

        Returns:
            dict with converted_code, model, and success status
        """
        source_desc = FORMAT_DESCRIPTIONS.get(source_format, source_format.value)
        target_desc = FORMAT_DESCRIPTIONS.get(target_format, target_format.value)

        user_prompt = self._build_conversion_prompt(
            source_code, source_format, target_format, source_desc, target_desc, context
        )

        model = model_override or (ANTHROPIC_MODEL if provider == LLMProvider.ANTHROPIC else OPENAI_MODEL)

        try:
            converted_code = self._call_llm(
                provider=provider,
                system_prompt=CONVERSION_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=4096,
                api_key=api_key,
                model_override=model_override,
            )

            # Clean up code blocks if present
            if converted_code.startswith("```"):
                lines = converted_code.split("\n")
                # Remove first line (```language) and last line (```)
                if lines[-1].strip() == "```":
                    lines = lines[1:-1]
                else:
                    lines = lines[1:]
                converted_code = "\n".join(lines)

            return {
                "converted_code": converted_code,
                "source_format": source_format.value,
                "target_format": target_format.value,
                "provider": provider.value,
                "model": model,
                "success": True,
            }

        except Exception as e:
            logger.error(f"Conversion error with {provider}: {e}")
            return {
                "converted_code": "",
                "error": str(e),
                "provider": provider.value,
                "model": model,
                "success": False,
            }

    def _build_conversion_prompt(
        self,
        source_code: str,
        source_format: ConversionFormat,
        target_format: ConversionFormat,
        source_desc: str,
        target_desc: str,
        context: Optional[str],
    ) -> str:
        """Build the conversion prompt."""
        prompt = f"""Convert the following detection rule:

**Source Format:** {source_desc}
**Target Format:** {target_desc}

**Source Code:**
```
{source_code}
```
"""

        if context:
            prompt += f"""
**Additional Context:**
{context}
"""

        # Add format-specific instructions
        if target_format == ConversionFormat.PANTHER:
            prompt += """
**Panther Python Rule Requirements:**
- Use def rule(event) -> bool for the main detection logic
- Use def title(event) -> str for the alert title
- Use def severity(event) -> str returning "INFO", "LOW", "MEDIUM", "HIGH", or "CRITICAL"
- Access event fields with event.get("field_name", default)
- For aggregation queries, create a Scheduled Rule with:
  - A SCHEDULED_QUERY string containing the SQL
  - The rule() function processes each result row
  - Use p_occurs_since('X hours') for time filtering in SQL
"""

        elif target_format == ConversionFormat.SIGMA:
            prompt += """
**Sigma Rule Requirements:**
- Use proper YAML format
- Include title, status, description, author, logsource, detection, and level fields
- Use appropriate logsource (product, category, service)
- Use selection and condition in detection
- Support modifiers like |contains, |startswith, |endswith
"""

        elif target_format == ConversionFormat.YARAL:
            prompt += """
**YARA-L Rule Requirements:**
- Use proper rule syntax with meta, events, and condition sections
- Map to UDM (Unified Data Model) fields
- Use $e for event variable
- Use regex syntax with /pattern/
"""

        elif target_format == ConversionFormat.SPL:
            prompt += """
**Splunk SPL Requirements:**
- Start with appropriate index and sourcetype
- Use | where for filtering
- Use | stats for aggregations
- Use | table for output fields
- Use earliest=-1h or similar for time ranges
"""

        elif target_format == ConversionFormat.KQL:
            prompt += """
**Microsoft Sentinel KQL Requirements:**
- Start with the appropriate table (SecurityEvent, SigninLogs, etc.)
- Use | where for filtering
- Use | summarize for aggregations
- Use | project for output fields
- Use ago(1h) for time ranges
"""

        prompt += "\n**Output only the converted code, no explanations.**"

        return prompt

    def explain_rule(
        self,
        source_code: str,
        source_format: ConversionFormat,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
        api_key: Optional[str] = None,
        model_override: Optional[str] = None,
    ) -> dict:
        """Get an explanation of what a detection rule does."""
        source_desc = FORMAT_DESCRIPTIONS.get(source_format, source_format.value)

        prompt = f"""Explain what this {source_desc} detection rule does in plain English.
Include:
1. What it's detecting (the threat/behavior)
2. The key conditions/filters
3. Any aggregation or correlation logic
4. MITRE ATT&CK mapping if identifiable
5. Potential false positive scenarios

**Rule:**
```
{source_code}
```

Provide a concise but complete explanation."""

        model = model_override or (ANTHROPIC_MODEL if provider == LLMProvider.ANTHROPIC else OPENAI_MODEL)

        try:
            explanation = self._call_llm(
                provider=provider,
                system_prompt="You are a security detection expert who explains detection rules clearly.",
                user_prompt=prompt,
                api_key=api_key,
                model_override=model_override,
                max_tokens=1024,
            )
            return {
                "explanation": explanation,
                "provider": provider.value,
                "model": model,
                "success": True,
            }
        except Exception as e:
            logger.error(f"Explanation error: {e}")
            return {
                "explanation": "",
                "error": str(e),
                "provider": provider.value,
                "model": model,
                "success": False,
            }

    def suggest_improvements(
        self,
        source_code: str,
        source_format: ConversionFormat,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
        api_key: Optional[str] = None,
        model_override: Optional[str] = None,
    ) -> dict:
        """Suggest improvements for a detection rule."""
        source_desc = FORMAT_DESCRIPTIONS.get(source_format, source_format.value)

        prompt = f"""Review this {source_desc} detection rule and suggest improvements:

**Rule:**
```
{source_code}
```

Provide suggestions for:
1. Detection accuracy (reducing false positives/negatives)
2. Performance optimization
3. Additional conditions to consider
4. MITRE ATT&CK coverage
5. Best practices

Be specific and actionable."""

        model = model_override or (ANTHROPIC_MODEL if provider == LLMProvider.ANTHROPIC else OPENAI_MODEL)

        try:
            suggestions = self._call_llm(
                provider=provider,
                system_prompt="You are a security detection expert who provides actionable improvement suggestions.",
                api_key=api_key,
                model_override=model_override,
                user_prompt=prompt,
                max_tokens=1024,
            )
            return {
                "suggestions": suggestions,
                "provider": provider.value,
                "model": model,
                "success": True,
            }
        except Exception as e:
            logger.error(f"Suggestion error: {e}")
            return {
                "suggestions": "",
                "error": str(e),
                "provider": provider.value,
                "model": model,
                "success": False,
            }


# Singleton instance
ai_converter_service = AIConverterService()
