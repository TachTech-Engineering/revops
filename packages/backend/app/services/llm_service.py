"""
LLM Service for AI-powered alert and incident summarization.
Supports both OpenAI and Anthropic providers.
"""

import json
import logging
import uuid
from datetime import timedelta

import httpx
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.time_utils import utcnow
from app.db.models import AISummaryCache, LLMProvider
from app.services.encryption_service import decrypt_credential

logger = logging.getLogger(__name__)


class LLMService:
    """Service for LLM-powered summarization."""

    # Prompt templates
    ALERT_SUMMARY_PROMPT = """Analyze the following security alert and provide a concise
summary for a security analyst.

Alert Data:
{alert_data}

Please provide:
1. **Summary**: A 2-3 sentence overview of what this alert indicates
2. **Risk Assessment**: The potential impact and urgency (Critical/High/Medium/Low)
3. **Key Indicators**: The most important IOCs or suspicious patterns
4. **Recommended Actions**: 2-3 immediate steps the analyst should take

Keep the response focused and actionable. Use bullet points where appropriate."""

    INCIDENT_SUMMARY_PROMPT = """Analyze the following security incident containing multiple
related alerts and provide an executive summary.

Incident Data:
{incident_data}

Please provide:
1. **Executive Summary**: A brief overview of the incident suitable for management
2. **Attack Timeline**: Key events in chronological order
3. **Scope of Impact**: Systems, users, or data potentially affected
4. **Root Cause Analysis**: Likely attack vector or vulnerability exploited
5. **Containment Status**: Current state and any immediate actions taken
6. **Recommendations**: Prioritized remediation steps

Be concise but thorough. This summary should enable quick decision-making."""

    async def summarize_alert(
        self,
        db: AsyncSession,
        alert_id: str,
        alert_data: dict,
        provider: LLMProvider | None = None,
        force_refresh: bool = False,
    ) -> dict:
        """
        Generate or retrieve a cached summary for an alert.

        Args:
            db: Database session
            alert_id: Alert identifier
            alert_data: Alert data to summarize
            provider: LLM provider to use (defaults to configured default)
            force_refresh: If True, bypass cache and generate new summary

        Returns:
            Dictionary with summary and metadata
        """
        provider = provider or LLMProvider(settings.default_llm_provider)

        # Check cache first
        if not force_refresh:
            cached = await self._get_cached_summary(db, "alert", alert_id)
            if cached:
                return {
                    "summary": cached.summary_text,
                    "model": cached.model_used,
                    "provider": cached.provider.value,
                    "cached": True,
                    "generated_at": cached.created_at.isoformat(),
                    "input_tokens": cached.input_tokens,
                    "output_tokens": cached.output_tokens,
                }

        # Generate new summary
        prompt = self.ALERT_SUMMARY_PROMPT.format(
            alert_data=json.dumps(self._sanitize_alert_data(alert_data), indent=2)
        )

        result = await self._call_llm(prompt, provider)

        # Cache the result
        await self._cache_summary(
            db,
            resource_type="alert",
            resource_id=alert_id,
            summary_text=result["summary"],
            model_used=result["model"],
            provider=provider,
            input_tokens=result.get("input_tokens", 0),
            output_tokens=result.get("output_tokens", 0),
        )

        return {
            "summary": result["summary"],
            "model": result["model"],
            "provider": provider.value,
            "cached": False,
            "generated_at": utcnow().isoformat(),
            "input_tokens": result.get("input_tokens", 0),
            "output_tokens": result.get("output_tokens", 0),
        }

    async def summarize_incident(
        self,
        db: AsyncSession,
        incident_id: str,
        incident_data: dict,
        provider: LLMProvider | None = None,
        force_refresh: bool = False,
    ) -> dict:
        """
        Generate or retrieve a cached summary for an incident.

        Args:
            db: Database session
            incident_id: Incident identifier
            incident_data: Incident data including related alerts
            provider: LLM provider to use
            force_refresh: If True, bypass cache

        Returns:
            Dictionary with summary and metadata
        """
        provider = provider or LLMProvider(settings.default_llm_provider)

        # Check cache first
        if not force_refresh:
            cached = await self._get_cached_summary(db, "incident", incident_id)
            if cached:
                return {
                    "summary": cached.summary_text,
                    "model": cached.model_used,
                    "provider": cached.provider.value,
                    "cached": True,
                    "generated_at": cached.created_at.isoformat(),
                    "input_tokens": cached.input_tokens,
                    "output_tokens": cached.output_tokens,
                }

        # Generate new summary
        prompt = self.INCIDENT_SUMMARY_PROMPT.format(
            incident_data=json.dumps(self._sanitize_incident_data(incident_data), indent=2)
        )

        result = await self._call_llm(prompt, provider)

        # Cache the result
        await self._cache_summary(
            db,
            resource_type="incident",
            resource_id=incident_id,
            summary_text=result["summary"],
            model_used=result["model"],
            provider=provider,
            input_tokens=result.get("input_tokens", 0),
            output_tokens=result.get("output_tokens", 0),
        )

        return {
            "summary": result["summary"],
            "model": result["model"],
            "provider": provider.value,
            "cached": False,
            "generated_at": utcnow().isoformat(),
            "input_tokens": result.get("input_tokens", 0),
            "output_tokens": result.get("output_tokens", 0),
        }

    # Default system prompt used when a caller does not supply one.
    DEFAULT_SYSTEM_PROMPT = (
        "You are a security analyst assistant that helps analyze and summarize "
        "security alerts and incidents."
    )

    async def _call_llm(
        self,
        prompt: str,
        provider: LLMProvider,
        system: str | None = None,
        max_tokens: int = 2000,
    ) -> dict:
        """Call the appropriate LLM provider using system (global) keys."""
        if provider == LLMProvider.OPENAI:
            return await self._call_openai(prompt, system=system, max_tokens=max_tokens)
        elif provider == LLMProvider.ANTHROPIC:
            return await self._call_anthropic(prompt, system=system, max_tokens=max_tokens)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

    async def _call_openai(
        self, prompt: str, system: str | None = None, max_tokens: int = 2000
    ) -> dict:
        """Call OpenAI API."""
        if not settings.openai_api_key:
            raise ValueError("OpenAI API key not configured")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.openai_model,
                    "messages": [
                        {"role": "system", "content": system or self.DEFAULT_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
                timeout=60.0,
            )

            if response.status_code == 401:
                raise ValueError("Invalid OpenAI API key")
            elif response.status_code == 429:
                raise ValueError("OpenAI rate limit exceeded")

            response.raise_for_status()
            data = response.json()

            return {
                "summary": data["choices"][0]["message"]["content"],
                "model": settings.openai_model,
                "input_tokens": data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": data.get("usage", {}).get("completion_tokens", 0),
            }

    async def _call_anthropic(
        self, prompt: str, system: str | None = None, max_tokens: int = 2000
    ) -> dict:
        """Call Anthropic API."""
        if not settings.anthropic_api_key:
            raise ValueError("Anthropic API key not configured")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.anthropic_api_key,
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": settings.default_llm_model,
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "user", "content": prompt},
                    ],
                    "system": system or self.DEFAULT_SYSTEM_PROMPT,
                },
                timeout=60.0,
            )

            if response.status_code == 401:
                raise ValueError("Invalid Anthropic API key")
            elif response.status_code == 429:
                raise ValueError("Anthropic rate limit exceeded")

            response.raise_for_status()
            data = response.json()

            return {
                "summary": data["content"][0]["text"],
                "model": settings.default_llm_model,
                "input_tokens": data.get("usage", {}).get("input_tokens", 0),
                "output_tokens": data.get("usage", {}).get("output_tokens", 0),
            }

    async def _get_cached_summary(
        self,
        db: AsyncSession,
        resource_type: str,
        resource_id: str,
    ) -> AISummaryCache | None:
        """Get a cached summary if it exists and hasn't expired."""
        result = await db.execute(
            select(AISummaryCache).where(
                and_(
                    AISummaryCache.resource_type == resource_type,
                    AISummaryCache.resource_id == resource_id,
                    AISummaryCache.expires_at > utcnow(),
                )
            )
        )
        return result.scalar_one_or_none()

    async def _cache_summary(
        self,
        db: AsyncSession,
        resource_type: str,
        resource_id: str,
        summary_text: str,
        model_used: str,
        provider: LLMProvider,
        input_tokens: int,
        output_tokens: int,
        ttl_hours: int = 24,
    ) -> AISummaryCache:
        """Cache a generated summary."""
        # Delete any existing cache entry
        result = await db.execute(
            select(AISummaryCache).where(
                and_(
                    AISummaryCache.resource_type == resource_type,
                    AISummaryCache.resource_id == resource_id,
                )
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            await db.delete(existing)

        # Create new cache entry
        cache_entry = AISummaryCache(
            resource_type=resource_type,
            resource_id=resource_id,
            summary_text=summary_text,
            model_used=model_used,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            expires_at=utcnow() + timedelta(hours=ttl_hours),
        )
        db.add(cache_entry)
        await db.commit()
        await db.refresh(cache_entry)
        return cache_entry

    def _sanitize_alert_data(self, data: dict) -> dict:
        """Remove sensitive or unnecessary fields from alert data."""
        # Fields to include in the summary
        include_fields = [
            "id",
            "title",
            "severity",
            "status",
            "rule",
            "createdAt",
            "description",
            "detection",
            "reference",
            "logTypes",
            "firstEventMatch",
            "lastEventMatch",
            "alertCount",
        ]

        sanitized = {}
        for field in include_fields:
            if field in data:
                sanitized[field] = data[field]

        # Include first event data if available (limited)
        if "events" in data and data["events"]:
            # Only include first event with limited fields
            first_event = data["events"][0] if isinstance(data["events"], list) else data["events"]
            if isinstance(first_event, dict):
                sanitized["sample_event"] = {
                    k: v
                    for k, v in list(first_event.items())[:20]  # Limit to 20 fields
                }

        return sanitized

    def _sanitize_incident_data(self, data: dict) -> dict:
        """Remove sensitive or unnecessary fields from incident data."""
        sanitized = {
            "id": data.get("id"),
            "title": data.get("title"),
            "description": data.get("description"),
            "severity": data.get("severity"),
            "status": data.get("status"),
            "created_at": data.get("created_at"),
            "alert_count": data.get("alert_count", 0),
        }

        # Include summary of alerts
        if "alerts" in data:
            alerts = data["alerts"][:10]  # Limit to 10 alerts
            sanitized["alerts"] = [
                {
                    "title": a.get("title"),
                    "severity": a.get("severity"),
                    "rule": a.get("rule", {}).get("name")
                    if isinstance(a.get("rule"), dict)
                    else a.get("rule"),
                    "createdAt": a.get("createdAt"),
                }
                for a in alerts
            ]

        return sanitized

    async def cluster_alerts(
        self, db: AsyncSession, organization_id: uuid.UUID, alerts: list[dict]
    ) -> dict:
        """
        Generate a name and narrative summary for a cluster of alerts using org-specific keys.
        """
        import logging

        logger = logging.getLogger(__name__)
        logger.info(
            f"Generating AI narrative for cluster with {len(alerts)} alerts "
            f"for org {organization_id}"
        )

        prompt = f"""Analyze this cluster of related security alerts and provide exactly two lines:
NAME: [A concise professional name for this cluster, max 6 words]
STORY: [A one-sentence narrative connecting these events]

Alerts:
{json.dumps(alerts[:10], indent=2)}
"""

        try:
            key_data = await self._get_org_api_key(db, organization_id)
            if key_data:
                result = await self._call_llm_with_key(
                    prompt,
                    LLMProvider(key_data["provider"]),
                    key_data["api_key"],
                    key_data.get("model"),
                )
            else:
                # Fallback to system key, but check which one is actually configured
                if settings.anthropic_api_key:
                    provider = LLMProvider.ANTHROPIC
                elif settings.openai_api_key:
                    provider = LLMProvider.OPENAI
                else:
                    raise ValueError("No LLM keys configured (system or org)")

                result = await self._call_llm(prompt, provider)

            text = result["summary"].strip()
            lines = text.split("\n")

            cluster_name = f"Cluster: {alerts[0].get('title')}"
            narrative = f"Automated cluster of {len(alerts)} alerts."

            for line in lines:
                if line.startswith("NAME:"):
                    cluster_name = line.replace("NAME:", "").strip()
                elif line.startswith("STORY:"):
                    narrative = line.replace("STORY:", "").strip()

            return {"name": cluster_name, "narrative": narrative}
        except Exception as e:
            logger.error(f"AI Narrative generation failed: {str(e)}", exc_info=True)
            return {
                "name": f"Cluster: {alerts[0].get('title', 'Security Events')}",
                "narrative": f"Automated cluster of {len(alerts)} alerts based on shared entities.",
            }

    async def _get_org_api_key(self, db: AsyncSession, organization_id: uuid.UUID) -> dict | None:
        """Fetch and decrypt an active API key for the organization."""
        from app.db import OrganizationAPIKeys

        result = await db.execute(
            select(OrganizationAPIKeys).where(
                and_(
                    OrganizationAPIKeys.organization_id == organization_id,
                    OrganizationAPIKeys.is_active.is_(True),
                )
            )
        )
        key_record = result.scalar_one_or_none()
        if not key_record:
            return None

        decrypted = decrypt_credential(key_record.api_key_encrypted)
        logger.info(f"Retrieved key for {key_record.provider}. Key starts with: {decrypted[:8]}...")

        return {"provider": key_record.provider, "api_key": decrypted, "model": key_record.model}

    async def _call_llm_with_key(
        self,
        prompt: str,
        provider: LLMProvider,
        api_key: str,
        model: str | None = None,
        system: str | None = None,
        max_tokens: int = 2000,
    ) -> dict:
        """Call LLM provider with a specific (per-org) key."""
        if provider == LLMProvider.OPENAI:
            return await self._call_openai_with_key(
                prompt, api_key, model, system=system, max_tokens=max_tokens
            )
        elif provider == LLMProvider.ANTHROPIC:
            return await self._call_anthropic_with_key(
                prompt, api_key, model, system=system, max_tokens=max_tokens
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

    async def generate_completion(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2000,
    ) -> str:
        """Generate a raw text completion for a router/service call site.

        Resolves the organization's encrypted API key first (provider + model
        come from that record) and falls back to the globally configured
        provider key only when the org has none. This is the single entry point
        callers should use instead of constructing provider clients directly.

        Args:
            db: Database session (required to look up the org's encrypted key).
            organization_id: Organization whose key/model should be used.
            prompt: The user prompt.
            system: Optional system prompt (defaults to the security-analyst prompt).
            max_tokens: Response token cap.

        Returns:
            The model's response text.

        Raises:
            ValueError: If no LLM key is configured (org or system).
        """
        key_data = await self._get_org_api_key(db, organization_id)
        if key_data:
            result = await self._call_llm_with_key(
                prompt,
                LLMProvider(key_data["provider"]),
                key_data["api_key"],
                key_data.get("model"),
                system=system,
                max_tokens=max_tokens,
            )
        else:
            # Fall back to whichever global provider key is configured.
            if settings.anthropic_api_key:
                provider = LLMProvider.ANTHROPIC
            elif settings.openai_api_key:
                provider = LLMProvider.OPENAI
            else:
                raise ValueError("No LLM keys configured (system or org)")
            result = await self._call_llm(
                prompt, provider, system=system, max_tokens=max_tokens
            )

        return result["summary"]

    async def get_settings(self) -> dict:
        """Get current LLM configuration."""
        return {
            "default_provider": settings.default_llm_provider,
            "openai": {
                "configured": bool(settings.openai_api_key),
                "model": settings.openai_model,
            },
            "anthropic": {
                "configured": bool(settings.anthropic_api_key),
                "model": settings.default_llm_model,
            },
        }

    async def test_connection(self, provider: LLMProvider) -> dict:
        """Test connection to an LLM provider using configured settings."""
        test_prompt = "Respond with 'Connection successful' if you can read this message."

        try:
            result = await self._call_llm(test_prompt, provider)
            return {
                "status": "success",
                "provider": provider.value,
                "model": result["model"],
                "message": "Connection successful",
            }
        except Exception as e:
            return {
                "status": "error",
                "provider": provider.value,
                "message": str(e),
            }

    async def test_connection_with_key(
        self,
        provider: LLMProvider,
        api_key: str,
        model: str | None = None,
    ) -> dict:
        """Test connection to an LLM provider using a custom API key."""
        test_prompt = "Respond with 'Connection successful' if you can read this message."

        try:
            if provider == LLMProvider.OPENAI:
                result = await self._call_openai_with_key(test_prompt, api_key, model)
            elif provider == LLMProvider.ANTHROPIC:
                result = await self._call_anthropic_with_key(test_prompt, api_key, model)
            else:
                raise ValueError(f"Unsupported provider: {provider}")

            return {
                "status": "success",
                "provider": provider.value,
                "model": result["model"],
                "message": "Connection successful - API key is valid",
            }
        except Exception as e:
            return {
                "status": "error",
                "provider": provider.value,
                "message": str(e),
            }

    async def _call_openai_with_key(
        self,
        prompt: str,
        api_key: str,
        model: str | None = None,
        system: str | None = None,
        max_tokens: int = 100,
    ) -> dict:
        """Call OpenAI API with a custom API key."""
        model_to_use = model or settings.openai_model

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model_to_use,
                    "messages": [
                        {
                            "role": "system",
                            "content": system or "You are a security analyst assistant.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
                timeout=30.0,
            )

            if response.status_code == 401:
                raise ValueError("Invalid OpenAI API key")
            elif response.status_code == 429:
                raise ValueError("OpenAI rate limit exceeded")
            elif response.status_code == 404:
                raise ValueError(f"Model '{model_to_use}' not found or you don't have access")

            response.raise_for_status()
            data = response.json()

            return {
                "summary": data["choices"][0]["message"]["content"],
                "model": model_to_use,
                "input_tokens": data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": data.get("usage", {}).get("completion_tokens", 0),
            }

    async def _call_anthropic_with_key(
        self,
        prompt: str,
        api_key: str,
        model: str | None = None,
        system: str | None = None,
        max_tokens: int = 2000,
    ) -> dict:
        """Call Anthropic API with a custom API key."""
        model_to_use = model or settings.default_llm_model

        async def make_request(m):
            async with httpx.AsyncClient() as client:
                return await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": m,
                        "max_tokens": max_tokens,
                        "messages": [
                            {"role": "user", "content": prompt},
                        ],
                        "system": system or "You are a security analyst assistant.",
                    },
                    timeout=30.0,
                )

        response = await make_request(model_to_use)

        # Fallback logic for 404 Model Not Found
        if response.status_code == 404:
            fallbacks = [
                "claude-3-5-sonnet-20240620",
                "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307",
            ]
            logger.warning(f"Model {model_to_use} not found. Trying fallbacks: {fallbacks}")
            for fallback_model in fallbacks:
                if fallback_model == model_to_use:
                    continue
                response = await make_request(fallback_model)
                if response.status_code != 404:
                    model_to_use = fallback_model
                    break

        if response.status_code == 401:
            raise ValueError("Invalid Anthropic API key")
        elif response.status_code == 429:
            raise ValueError("Anthropic rate limit exceeded")
        elif response.status_code == 404:
            raise ValueError(f"Model '{model_to_use}' and all fallbacks not found")

        response.raise_for_status()
        data = response.json()

        return {
            "summary": data["content"][0]["text"],
            "model": model_to_use,
            "input_tokens": data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": data.get("usage", {}).get("output_tokens", 0),
        }


# Singleton instance
llm_service = LLMService()
