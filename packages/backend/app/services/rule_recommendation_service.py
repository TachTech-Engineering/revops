"""
Rule Recommendation Service.
Analyzes log sources and recommends detection rules.
"""

import json
import os
import uuid

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RecommendationStatus, RuleRecommendation, RuleRecommendationDismissal


class RuleRecommendationService:
    """Service for generating and managing rule recommendations."""

    def __init__(self):
        self._catalog = None
        self._catalog_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "rule_catalog.json"
        )

    @property
    def catalog(self) -> dict:
        """Load and cache the rule catalog."""
        if self._catalog is None:
            with open(self._catalog_path) as f:
                self._catalog = json.load(f)
        return self._catalog

    async def analyze_log_sources(self, panther_service) -> list[dict]:
        """
        Analyze available log sources from Panther.

        Returns:
            List of log source analysis results
        """
        # Get log sources from Panther
        try:
            # This would call Panther's API to get available log sources
            # For now, we'll return a sample based on common sources
            log_sources = await self._get_log_sources(panther_service)
        except Exception:
            log_sources = []

        analysis = []
        for source in log_sources:
            # Find matching rules in catalog
            matching_rules = [
                rule
                for rule in self.catalog.get("rules", [])
                if source in rule.get("log_sources", [])
            ]

            analysis.append(
                {
                    "log_source": source,
                    "available_rules": len(matching_rules),
                    "rules": [
                        {
                            "id": r["id"],
                            "name": r["name"],
                            "confidence": r["confidence_score"],
                        }
                        for r in matching_rules
                    ],
                }
            )

        return analysis

    async def _get_log_sources(self, panther_service) -> list[str]:
        """Get available log sources from Panther."""
        # Try to get log sources from Panther API
        # Fall back to common sources if not available
        common_sources = [
            "AWS.CloudTrail",
            "Okta.SystemLog",
            "GitHub.Audit",
            "GCP.AuditLog",
            "Azure.SignInLogs",
            "CrowdStrike.FDREvent",
            "Windows.EventLogs",
            "Linux.Syslog",
        ]
        return common_sources

    async def get_recommendations(
        self,
        db: AsyncSession,
        log_sources: list[str] | None = None,
        status: RecommendationStatus | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[RuleRecommendation], int]:
        """
        Get rule recommendations for specified log sources.

        Args:
            db: Database session
            log_sources: Filter by log sources (if None, returns all)
            status: Filter by status
            page: Page number
            page_size: Items per page

        Returns:
            Tuple of (recommendations, total_count)
        """
        conditions = []

        if log_sources:
            conditions.append(RuleRecommendation.log_source.in_(log_sources))

        if status:
            conditions.append(RuleRecommendation.status == status)

        # Get total count
        count_query = select(func.count()).select_from(RuleRecommendation)
        if conditions:
            count_query = count_query.where(and_(*conditions))
        count_result = await db.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        query = select(RuleRecommendation)
        if conditions:
            query = query.where(and_(*conditions))

        offset = (page - 1) * page_size
        query = (
            query.order_by(RuleRecommendation.confidence_score.desc())
            .offset(offset)
            .limit(page_size)
        )

        result = await db.execute(query)
        recommendations = list(result.scalars().all())

        return recommendations, total

    async def generate_recommendations(
        self,
        db: AsyncSession,
        log_sources: list[str],
    ) -> dict:
        """
        Generate recommendations for given log sources based on catalog.

        Args:
            db: Database session
            log_sources: List of log source names

        Returns:
            Dictionary with generation results
        """
        added = 0
        skipped = 0

        for rule in self.catalog.get("rules", []):
            # Check if rule applies to any of the log sources
            rule_sources = rule.get("log_sources", [])
            matching_sources = set(log_sources) & set(rule_sources)

            if not matching_sources:
                continue

            for source in matching_sources:
                # Check if recommendation already exists
                existing = await db.execute(
                    select(RuleRecommendation).where(
                        and_(
                            RuleRecommendation.rule_id == rule["id"],
                            RuleRecommendation.log_source == source,
                        )
                    )
                )
                if existing.scalar_one_or_none():
                    skipped += 1
                    continue

                # Create new recommendation
                recommendation = RuleRecommendation(
                    log_source=source,
                    rule_name=rule["name"],
                    rule_id=rule["id"],
                    rule_code=rule["rule_code"],
                    description=rule.get("description"),
                    mitre_techniques=rule.get("mitre_techniques", []),
                    confidence_score=rule.get("confidence_score", 0.5),
                    status=RecommendationStatus.PENDING,
                )
                db.add(recommendation)
                added += 1

        await db.commit()

        return {
            "added": added,
            "skipped": skipped,
            "total_rules_in_catalog": len(self.catalog.get("rules", [])),
        }

    async def get_coverage_gaps(
        self,
        db: AsyncSession,
        panther_service,
    ) -> list[dict]:
        """
        Identify coverage gaps based on log sources and existing rules.

        Returns:
            List of coverage gap analyses
        """
        gaps = []

        # Get available log sources
        log_sources = await self._get_log_sources(panther_service)

        # Get existing rules from Panther (simplified - would need actual API call)
        existing_rules = set()
        try:
            rules_response = await panther_service.list_rules()
            for rule in rules_response.get("rules", []):
                existing_rules.add(rule.get("id", ""))
        except Exception:
            pass

        # Get accepted recommendations
        accepted_result = await db.execute(
            select(RuleRecommendation).where(
                RuleRecommendation.status == RecommendationStatus.ACCEPTED
            )
        )
        accepted = {r.rule_id for r in accepted_result.scalars().all()}

        for source in log_sources:
            # Find rules that could apply to this source
            applicable_rules = [
                rule
                for rule in self.catalog.get("rules", [])
                if source in rule.get("log_sources", [])
            ]

            # Determine which are missing
            missing_rules = [
                rule
                for rule in applicable_rules
                if rule["id"] not in existing_rules and rule["id"] not in accepted
            ]

            coverage_pct = (
                (len(applicable_rules) - len(missing_rules)) / len(applicable_rules) * 100
                if applicable_rules
                else 100
            )

            gaps.append(
                {
                    "log_source": source,
                    "total_available_rules": len(applicable_rules),
                    "implemented_rules": len(applicable_rules) - len(missing_rules),
                    "missing_rules": len(missing_rules),
                    "coverage_percentage": round(coverage_pct, 1),
                    "missing_rule_details": [
                        {
                            "id": r["id"],
                            "name": r["name"],
                            "mitre_tactic": r.get("mitre_tactic"),
                            "confidence": r.get("confidence_score", 0.5),
                        }
                        for r in missing_rules
                    ],
                }
            )

        # Sort by coverage percentage (lowest first)
        gaps.sort(key=lambda x: x["coverage_percentage"])

        return gaps

    async def accept_recommendation(
        self,
        db: AsyncSession,
        recommendation_id: uuid.UUID,
        panther_service,
        user_email: str,
    ) -> dict:
        """
        Accept a recommendation and create the rule in Panther.

        Args:
            db: Database session
            recommendation_id: Recommendation ID
            panther_service: Panther service instance
            user_email: User accepting the recommendation

        Returns:
            Dictionary with acceptance results
        """
        result = await db.execute(
            select(RuleRecommendation).where(RuleRecommendation.id == recommendation_id)
        )
        recommendation = result.scalar_one_or_none()

        if not recommendation:
            raise ValueError("Recommendation not found")

        if recommendation.status != RecommendationStatus.PENDING:
            raise ValueError(f"Recommendation is already {recommendation.status.value}")

        # Create rule in Panther
        try:
            rule_response = await panther_service.create_rule(
                {
                    "id": recommendation.rule_id,
                    "displayName": recommendation.rule_name,
                    "body": recommendation.rule_code,
                    "severity": "Medium",
                    "logTypes": [recommendation.log_source],
                    "enabled": True,
                    "description": recommendation.description or "",
                }
            )
            panther_rule_id = rule_response.get("id", recommendation.rule_id)
        except Exception as e:
            raise ValueError(f"Failed to create rule in Panther: {str(e)}")

        # Update recommendation status
        recommendation.status = RecommendationStatus.ACCEPTED
        await db.commit()

        return {
            "recommendation_id": str(recommendation_id),
            "rule_id": recommendation.rule_id,
            "panther_rule_id": panther_rule_id,
            "status": "accepted",
            "message": f"Rule '{recommendation.rule_name}' created successfully",
        }

    async def dismiss_recommendation(
        self,
        db: AsyncSession,
        recommendation_id: uuid.UUID,
        user_email: str,
        reason: str | None = None,
    ) -> dict:
        """
        Dismiss a recommendation with an optional reason.

        Args:
            db: Database session
            recommendation_id: Recommendation ID
            user_email: User dismissing the recommendation
            reason: Optional dismissal reason

        Returns:
            Dictionary with dismissal results
        """
        result = await db.execute(
            select(RuleRecommendation).where(RuleRecommendation.id == recommendation_id)
        )
        recommendation = result.scalar_one_or_none()

        if not recommendation:
            raise ValueError("Recommendation not found")

        if recommendation.status == RecommendationStatus.DISMISSED:
            raise ValueError("Recommendation is already dismissed")

        # Create dismissal record
        dismissal = RuleRecommendationDismissal(
            recommendation_id=recommendation_id,
            dismissed_by=user_email,
            reason=reason,
        )
        db.add(dismissal)

        # Update recommendation status
        recommendation.status = RecommendationStatus.DISMISSED
        await db.commit()

        return {
            "recommendation_id": str(recommendation_id),
            "status": "dismissed",
            "dismissed_by": user_email,
            "reason": reason,
        }

    async def get_stats(self, db: AsyncSession) -> dict:
        """Get recommendation statistics."""
        # Total counts by status
        status_counts = {}
        for status in RecommendationStatus:
            result = await db.execute(
                select(func.count())
                .select_from(RuleRecommendation)
                .where(RuleRecommendation.status == status)
            )
            status_counts[status.value] = result.scalar() or 0

        # By log source
        source_result = await db.execute(
            select(RuleRecommendation.log_source, func.count())
            .where(RuleRecommendation.status == RecommendationStatus.PENDING)
            .group_by(RuleRecommendation.log_source)
        )
        by_source = {row[0]: row[1] for row in source_result.all()}

        return {
            "total": sum(status_counts.values()),
            "by_status": status_counts,
            "pending_by_source": by_source,
            "catalog_version": self.catalog.get("version", "unknown"),
            "catalog_rules": len(self.catalog.get("rules", [])),
        }


# Singleton instance
rule_recommendation_service = RuleRecommendationService()
