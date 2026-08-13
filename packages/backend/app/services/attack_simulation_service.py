"""
Attack Simulation Service.
Orchestrates attack simulations using Atomic Red Team and Stratus Red Team.
Supports manual mode (showing commands) and automated cloud execution.
"""

import asyncio
import logging
import subprocess
import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.time_utils import utcnow
from app.db.models import (
    SimulationFramework,
    SimulationResult,
    SimulationRun,
    SimulationStatus,
    SimulationTemplate,
)

logger = logging.getLogger(__name__)


class ExecutionMode(StrEnum):
    """Execution modes for simulations."""

    MANUAL = "manual"  # Show commands to user
    AUTOMATED = "automated"  # Execute automatically (cloud only)


class AttackSimulationService:
    """Service for managing attack simulations."""

    async def list_templates(
        self,
        db: AsyncSession,
        framework: SimulationFramework | None = None,
        platform: str | None = None,
        tactic: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict], int]:
        """
        List available simulation templates from the database.

        Templates are synced from GitHub via technique_sync_service.
        """
        conditions = [SimulationTemplate.is_enabled.is_(True)]

        if framework:
            conditions.append(SimulationTemplate.framework == framework)

        if platform:
            # Check if platform is in the platforms array
            conditions.append(SimulationTemplate.platforms.contains([platform.lower()]))

        if tactic:
            conditions.append(func.lower(SimulationTemplate.mitre_tactic) == tactic.lower())

        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    SimulationTemplate.name.ilike(search_term),
                    SimulationTemplate.description.ilike(search_term),
                    SimulationTemplate.technique_id.ilike(search_term),
                    SimulationTemplate.mitre_technique_id.ilike(search_term),
                )
            )

        # Get total count
        count_query = select(func.count()).select_from(SimulationTemplate).where(and_(*conditions))
        count_result = await db.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        offset = (page - 1) * page_size
        query = (
            select(SimulationTemplate)
            .where(and_(*conditions))
            .order_by(SimulationTemplate.mitre_technique_id, SimulationTemplate.name)
            .offset(offset)
            .limit(page_size)
        )
        result = await db.execute(query)
        templates = list(result.scalars().all())

        # Convert to response format
        template_list = []
        for t in templates:
            template_dict = {
                "id": t.technique_id,
                "framework": t.framework.value if t.framework else "atomic",
                "technique_id": t.technique_id,
                "mitre_technique_id": t.mitre_technique_id,
                "name": t.name,
                "description": t.description or "",
                "mitre_tactic": t.mitre_tactic or "",
                "mitre_technique": t.mitre_technique or "",
                "platforms": t.platforms or [],
                "is_enabled": t.is_enabled,
                # Manual mode data
                "executor_type": t.executor_type,
                "executor_command": t.executor_command,
                "executor_cleanup": t.executor_cleanup,
                "input_arguments": t.input_arguments or {},
                "dependencies": t.dependencies or [],
                # Cloud execution data
                "cloud_provider": t.cloud_provider,
                "cloud_permissions": t.cloud_permissions or [],
                "detonation_command": t.detonation_command,
                "cleanup_command": t.cleanup_command,
            }
            template_list.append(template_dict)

        return template_list, total

    async def get_template(
        self,
        db: AsyncSession,
        template_id: str,
    ) -> dict | None:
        """Get a specific template by ID."""
        result = await db.execute(
            select(SimulationTemplate).where(SimulationTemplate.technique_id == template_id)
        )
        t = result.scalar_one_or_none()

        if not t:
            return None

        return {
            "id": t.technique_id,
            "framework": t.framework.value if t.framework else "atomic",
            "technique_id": t.technique_id,
            "mitre_technique_id": t.mitre_technique_id,
            "name": t.name,
            "description": t.description or "",
            "mitre_tactic": t.mitre_tactic or "",
            "mitre_technique": t.mitre_technique or "",
            "platforms": t.platforms or [],
            "is_enabled": t.is_enabled,
            "executor_type": t.executor_type,
            "executor_command": t.executor_command,
            "executor_cleanup": t.executor_cleanup,
            "input_arguments": t.input_arguments or {},
            "dependencies": t.dependencies or [],
            "cloud_provider": t.cloud_provider,
            "cloud_permissions": t.cloud_permissions or [],
            "detonation_command": t.detonation_command,
            "cleanup_command": t.cleanup_command,
        }

    async def get_manual_commands(
        self,
        db: AsyncSession,
        template_id: str,
        parameters: dict | None = None,
    ) -> dict:
        """
        Get the manual execution commands for a template.

        Returns the commands the user should run manually on their target system.
        """
        template = await self.get_template(db, template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")

        # Substitute parameters into command
        command = template.get("executor_command", "")
        cleanup_command = template.get("executor_cleanup", "")
        detonation_command = template.get("detonation_command", "")

        input_args = template.get("input_arguments", {})

        # Build parameter substitutions
        substitutions = {}
        for arg_name, arg_info in input_args.items():
            if parameters and arg_name in parameters:
                substitutions[arg_name] = parameters[arg_name]
            elif isinstance(arg_info, dict) and "default" in arg_info:
                substitutions[arg_name] = arg_info["default"]
            else:
                substitutions[arg_name] = f"<{arg_name}>"

        # Substitute in commands
        for var_name, var_value in substitutions.items():
            placeholder = "#{" + var_name + "}"
            command = command.replace(placeholder, str(var_value))
            cleanup_command = cleanup_command.replace(placeholder, str(var_value))

        # For Stratus RT, use the detonation command
        if template.get("framework") == "stratus":
            command = detonation_command or f"stratus detonate {template_id}"
            cleanup_command = (
                template.get("cleanup_command", "") or f"stratus cleanup {template_id}"
            )

        return {
            "template_id": template_id,
            "name": template.get("name"),
            "framework": template.get("framework"),
            "executor_type": template.get("executor_type"),
            "platform": template.get("platforms", [])[0] if template.get("platforms") else None,
            "cloud_provider": template.get("cloud_provider"),
            "execution_command": command,
            "cleanup_command": cleanup_command,
            "input_arguments": input_args,
            "applied_parameters": substitutions,
            "dependencies": template.get("dependencies", []),
            "cloud_permissions": template.get("cloud_permissions", []),
            "instructions": self._get_manual_instructions(template),
        }

    def _get_manual_instructions(self, template: dict) -> list[str]:
        """Generate manual execution instructions."""
        instructions = []
        framework = template.get("framework")

        if framework == "stratus":
            cloud = template.get("cloud_provider", "aws")
            instructions.append(
                "1. Ensure you have Stratus Red Team installed: "
                "`go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest`"
            )
            instructions.append(f"2. Configure {cloud.upper()} credentials in your environment")
            if template.get("cloud_permissions"):
                perms = ", ".join(template.get("cloud_permissions", []))
                instructions.append(f"3. Required IAM permissions: {perms}")
            instructions.append("4. Run the execution command below")
            instructions.append("5. After testing, run the cleanup command")
        else:
            executor_type = template.get("executor_type", "")
            if executor_type == "powershell":
                instructions.append("1. Open PowerShell as Administrator")
                instructions.append(
                    "2. Set execution policy if needed: `Set-ExecutionPolicy Bypass -Scope Process`"
                )
            elif executor_type == "command_prompt":
                instructions.append("1. Open Command Prompt as Administrator")
            elif executor_type == "bash":
                instructions.append("1. Open a terminal with appropriate permissions")
            elif executor_type == "sh":
                instructions.append("1. Open a shell with appropriate permissions")

            if template.get("dependencies"):
                instructions.append("2. Install dependencies if needed (see dependencies list)")
            instructions.append("3. Run the execution command below")
            if template.get("executor_cleanup"):
                instructions.append(
                    "4. After testing, run the cleanup command to restore system state"
                )

        return instructions

    async def run_simulation(
        self,
        db: AsyncSession,
        template_id: str,
        targets: list[str],
        triggered_by: str,
        organization_id: uuid.UUID,
        mode: ExecutionMode = ExecutionMode.MANUAL,
        parameters: dict | None = None,
    ) -> SimulationRun:
        """
        Record a simulation run.

        For manual mode: Records the run and returns commands to execute.
        For automated mode: Attempts to execute Stratus RT commands directly.
        """
        # Get template from database
        result = await db.execute(
            select(SimulationTemplate).where(SimulationTemplate.technique_id == template_id)
        )
        template = result.scalar_one_or_none()

        if not template:
            raise ValueError(f"Template not found: {template_id}")

        # Create simulation run
        run = SimulationRun(
            organization_id=organization_id,
            template_id=template.id,
            status=SimulationStatus.PENDING,
            targets=targets,
            triggered_by=triggered_by,
            detection_expected=True,
        )
        db.add(run)
        await db.flush()

        # For manual mode, just record the run
        if mode == ExecutionMode.MANUAL:
            run.status = SimulationStatus.RUNNING
            run.started_at = utcnow()

            # Create result records for each target
            for target in targets:
                sim_result = SimulationResult(
                    organization_id=organization_id,
                    run_id=run.id,
                    target=target,
                    success=True,  # Manual execution assumed successful
                    output="Manual execution - verify detection in Panther",
                    detection_details={
                        "mode": "manual",
                        "instructions": "User executing manually",
                    },
                )
                db.add(sim_result)

            await db.commit()
            await db.refresh(run)
            return run

        # Automated mode - only for Stratus RT with cloud execution
        if template.framework != SimulationFramework.STRATUS_RED_TEAM:
            raise ValueError(
                "Automated execution only supported for Stratus Red Team cloud techniques"
            )

        run.status = SimulationStatus.RUNNING
        run.started_at = utcnow()
        await db.flush()

        try:
            # Execute for each target (cloud provider)
            for target in targets:
                exec_result = await self._execute_stratus(
                    template.technique_id,
                    template.cloud_provider or target,
                    parameters,
                )

                sim_result = SimulationResult(
                    organization_id=organization_id,
                    run_id=run.id,
                    target=target,
                    success=exec_result.get("success", False),
                    output=exec_result.get("output", ""),
                    detection_details=exec_result,
                )
                db.add(sim_result)

            run.status = SimulationStatus.COMPLETED
            run.completed_at = utcnow()

        except Exception as e:
            logger.error(f"Simulation execution failed: {e}")
            run.status = SimulationStatus.FAILED
            run.error_message = str(e)
            run.completed_at = utcnow()

        await db.commit()
        await db.refresh(run)
        return run

    async def _execute_stratus(
        self,
        technique_id: str,
        cloud: str,
        parameters: dict | None = None,
    ) -> dict:
        """
        Execute a Stratus Red Team technique.

        Requires stratus-red-team CLI to be installed and cloud credentials configured.
        """
        # Check if we have credentials
        if cloud == "aws":
            if not settings.aws_access_key_id or not settings.aws_secret_access_key:
                return {
                    "success": False,
                    "output": "AWS credentials not configured",
                    "error": "Missing AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY",
                }

        # Build environment with cloud credentials
        env = {
            "AWS_ACCESS_KEY_ID": settings.aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": settings.aws_secret_access_key,
            "AWS_REGION": settings.aws_region,
        }

        # Extract just the technique name from full ID
        # (e.g., stratus-aws-technique -> aws.technique)
        stratus_id = technique_id
        if stratus_id.startswith("stratus-"):
            stratus_id = stratus_id.replace("stratus-", "").replace("-", ".", 1)

        try:
            # Run stratus detonate command
            result = await asyncio.to_thread(
                subprocess.run,
                ["stratus", "detonate", stratus_id, "--no-warmup"],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                env={**env},
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
                "return_code": result.returncode,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "output": "",
                "error": "Execution timed out after 5 minutes",
            }
        except FileNotFoundError:
            return {
                "success": False,
                "output": "",
                "error": (
                    "stratus-red-team CLI not found. Install with: "
                    "go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest"
                ),
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
            }

    async def cleanup_stratus(
        self,
        db: AsyncSession,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> dict:
        """
        Clean up resources created by a Stratus RT detonation.
        """
        run = await self.get_run(db, run_id, organization_id=organization_id)
        if not run:
            raise ValueError("Simulation run not found")

        # Get template
        result = await db.execute(
            select(SimulationTemplate).where(SimulationTemplate.id == run.template_id)
        )
        template = result.scalar_one_or_none()

        if not template or template.framework != SimulationFramework.STRATUS_RED_TEAM:
            raise ValueError("Cleanup only available for Stratus Red Team techniques")

        stratus_id = template.technique_id
        if stratus_id.startswith("stratus-"):
            stratus_id = stratus_id.replace("stratus-", "").replace("-", ".", 1)

        env = {
            "AWS_ACCESS_KEY_ID": settings.aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": settings.aws_secret_access_key,
            "AWS_REGION": settings.aws_region,
        }

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["stratus", "cleanup", stratus_id],
                capture_output=True,
                text=True,
                timeout=300,
                env={**env},
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    async def get_run(
        self,
        db: AsyncSession,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> SimulationRun | None:
        """Get a simulation run by ID, scoped to the caller's organization."""
        result = await db.execute(
            select(SimulationRun).where(
                and_(
                    SimulationRun.id == run_id,
                    SimulationRun.organization_id == organization_id,
                )
            )
        )
        return result.scalar_one_or_none()

    async def list_runs(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID,
        status: SimulationStatus | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[SimulationRun], int]:
        """List simulation runs for an organization with optional filtering."""
        conditions = [SimulationRun.organization_id == organization_id]

        if status:
            conditions.append(SimulationRun.status == status)

        # Get total count
        count_query = select(func.count()).select_from(SimulationRun).where(and_(*conditions))
        count_result = await db.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        query = select(SimulationRun).where(and_(*conditions))

        offset = (page - 1) * page_size
        query = query.order_by(SimulationRun.created_at.desc()).offset(offset).limit(page_size)

        result = await db.execute(query)
        runs = list(result.scalars().all())

        return runs, total

    async def get_run_results(
        self,
        db: AsyncSession,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> list[SimulationResult]:
        """Get results for a simulation run, scoped to the caller's organization."""
        result = await db.execute(
            select(SimulationResult).where(
                and_(
                    SimulationResult.run_id == run_id,
                    SimulationResult.organization_id == organization_id,
                )
            )
        )
        return list(result.scalars().all())

    async def verify_detection(
        self,
        db: AsyncSession,
        run_id: uuid.UUID,
        panther_service,
        organization_id: uuid.UUID,
    ) -> dict:
        """
        Verify if the simulation triggered any detections in Panther.
        """
        run = await self.get_run(db, run_id, organization_id=organization_id)
        if not run:
            raise ValueError("Simulation run not found")

        # Get the template
        result = await db.execute(
            select(SimulationTemplate).where(SimulationTemplate.id == run.template_id)
        )
        template = result.scalar_one_or_none()

        if not template:
            raise ValueError("Template not found")

        detection_found = False
        detection_details = []

        try:
            # Search for alerts in the time window
            alerts = await panther_service.list_alerts(
                start_time=run.started_at.isoformat() if run.started_at else None,
                end_time=utcnow().isoformat(),
            )

            # Look for alerts related to this technique
            for alert in alerts.get("edges", []):
                alert_node = alert.get("node", {})
                alert_tags = alert_node.get("tags", [])
                alert_title = alert_node.get("title", "").lower()

                # Match by MITRE technique ID
                technique_id = (template.mitre_technique_id or template.technique_id).lower()
                technique_name = template.name.lower() if template.name else ""

                if (
                    technique_id in str(alert_tags).lower()
                    or technique_id in alert_title
                    or technique_name in alert_title
                ):
                    detection_found = True
                    detection_details.append(
                        {
                            "alert_id": alert_node.get("id"),
                            "title": alert_node.get("title"),
                            "severity": alert_node.get("severity"),
                            "created_at": alert_node.get("createdAt"),
                        }
                    )

        except Exception as e:
            return {
                "run_id": str(run_id),
                "status": "error",
                "error": str(e),
                "detection_found": False,
            }

        # Update run with detection status
        run.detection_found = detection_found
        if detection_details:
            run.detection_rule_id = detection_details[0].get("alert_id")

        await db.commit()

        return {
            "run_id": str(run_id),
            "technique_id": template.technique_id,
            "technique_name": template.name,
            "mitre_technique_id": template.mitre_technique_id,
            "status": "verified",
            "detection_found": detection_found,
            "detection_count": len(detection_details),
            "detections": detection_details,
            "time_to_detect": (
                (
                    datetime.fromisoformat(
                        detection_details[0]["created_at"].replace("Z", "+00:00")
                    ).replace(tzinfo=None)
                    - run.started_at
                ).total_seconds()
                if detection_details and run.started_at
                else None
            ),
        }

    async def mark_run_executed(
        self,
        db: AsyncSession,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> SimulationRun:
        """
        Mark a manual run as executed (user confirmed they ran the commands).
        """
        run = await self.get_run(db, run_id, organization_id=organization_id)
        if not run:
            raise ValueError("Simulation run not found")

        run.status = SimulationStatus.COMPLETED
        run.completed_at = utcnow()

        await db.commit()
        await db.refresh(run)
        return run

    async def get_stats(self, db: AsyncSession, organization_id: uuid.UUID) -> dict:
        """Get simulation statistics for an organization."""
        org_filter = SimulationRun.organization_id == organization_id

        # Total runs
        total_result = await db.execute(
            select(func.count()).select_from(SimulationRun).where(org_filter)
        )
        total = total_result.scalar() or 0

        # By status
        status_counts = {}
        for status in SimulationStatus:
            result = await db.execute(
                select(func.count())
                .select_from(SimulationRun)
                .where(and_(org_filter, SimulationRun.status == status))
            )
            status_counts[status.value] = result.scalar() or 0

        # Detection rate
        detected_result = await db.execute(
            select(func.count())
            .select_from(SimulationRun)
            .where(and_(org_filter, SimulationRun.detection_found.is_(True)))
        )
        detected = detected_result.scalar() or 0

        completed = status_counts.get("completed", 0)
        detection_rate = (detected / completed * 100) if completed > 0 else 0

        # Template counts
        atomic_count = await db.execute(
            select(func.count())
            .select_from(SimulationTemplate)
            .where(SimulationTemplate.framework == SimulationFramework.ATOMIC_RED_TEAM)
        )
        stratus_count = await db.execute(
            select(func.count())
            .select_from(SimulationTemplate)
            .where(SimulationTemplate.framework == SimulationFramework.STRATUS_RED_TEAM)
        )

        return {
            "total_runs": total,
            "by_status": status_counts,
            "detections": {
                "found": detected,
                "completed_runs": completed,
                "detection_rate": round(detection_rate, 1),
            },
            "templates": {
                "atomic_red_team": atomic_count.scalar() or 0,
                "stratus_red_team": stratus_count.scalar() or 0,
            },
        }


# Singleton instance
attack_simulation_service = AttackSimulationService()
