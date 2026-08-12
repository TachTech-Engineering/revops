"""
Service for syncing attack techniques from Atomic Red Team and Stratus Red Team.

Fetches technique definitions from GitHub and stores them in the database
for use in attack simulations.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import SimulationFramework, SimulationTemplate

logger = logging.getLogger(__name__)

# GitHub API endpoints
ATOMIC_RT_API = "https://api.github.com/repos/redcanaryco/atomic-red-team/contents/atomics"
ATOMIC_RT_RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"

STRATUS_RT_API = (
    "https://api.github.com/repos/DataDog/stratus-red-team/contents/docs/attack-techniques"
)
STRATUS_RT_RAW = "https://raw.githubusercontent.com/DataDog/stratus-red-team/main"

# Cache directory for downloaded techniques
CACHE_DIR = Path("/tmp/attack-techniques-cache")


class TechniqueSyncService:
    """Syncs attack techniques from external repositories."""

    def __init__(self):
        self.http_client: httpx.AsyncClient | None = None
        self._last_sync: datetime | None = None
        self._sync_interval = timedelta(hours=24)

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.http_client is None or self.http_client.is_closed:
            self.http_client = httpx.AsyncClient(
                timeout=30.0, headers={"Accept": "application/vnd.github.v3+json"}
            )
        return self.http_client

    async def sync_all(self, db: AsyncSession, force: bool = False) -> dict:
        """
        Sync all techniques from both Atomic RT and Stratus RT.

        Args:
            db: Database session
            force: Force sync even if recently synced

        Returns:
            Summary of sync results
        """
        if not force and self._last_sync:
            if utcnow() - self._last_sync < self._sync_interval:
                logger.info("Skipping sync - recently synced")
                return {"skipped": True, "reason": "Recently synced"}

        results = {
            "atomic_red_team": {"added": 0, "updated": 0, "errors": []},
            "stratus_red_team": {"added": 0, "updated": 0, "errors": []},
            "synced_at": utcnow().isoformat(),
        }

        try:
            atomic_result = await self.sync_atomic_red_team(db)
            results["atomic_red_team"] = atomic_result
        except Exception as e:
            logger.error(f"Failed to sync Atomic Red Team: {e}")
            results["atomic_red_team"]["errors"].append(str(e))

        try:
            stratus_result = await self.sync_stratus_red_team(db)
            results["stratus_red_team"] = stratus_result
        except Exception as e:
            logger.error(f"Failed to sync Stratus Red Team: {e}")
            results["stratus_red_team"]["errors"].append(str(e))

        self._last_sync = utcnow()
        return results

    async def sync_atomic_red_team(self, db: AsyncSession) -> dict:
        """
        Sync Atomic Red Team techniques from GitHub.

        Atomic RT organizes techniques by MITRE ATT&CK ID (T1001, T1003, etc.)
        Each technique folder contains a YAML file with test definitions.
        """
        client = await self._get_client()
        result = {"added": 0, "updated": 0, "errors": []}

        try:
            # Get list of technique directories
            response = await client.get(ATOMIC_RT_API)
            response.raise_for_status()
            directories = response.json()

            for dir_info in directories:
                if dir_info["type"] != "dir":
                    continue

                technique_id = dir_info["name"]
                if not technique_id.startswith("T"):
                    continue

                try:
                    # Fetch the YAML file for this technique
                    yaml_url = f"{ATOMIC_RT_RAW}/{technique_id}/{technique_id}.yaml"
                    yaml_response = await client.get(yaml_url)

                    if yaml_response.status_code != 200:
                        continue

                    technique_data = yaml.safe_load(yaml_response.text)

                    # Process each atomic test within the technique
                    atomic_tests = technique_data.get("atomic_tests", [])

                    for i, test in enumerate(atomic_tests):
                        template_id = f"atomic-{technique_id}-{i}"

                        # Check if template exists
                        existing = await db.execute(
                            select(SimulationTemplate).where(
                                SimulationTemplate.technique_id == template_id
                            )
                        )
                        existing_template = existing.scalar_one_or_none()

                        # Extract test details
                        platforms = test.get("supported_platforms", [])
                        executor = test.get("executor", {})

                        template_data = {
                            "framework": SimulationFramework.ATOMIC_RED_TEAM,
                            "technique_id": template_id,
                            "mitre_technique_id": technique_id,
                            "name": test.get("name", f"{technique_id} Test {i}"),
                            "description": test.get("description", ""),
                            "mitre_tactic": self._get_tactic_from_technique(technique_id),
                            "mitre_technique": technique_data.get("display_name", technique_id),
                            "platforms": platforms,
                            "executor_type": executor.get("name", "manual"),
                            "executor_command": executor.get("command", ""),
                            "executor_cleanup": executor.get("cleanup_command", ""),
                            "input_arguments": test.get("input_arguments", {}),
                            "dependencies": test.get("dependencies", []),
                            "is_enabled": True,
                        }

                        if existing_template:
                            for key, value in template_data.items():
                                setattr(existing_template, key, value)
                            existing_template.updated_at = utcnow()
                            result["updated"] += 1
                        else:
                            new_template = SimulationTemplate(**template_data)
                            db.add(new_template)
                            result["added"] += 1

                    # Commit after each technique to avoid large transactions
                    await db.commit()

                except Exception as e:
                    logger.warning(f"Failed to process Atomic RT technique {technique_id}: {e}")
                    result["errors"].append(f"{technique_id}: {str(e)}")
                    await db.rollback()

                # Rate limiting
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.error(f"Failed to fetch Atomic RT directory listing: {e}")
            result["errors"].append(str(e))

        return result

    async def sync_stratus_red_team(self, db: AsyncSession) -> dict:
        """
        Sync Stratus Red Team techniques from GitHub.

        Stratus RT focuses on cloud attack techniques for AWS, Azure, GCP.
        Techniques are defined in Go but documented in markdown.
        """
        client = await self._get_client()
        result = {"added": 0, "updated": 0, "errors": []}

        # Stratus techniques by cloud provider (case-sensitive folder names)
        cloud_providers = ["AWS", "azure", "GCP", "kubernetes", "EKS", "entra-id"]

        for provider in cloud_providers:
            try:
                # Get technique list for this provider
                api_url = f"{STRATUS_RT_API}/{provider}"
                response = await client.get(api_url)

                if response.status_code != 200:
                    continue

                files = response.json()

                for file_info in files:
                    if not file_info["name"].endswith(".md"):
                        continue
                    if file_info["name"] == "index.md":
                        continue

                    technique_name = file_info["name"].replace(".md", "")

                    try:
                        # Fetch the markdown file
                        md_url = (
                            f"{STRATUS_RT_RAW}/docs/attack-techniques/"
                            f"{provider}/{file_info['name']}"
                        )
                        md_response = await client.get(md_url)

                        if md_response.status_code != 200:
                            continue

                        # Parse technique info from markdown
                        technique_data = self._parse_stratus_markdown(
                            md_response.text, technique_name, provider
                        )

                        if not technique_data:
                            continue

                        template_id = f"stratus-{provider.lower()}-{technique_name}"

                        # Check if exists
                        existing = await db.execute(
                            select(SimulationTemplate).where(
                                SimulationTemplate.technique_id == template_id
                            )
                        )
                        existing_template = existing.scalar_one_or_none()

                        # Normalize provider name to lowercase for consistency
                        provider_normalized = provider.lower().replace("-", "_")

                        template_data = {
                            "framework": SimulationFramework.STRATUS_RED_TEAM,
                            "technique_id": template_id,
                            "mitre_technique_id": technique_data.get("mitre_id", ""),
                            "name": technique_data.get("name", technique_name),
                            "description": technique_data.get("description", ""),
                            "mitre_tactic": technique_data.get("tactic", ""),
                            "mitre_technique": technique_data.get("mitre_technique", ""),
                            "platforms": [provider_normalized],
                            "cloud_provider": provider_normalized,
                            "cloud_permissions": technique_data.get("permissions", []),
                            "detonation_command": technique_data.get("detonation", ""),
                            "cleanup_command": technique_data.get("cleanup", ""),
                            "is_enabled": True,
                        }

                        if existing_template:
                            for key, value in template_data.items():
                                setattr(existing_template, key, value)
                            existing_template.updated_at = utcnow()
                            result["updated"] += 1
                        else:
                            new_template = SimulationTemplate(**template_data)
                            db.add(new_template)
                            result["added"] += 1

                    except Exception as e:
                        logger.warning(f"Failed to process Stratus technique {technique_name}: {e}")
                        result["errors"].append(f"{technique_name}: {str(e)}")

                await db.commit()
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning(f"Failed to fetch Stratus techniques for {provider}: {e}")
                result["errors"].append(f"{provider}: {str(e)}")

        return result

    def _parse_stratus_markdown(self, content: str, name: str, provider: str) -> dict | None:
        """Parse Stratus technique info from markdown documentation."""
        try:
            result = {
                "name": name.replace("-", " ").title(),
                "description": "",
                "mitre_id": "",
                "mitre_technique": "",
                "tactic": "",
                "permissions": [],
            }

            # Extract title
            title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            if title_match:
                result["name"] = title_match.group(1).strip()

            # Extract MITRE ATT&CK ID
            mitre_match = re.search(r"\[([T\d.]+)\]", content)
            if mitre_match:
                result["mitre_id"] = mitre_match.group(1)

            # Extract description (first paragraph after title)
            desc_match = re.search(r"^#.+\n\n(.+?)(?=\n\n|\n##)", content, re.MULTILINE | re.DOTALL)
            if desc_match:
                result["description"] = desc_match.group(1).strip()

            # Extract tactic
            tactic_match = re.search(
                r"MITRE ATT&CK Tactic[s]?[:\s]+\*?\*?([^*\n]+)", content, re.IGNORECASE
            )
            if tactic_match:
                result["tactic"] = tactic_match.group(1).strip()

            # Extract required permissions
            perm_match = re.search(
                r"Required.*?Permissions?[:\s]+(.+?)(?=\n\n|\n##)",
                content,
                re.IGNORECASE | re.DOTALL,
            )
            if perm_match:
                perms = re.findall(r"`([^`]+)`", perm_match.group(1))
                result["permissions"] = perms

            # Extract detonation instructions
            det_match = re.search(r"## Detonation\n\n```[^\n]*\n(.+?)```", content, re.DOTALL)
            if det_match:
                result["detonation"] = det_match.group(1).strip()

            return result

        except Exception as e:
            logger.warning(f"Failed to parse Stratus markdown for {name}: {e}")
            return None

    def _get_tactic_from_technique(self, technique_id: str) -> str:
        """Map MITRE technique ID to tactic (simplified mapping)."""
        # This is a simplified mapping - in production you'd want the full MITRE data
        tactic_ranges = {
            "Initial Access": [
                "T1189",
                "T1190",
                "T1133",
                "T1200",
                "T1566",
                "T1091",
                "T1195",
                "T1199",
                "T1078",
            ],
            "Execution": [
                "T1059",
                "T1203",
                "T1559",
                "T1106",
                "T1053",
                "T1129",
                "T1072",
                "T1569",
                "T1204",
            ],
            "Persistence": [
                "T1098",
                "T1197",
                "T1547",
                "T1037",
                "T1136",
                "T1543",
                "T1546",
                "T1133",
                "T1574",
            ],
            "Privilege Escalation": [
                "T1548",
                "T1134",
                "T1547",
                "T1037",
                "T1543",
                "T1484",
                "T1546",
                "T1068",
            ],
            "Defense Evasion": [
                "T1548",
                "T1134",
                "T1197",
                "T1140",
                "T1480",
                "T1211",
                "T1222",
                "T1564",
            ],
            "Credential Access": [
                "T1110",
                "T1555",
                "T1212",
                "T1187",
                "T1606",
                "T1056",
                "T1557",
                "T1003",
            ],
            "Discovery": ["T1087", "T1010", "T1217", "T1580", "T1538", "T1526", "T1619", "T1613"],
            "Lateral Movement": ["T1210", "T1534", "T1570", "T1563", "T1021", "T1091", "T1080"],
            "Collection": ["T1560", "T1123", "T1119", "T1115", "T1530", "T1602", "T1213", "T1005"],
            "Exfiltration": [
                "T1020",
                "T1030",
                "T1048",
                "T1041",
                "T1011",
                "T1052",
                "T1567",
                "T1537",
            ],
            "Impact": ["T1531", "T1485", "T1486", "T1565", "T1491", "T1561", "T1499", "T1498"],
        }

        base_technique = technique_id.split(".")[0]

        for tactic, techniques in tactic_ranges.items():
            if base_technique in techniques:
                return tactic

        return "Unknown"

    async def get_sync_status(self, db: AsyncSession) -> dict:
        """Get current sync status and technique counts."""
        atomic_count = await db.execute(
            select(SimulationTemplate).where(
                SimulationTemplate.framework == SimulationFramework.ATOMIC_RED_TEAM
            )
        )
        stratus_count = await db.execute(
            select(SimulationTemplate).where(
                SimulationTemplate.framework == SimulationFramework.STRATUS_RED_TEAM
            )
        )

        return {
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "atomic_red_team_count": len(atomic_count.scalars().all()),
            "stratus_red_team_count": len(stratus_count.scalars().all()),
            "next_sync": (self._last_sync + self._sync_interval).isoformat()
            if self._last_sync
            else "Not synced",
        }

    async def close(self):
        """Close HTTP client."""
        if self.http_client:
            await self.http_client.aclose()


# Singleton instance
technique_sync_service = TechniqueSyncService()
