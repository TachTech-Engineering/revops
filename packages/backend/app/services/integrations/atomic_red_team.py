"""
Atomic Red Team integration for attack simulation.
https://github.com/redcanaryco/atomic-red-team
"""

import httpx
import yaml

from app.config import settings


class AtomicRedTeamConnector:
    """Connector for Atomic Red Team attack simulations."""

    # GitHub raw content URL for atomic tests
    GITHUB_BASE_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"
    INDEX_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-Markdown/index.md"

    # Pre-defined subset of commonly used techniques for the UI
    COMMON_TECHNIQUES = [
        {
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "tactic": "credential-access",
            "description": (
                "Adversaries may attempt to dump credentials to obtain account login information."
            ),
            "platforms": ["windows", "linux", "macos"],
            "tests": [
                {"name": "Gsecdump", "description": "Dump credentials using Gsecdump"},
                {"name": "Windows Credential Editor", "description": "Dump credentials using WCE"},
                {"name": "Mimikatz", "description": "Dump LSASS memory using Mimikatz"},
            ],
        },
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "platforms": ["windows"],
            "tests": [
                {
                    "name": "Mimikatz via PowerShell",
                    "description": "Run Mimikatz through PowerShell",
                },
                {"name": "Encoded Command", "description": "Execute base64 encoded PowerShell"},
                {"name": "Download Cradle", "description": "PowerShell download and execute"},
            ],
        },
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task",
            "tactic": "persistence",
            "description": "Adversaries may abuse task scheduling to execute malicious code.",
            "platforms": ["windows"],
            "tests": [
                {
                    "name": "Create Scheduled Task",
                    "description": "Create a scheduled task for persistence",
                },
                {"name": "schtasks.exe", "description": "Use schtasks to create task"},
            ],
        },
        {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "defense-evasion",
            "description": "Adversaries may inject code into processes to evade defenses.",
            "platforms": ["windows", "linux", "macos"],
            "tests": [
                {"name": "Process Hollowing", "description": "Hollow a process and inject code"},
                {"name": "DLL Injection", "description": "Inject a DLL into a running process"},
            ],
        },
        {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "discovery",
            "description": "An adversary may attempt to get detailed information about the OS.",
            "platforms": ["windows", "linux", "macos"],
            "tests": [
                {"name": "System Info Commands", "description": "Run system information commands"},
                {"name": "Hostname Discovery", "description": "Discover system hostname"},
            ],
        },
        {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "command-and-control",
            "description": "Adversaries may transfer tools from an external system.",
            "platforms": ["windows", "linux", "macos"],
            "tests": [
                {"name": "certutil Download", "description": "Use certutil to download file"},
                {"name": "PowerShell Download", "description": "Use PowerShell to download"},
                {"name": "curl Download", "description": "Use curl to download file"},
            ],
        },
        {
            "technique_id": "T1136.001",
            "technique_name": "Create Account: Local Account",
            "tactic": "persistence",
            "description": "Adversaries may create a local account to maintain access.",
            "platforms": ["windows", "linux", "macos"],
            "tests": [
                {"name": "Create Local User", "description": "Create a new local user account"},
                {"name": "net user", "description": "Create user with net user command"},
            ],
        },
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "impact",
            "description": "Adversaries may encrypt data to interrupt availability.",
            "platforms": ["windows", "linux", "macos"],
            "tests": [
                {"name": "GPG Encryption", "description": "Encrypt files using GPG"},
                {"name": "OpenSSL Encryption", "description": "Encrypt files using OpenSSL"},
            ],
        },
    ]

    def __init__(self, base_path: str | None = None):
        self.base_path = base_path or settings.atomic_red_team_path

    async def fetch_techniques(self) -> list[dict]:
        """
        Fetch available Atomic Red Team techniques.

        Returns a curated list of common techniques for the UI.
        """
        return self.COMMON_TECHNIQUES

    async def get_test_by_mitre_id(self, technique_id: str) -> dict | None:
        """
        Get Atomic test details by MITRE technique ID.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1003)

        Returns:
            Test details or None if not found
        """
        # First check our common techniques
        for tech in self.COMMON_TECHNIQUES:
            if tech["technique_id"] == technique_id:
                return tech

        # Try to fetch from GitHub
        try:
            async with httpx.AsyncClient() as client:
                # Try to get the YAML file for this technique
                url = f"{self.GITHUB_BASE_URL}/{technique_id}/{technique_id}.yaml"
                response = await client.get(url, timeout=10.0)

                if response.status_code == 200:
                    data = yaml.safe_load(response.text)
                    return self._parse_atomic_yaml(data)

        except Exception:
            pass

        return None

    def _parse_atomic_yaml(self, data: dict) -> dict:
        """Parse Atomic Red Team YAML file into our format."""
        attack_technique = data.get("attack_technique", "")
        display_name = data.get("display_name", "")

        tests = []
        for test in data.get("atomic_tests", []):
            tests.append(
                {
                    "name": test.get("name", ""),
                    "description": test.get("description", ""),
                    "supported_platforms": test.get("supported_platforms", []),
                    "executor": test.get("executor", {}),
                    "input_arguments": test.get("input_arguments", {}),
                }
            )

        return {
            "technique_id": attack_technique,
            "technique_name": display_name,
            "tests": tests,
        }

    async def execute_test(
        self,
        test_id: str,
        target: str,
        parameters: dict | None = None,
    ) -> dict:
        """
        Execute an Atomic Red Team test.

        Note: This is a simulation placeholder. Real execution would require
        an execution agent deployed on target systems.

        Args:
            test_id: Test identifier (technique_id-test_index)
            target: Target system identifier
            parameters: Optional test parameters

        Returns:
            Execution result
        """
        # In a real implementation, this would:
        # 1. Connect to an execution agent on the target
        # 2. Send the test commands
        # 3. Collect results

        # For now, return a simulated result
        return {
            "test_id": test_id,
            "target": target,
            "status": "simulated",
            "message": "Test execution simulated - requires Atomic Red Team execution agent",
            "output": None,
            "parameters": parameters,
        }


# Singleton instance
atomic_red_team_connector = AtomicRedTeamConnector()
