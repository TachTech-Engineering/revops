"""
Stratus Red Team integration for cloud attack simulation.
https://github.com/DataDog/stratus-red-team
"""

from app.config import settings


class StratusRedTeamConnector:
    """Connector for Stratus Red Team cloud attack simulations."""

    # Pre-defined catalog of Stratus Red Team techniques
    # Based on https://stratus-red-team.cloud/attack-techniques/
    ATTACK_TECHNIQUES = [
        # AWS Techniques
        {
            "id": "aws.credential-access.ec2-get-password-data",
            "name": "Retrieve EC2 Password Data",
            "cloud": "aws",
            "tactic": "credential-access",
            "technique_id": "T1552.005",
            "description": "Retrieves password data for Windows EC2 instances.",
            "detection": "CloudTrail: GetPasswordData API call",
        },
        {
            "id": "aws.credential-access.ec2-steal-instance-credentials",
            "name": "Steal EC2 Instance Credentials",
            "cloud": "aws",
            "tactic": "credential-access",
            "technique_id": "T1552.005",
            "description": "Steals instance credentials from the EC2 metadata service.",
            "detection": "Network traffic to 169.254.169.254",
        },
        {
            "id": "aws.credential-access.secretsmanager-retrieve-secrets",
            "name": "Retrieve Secrets from SecretsManager",
            "cloud": "aws",
            "tactic": "credential-access",
            "technique_id": "T1555",
            "description": "Retrieves secrets from AWS Secrets Manager.",
            "detection": "CloudTrail: GetSecretValue API calls",
        },
        {
            "id": "aws.defense-evasion.cloudtrail-stop",
            "name": "Stop CloudTrail Trail",
            "cloud": "aws",
            "tactic": "defense-evasion",
            "technique_id": "T1562.001",
            "description": "Stops a CloudTrail trail to evade detection.",
            "detection": "CloudTrail: StopLogging API call",
        },
        {
            "id": "aws.defense-evasion.vpc-remove-flow-logs",
            "name": "Remove VPC Flow Logs",
            "cloud": "aws",
            "tactic": "defense-evasion",
            "technique_id": "T1562.001",
            "description": "Removes VPC flow logs to hide network activity.",
            "detection": "CloudTrail: DeleteFlowLogs API call",
        },
        {
            "id": "aws.exfiltration.s3-backdoor-bucket-policy",
            "name": "Backdoor S3 Bucket via Policy",
            "cloud": "aws",
            "tactic": "exfiltration",
            "technique_id": "T1537",
            "description": "Creates a backdoor bucket policy allowing external access.",
            "detection": "CloudTrail: PutBucketPolicy with external principal",
        },
        {
            "id": "aws.initial-access.console-login-without-mfa",
            "name": "Console Login without MFA",
            "cloud": "aws",
            "tactic": "initial-access",
            "technique_id": "T1078.004",
            "description": "Simulates console login without multi-factor authentication.",
            "detection": "CloudTrail: ConsoleLogin without MFA",
        },
        {
            "id": "aws.persistence.iam-create-admin-user",
            "name": "Create IAM Admin User",
            "cloud": "aws",
            "tactic": "persistence",
            "technique_id": "T1136.003",
            "description": "Creates an IAM user with administrator privileges.",
            "detection": "CloudTrail: CreateUser + AttachUserPolicy",
        },
        {
            "id": "aws.persistence.iam-create-backdoor-role",
            "name": "Create Backdoor IAM Role",
            "cloud": "aws",
            "tactic": "persistence",
            "technique_id": "T1098.001",
            "description": "Creates an IAM role with trust relationship to external account.",
            "detection": "CloudTrail: CreateRole with external trust",
        },
        # Azure Techniques
        {
            "id": "azure.credential-access.steal-sp-credentials",
            "name": "Steal Service Principal Credentials",
            "cloud": "azure",
            "tactic": "credential-access",
            "technique_id": "T1552.005",
            "description": "Extracts service principal credentials from Azure AD.",
            "detection": "Azure AD Sign-in logs: Service Principal authentication",
        },
        {
            "id": "azure.defense-evasion.delete-diagnostic-settings",
            "name": "Delete Diagnostic Settings",
            "cloud": "azure",
            "tactic": "defense-evasion",
            "technique_id": "T1562.001",
            "description": "Deletes Azure diagnostic settings to evade logging.",
            "detection": "Azure Activity Log: Delete DiagnosticSettings",
        },
        {
            "id": "azure.persistence.create-backdoor-user",
            "name": "Create Backdoor Azure AD User",
            "cloud": "azure",
            "tactic": "persistence",
            "technique_id": "T1136.003",
            "description": "Creates a backdoor user in Azure AD with elevated privileges.",
            "detection": "Azure AD Audit logs: Add user, Add member to role",
        },
        # GCP Techniques
        {
            "id": "gcp.credential-access.steal-service-account-key",
            "name": "Steal Service Account Key",
            "cloud": "gcp",
            "tactic": "credential-access",
            "technique_id": "T1552.005",
            "description": "Creates and exfiltrates a service account key.",
            "detection": "GCP Audit Log: CreateServiceAccountKey",
        },
        {
            "id": "gcp.defense-evasion.disable-audit-logs",
            "name": "Disable GCP Audit Logs",
            "cloud": "gcp",
            "tactic": "defense-evasion",
            "technique_id": "T1562.001",
            "description": "Modifies IAM policy to disable audit logging.",
            "detection": "GCP Audit Log: SetIamPolicy changes to logging",
        },
        {
            "id": "gcp.persistence.create-admin-service-account",
            "name": "Create Admin Service Account",
            "cloud": "gcp",
            "tactic": "persistence",
            "technique_id": "T1136.003",
            "description": "Creates a service account with owner permissions.",
            "detection": "GCP Audit Log: CreateServiceAccount + SetIamPolicy",
        },
        {
            "id": "gcp.exfiltration.share-bucket-publicly",
            "name": "Share GCS Bucket Publicly",
            "cloud": "gcp",
            "tactic": "exfiltration",
            "technique_id": "T1537",
            "description": "Modifies a GCS bucket to allow public access.",
            "detection": "GCP Audit Log: SetIamPolicy with allUsers",
        },
    ]

    def __init__(self, base_path: str | None = None):
        self.base_path = base_path or settings.stratus_red_team_path

    async def list_attack_techniques(
        self,
        cloud: str | None = None,
        tactic: str | None = None,
    ) -> list[dict]:
        """
        List available Stratus Red Team attack techniques.

        Args:
            cloud: Filter by cloud provider (aws, azure, gcp)
            tactic: Filter by MITRE tactic

        Returns:
            List of attack technique details
        """
        techniques = self.ATTACK_TECHNIQUES

        if cloud:
            techniques = [t for t in techniques if t["cloud"] == cloud.lower()]

        if tactic:
            techniques = [t for t in techniques if t["tactic"] == tactic.lower()]

        return techniques

    async def get_technique(self, technique_id: str) -> dict | None:
        """
        Get details for a specific technique.

        Args:
            technique_id: Stratus technique ID

        Returns:
            Technique details or None
        """
        for tech in self.ATTACK_TECHNIQUES:
            if tech["id"] == technique_id:
                return tech
        return None

    async def detonate(
        self,
        technique_id: str,
        cloud: str,
        parameters: dict | None = None,
    ) -> dict:
        """
        Detonate a Stratus Red Team technique.

        Note: This is a simulation placeholder. Real detonation would require
        Stratus Red Team to be installed and configured with cloud credentials.

        Args:
            technique_id: Stratus technique ID
            cloud: Target cloud provider
            parameters: Optional technique parameters

        Returns:
            Detonation result
        """
        technique = await self.get_technique(technique_id)
        if not technique:
            return {
                "technique_id": technique_id,
                "status": "error",
                "message": f"Unknown technique: {technique_id}",
            }

        # In a real implementation, this would:
        # 1. Call stratus-red-team CLI
        # 2. Execute the technique
        # 3. Collect results

        # For now, return a simulated result
        return {
            "technique_id": technique_id,
            "technique_name": technique["name"],
            "cloud": cloud,
            "status": "simulated",
            "message": (
                "Detonation simulated - requires Stratus Red Team CLI with cloud credentials"
            ),
            "detection_guidance": technique.get("detection"),
            "parameters": parameters,
        }

    async def cleanup(self, detonation_id: str) -> dict:
        """
        Clean up resources created by a detonation.

        Args:
            detonation_id: ID of the detonation to clean up

        Returns:
            Cleanup result
        """
        return {
            "detonation_id": detonation_id,
            "status": "simulated",
            "message": "Cleanup simulated - requires Stratus Red Team CLI",
        }


# Singleton instance
stratus_red_team_connector = StratusRedTeamConnector()
