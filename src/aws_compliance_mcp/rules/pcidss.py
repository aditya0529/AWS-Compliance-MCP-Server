"""
PCI-DSS v3.2.1 — AWS Config rule mappings.
Each control has an exact AWS Config managed-rule name where applicable.
Controls without an automatable Config rule use manual_check.
"""

PCIDSS_RULES: dict = {
    "name": "PCI-DSS v3.2.1",
    "version": "3.2.1",
    "sections": [
        {
            "id": "REQ1",
            "title": "Install and maintain a firewall configuration to protect cardholder data",
            "controls": [
                {
                    "id": "PCI.1.1",
                    "title": "Security groups restrict inbound traffic to only necessary ports",
                    "config_rule": "RESTRICTED_INCOMING_TRAFFIC",
                    "severity": "HIGH",
                    "remediation": "Remove permissive inbound rules (0.0.0.0/0) on security groups",
                    "remediation_steps": [
                        "Open AWS VPC Console → Security Groups",
                        "Identify groups with 0.0.0.0/0 inbound rules on non-required ports",
                        "Delete or restrict those rules to specific CIDR ranges",
                        "Enable VPC Flow Logs to audit future traffic",
                    ],
                    "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"],
                },
                {
                    "id": "PCI.1.2",
                    "title": "Default security group restricts all traffic",
                    "config_rule": "VPC_DEFAULT_SECURITY_GROUP_CLOSED",
                    "severity": "MEDIUM",
                    "remediation": "Remove all inbound/outbound rules from the default security group",
                    "remediation_steps": [
                        "Navigate to EC2 → Security Groups → default",
                        "Remove all inbound and outbound rules",
                        "Create dedicated security groups for each workload",
                    ],
                    "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html"],
                },
            ],
        },
        {
            "id": "REQ2",
            "title": "Do not use vendor-supplied defaults for system passwords and other security parameters",
            "controls": [
                {
                    "id": "PCI.2.1",
                    "title": "IAM root access key should not exist",
                    "config_rule": "IAM_ROOT_ACCESS_KEY_CHECK",
                    "severity": "CRITICAL",
                    "remediation": "Delete root account access keys immediately",
                    "remediation_steps": [
                        "Sign in as root → My Security Credentials",
                        "Under Access Keys, delete any existing root keys",
                        "Enable MFA for root account",
                        "Use IAM roles for all programmatic access",
                    ],
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
                },
                {
                    "id": "PCI.2.2",
                    "title": "MFA should be enabled for root account",
                    "config_rule": "ROOT_ACCOUNT_MFA_ENABLED",
                    "severity": "CRITICAL",
                    "remediation": "Enable MFA on the root account using a hardware MFA device",
                    "remediation_steps": [
                        "Sign in as root → My Security Credentials → MFA",
                        "Assign a virtual or hardware MFA device",
                        "Store MFA device securely",
                    ],
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"],
                },
            ],
        },
        {
            "id": "REQ3",
            "title": "Protect stored cardholder data",
            "controls": [
                {
                    "id": "PCI.3.1",
                    "title": "S3 buckets should not be publicly accessible",
                    "config_rule": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
                    "severity": "CRITICAL",
                    "remediation": "Enable S3 Block Public Access at account and bucket level",
                    "remediation_steps": [
                        "Go to S3 → Block Public Access (account settings)",
                        "Enable all four block public access settings",
                        "For each bucket, verify bucket policy doesn't allow public access",
                        "Enable S3 Server-Side Encryption (SSE-S3 or SSE-KMS)",
                    ],
                    "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                },
                {
                    "id": "PCI.3.2",
                    "title": "S3 buckets should have server-side encryption enabled",
                    "config_rule": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
                    "severity": "HIGH",
                    "remediation": "Enable default SSE-KMS encryption on all S3 buckets",
                    "remediation_steps": [
                        "Go to each S3 bucket → Properties → Default Encryption",
                        "Select SSE-KMS and choose or create a KMS key",
                        "Enforce encryption via bucket policy",
                    ],
                    "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"],
                },
                {
                    "id": "PCI.3.3",
                    "title": "RDS instances should have encryption at rest enabled",
                    "config_rule": "RDS_STORAGE_ENCRYPTED",
                    "severity": "HIGH",
                    "remediation": "Enable encryption on RDS instances (requires snapshot restore for existing instances)",
                    "remediation_steps": [
                        "Create a snapshot of the unencrypted RDS instance",
                        "Copy the snapshot with encryption enabled",
                        "Restore a new RDS instance from the encrypted snapshot",
                        "Update application connection strings and delete the old instance",
                    ],
                    "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
                },
            ],
        },
        {
            "id": "REQ6",
            "title": "Develop and maintain secure systems and applications",
            "controls": [
                {
                    "id": "PCI.6.1",
                    "title": "EC2 instances should not have public IPs",
                    "config_rule": "EC2_INSTANCE_NO_PUBLIC_IP",
                    "severity": "HIGH",
                    "remediation": "Place EC2 instances in private subnets; use NAT Gateway for outbound internet access",
                    "remediation_steps": [
                        "Migrate EC2 instances to private subnets",
                        "Create a NAT Gateway in a public subnet",
                        "Update route tables to route 0.0.0.0/0 to NAT Gateway",
                        "Use ALB or API Gateway for inbound access",
                    ],
                    "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html"],
                },
                {
                    "id": "PCI.6.2",
                    "title": "Systems are protected against known vulnerabilities via patching",
                    "config_rule": "",
                    "manual_check": "Use AWS Systems Manager Patch Manager to enforce patch baselines",
                    "severity": "HIGH",
                    "remediation": "Implement automated patching via AWS Systems Manager Patch Manager",
                    "remediation_steps": [
                        "Enable AWS Systems Manager on all EC2 instances",
                        "Create a Patch Baseline aligned with your OS",
                        "Create a Maintenance Window for automated patching",
                        "Set up patch compliance reports in SSM",
                    ],
                    "references": ["https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html"],
                },
            ],
        },
        {
            "id": "REQ7",
            "title": "Restrict access to system components and cardholder data by business need to know",
            "controls": [
                {
                    "id": "PCI.7.1",
                    "title": "IAM policies should not allow full '*:*' administrative privileges",
                    "config_rule": "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS",
                    "severity": "CRITICAL",
                    "remediation": "Replace wildcard IAM policies with least-privilege policies",
                    "remediation_steps": [
                        "Identify policies with Action: '*' via IAM Access Analyzer",
                        "Replace with specific actions required by each role",
                        "Use AWS managed policies or create service-specific custom policies",
                        "Enforce via IAM Permission Boundaries",
                    ],
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"],
                },
                {
                    "id": "PCI.7.2",
                    "title": "IAM users should not have inline policies",
                    "config_rule": "IAM_USER_NO_POLICIES_CHECK",
                    "severity": "MEDIUM",
                    "remediation": "Move inline policies to managed policies attached to groups or roles",
                    "remediation_steps": [
                        "List IAM users with inline policies via IAM console",
                        "Convert inline policies to customer-managed policies",
                        "Attach managed policies to IAM groups instead of users",
                        "Add users to appropriate groups",
                    ],
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
                },
            ],
        },
        {
            "id": "REQ8",
            "title": "Identify users and authenticate access to system components",
            "controls": [
                {
                    "id": "PCI.8.1",
                    "title": "IAM users should have MFA enabled",
                    "config_rule": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
                    "severity": "HIGH",
                    "remediation": "Enforce MFA for all IAM users with console access",
                    "remediation_steps": [
                        "Identify IAM users without MFA via IAM console → Credential report",
                        "Require MFA via IAM policy condition: aws:MultiFactorAuthPresent",
                        "Guide each user to set up a virtual or hardware MFA device",
                    ],
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"],
                },
                {
                    "id": "PCI.8.2",
                    "title": "IAM password policy requires minimum length of 14 characters",
                    "config_rule": "IAM_PASSWORD_POLICY",
                    "severity": "MEDIUM",
                    "remediation": "Update IAM account password policy to enforce strong passwords",
                    "remediation_steps": [
                        "Go to IAM → Account Settings → Password Policy",
                        "Set minimum length to 14",
                        "Require uppercase, lowercase, numbers, and symbols",
                        "Enable password expiration (90 days) and prevent reuse",
                    ],
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"],
                },
            ],
        },
        {
            "id": "REQ10",
            "title": "Track and monitor all access to network resources and cardholder data",
            "controls": [
                {
                    "id": "PCI.10.1",
                    "title": "CloudTrail should be enabled in all regions",
                    "config_rule": "CLOUD_TRAIL_ENABLED",
                    "severity": "CRITICAL",
                    "remediation": "Enable multi-region CloudTrail logging with log file validation",
                    "remediation_steps": [
                        "Go to CloudTrail → Create Trail",
                        "Select 'All regions' and enable log file validation",
                        "Send logs to a dedicated S3 bucket with encryption",
                        "Enable CloudWatch Logs integration for alerting",
                    ],
                    "references": ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"],
                },
                {
                    "id": "PCI.10.2",
                    "title": "CloudTrail log files should be encrypted using KMS",
                    "config_rule": "CLOUD_TRAIL_ENCRYPTION_ENABLED",
                    "severity": "HIGH",
                    "remediation": "Enable KMS SSE encryption on CloudTrail logs",
                    "remediation_steps": [
                        "Go to CloudTrail → Trails → select your trail",
                        "Under 'Storage location', enable SSE-KMS",
                        "Create or select a CMK with appropriate key policy",
                        "Restrict key usage to CloudTrail service principal",
                    ],
                    "references": ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"],
                },
            ],
        },
        {
            "id": "REQ11",
            "title": "Regularly test security systems and processes",
            "controls": [
                {
                    "id": "PCI.11.1",
                    "title": "AWS Config should be enabled",
                    "config_rule": "CONFIG_ENABLED_IN_REGION",
                    "severity": "HIGH",
                    "remediation": "Enable AWS Config in all regions with a configuration recorder",
                    "remediation_steps": [
                        "Go to AWS Config → Get started",
                        "Select 'Record all resources supported in this region'",
                        "Create an S3 bucket for Config snapshots",
                        "Set up a delivery channel",
                    ],
                    "references": ["https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"],
                },
                {
                    "id": "PCI.11.2",
                    "title": "Security Hub should be enabled",
                    "config_rule": "SECURITYHUB_ENABLED",
                    "severity": "HIGH",
                    "remediation": "Enable AWS Security Hub and subscribe to PCI-DSS standard",
                    "remediation_steps": [
                        "Go to Security Hub → Enable Security Hub",
                        "Enable PCI-DSS v3.2.1 security standard",
                        "Integrate with GuardDuty, Inspector, and Macie",
                        "Set up EventBridge rules for high-severity findings",
                    ],
                    "references": ["https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html"],
                },
            ],
        },
    ],
}
