"""
AWS Well-Architected Framework — AWS Config rule mappings.
Covers Security, Reliability, Performance Efficiency, Cost Optimization, Operational Excellence pillars.
"""

WA_RULES: dict = {
    "name": "AWS Well-Architected Framework",
    "version": "2024",
    "sections": [
        {
            "id": "WAF.SEC",
            "title": "Security Pillar",
            "controls": [
                {
                    "id": "WAF.SEC.1",
                    "title": "Implement a strong identity foundation — no root access keys",
                    "config_rule": "IAM_ROOT_ACCESS_KEY_CHECK",
                    "severity": "CRITICAL",
                    "remediation": "Delete root access keys; use least-privilege IAM roles",
                    "remediation_steps": [
                        "Log in as root → Security Credentials → Delete access keys",
                        "Create IAM admin role with permission boundary",
                        "Use AWS SSO / IAM Identity Center for human access",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/identity-management.html"],
                },
                {
                    "id": "WAF.SEC.2",
                    "title": "Enable traceability — CloudTrail enabled in all regions",
                    "config_rule": "CLOUD_TRAIL_ENABLED",
                    "severity": "HIGH",
                    "remediation": "Enable multi-region CloudTrail with S3 and CloudWatch integration",
                    "remediation_steps": [
                        "Create organization-level CloudTrail trail",
                        "Enable data events for S3 and Lambda",
                        "Ship to CloudWatch Logs for real-time alerting",
                        "Archive to S3 with lifecycle policies",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/detective-controls.html"],
                },
                {
                    "id": "WAF.SEC.3",
                    "title": "Apply security at all layers — security groups restrict SSH",
                    "config_rule": "INCOMING_SSH_DISABLED",
                    "severity": "HIGH",
                    "remediation": "Use SSM Session Manager instead of direct SSH access",
                    "remediation_steps": [
                        "Remove all port-22 inbound rules from security groups",
                        "Enable SSM Agent on EC2 instances",
                        "Grant SSM:StartSession permissions to IAM roles",
                        "Use Session Manager for all remote access",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/infrastructure-protection.html"],
                },
                {
                    "id": "WAF.SEC.4",
                    "title": "Protect data at rest — S3 encryption enabled",
                    "config_rule": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
                    "severity": "HIGH",
                    "remediation": "Enable SSE-KMS encryption on all S3 buckets",
                    "remediation_steps": [
                        "Enable default bucket encryption with SSE-KMS",
                        "Create customer-managed CMK in KMS with rotation enabled",
                        "Deny PutObject requests without encryption header via bucket policy",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/data-protection.html"],
                },
            ],
        },
        {
            "id": "WAF.REL",
            "title": "Reliability Pillar",
            "controls": [
                {
                    "id": "WAF.REL.1",
                    "title": "Automatically recover from failure — RDS Multi-AZ enabled",
                    "config_rule": "RDS_MULTI_AZ_SUPPORT",
                    "severity": "HIGH",
                    "remediation": "Enable Multi-AZ for all production RDS instances",
                    "remediation_steps": [
                        "RDS Console → Select DB instance → Modify",
                        "Enable Multi-AZ deployment",
                        "Apply during maintenance window or immediately (causes brief restart)",
                        "Set up RDS event notifications for failover events",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_withstand_component_failures_multi_az_region_system.html"],
                },
                {
                    "id": "WAF.REL.2",
                    "title": "Manage change in automation — Config enabled for change tracking",
                    "config_rule": "CONFIG_ENABLED_IN_REGION",
                    "severity": "MEDIUM",
                    "remediation": "Enable AWS Config for resource change tracking in all regions",
                    "remediation_steps": [
                        "Enable Config in all active regions",
                        "Record all resource types including global resources",
                        "Set up Config Aggregator for multi-account/region view",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/change-management.html"],
                },
                {
                    "id": "WAF.REL.3",
                    "title": "Test recovery procedures — RDS automated backups enabled",
                    "config_rule": "DB_INSTANCE_BACKUP_ENABLED",
                    "severity": "HIGH",
                    "remediation": "Enable automated backups with at least 7-day retention on all RDS instances",
                    "remediation_steps": [
                        "RDS → Modify instance → Backup retention period → set to 7+",
                        "Set backup window to off-peak hours",
                        "Periodically restore from backup to verify recoverability",
                        "Use AWS Backup for centralized backup management",
                    ],
                    "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"],
                },
            ],
        },
        {
            "id": "WAF.PERF",
            "title": "Performance Efficiency Pillar",
            "controls": [
                {
                    "id": "WAF.PERF.1",
                    "title": "Democratize advanced technologies — use managed services where possible",
                    "config_rule": "",
                    "manual_check": "Review architecture for opportunities to replace self-managed EC2 workloads with managed services",
                    "severity": "LOW",
                    "remediation": "Replace self-managed infrastructure with AWS managed services (RDS, EKS, Lambda)",
                    "remediation_steps": [
                        "Audit current EC2-hosted databases and consider RDS/Aurora migration",
                        "Consider Lambda for event-driven workloads",
                        "Use EKS Fargate to eliminate node management",
                    ],
                    "references": ["https://docs.aws.amazon.com/wellarchitected/latest/performance-efficiency-pillar/selection.html"],
                },
                {
                    "id": "WAF.PERF.2",
                    "title": "Experiment more often — EC2 not over-provisioned (Compute Optimizer)",
                    "config_rule": "",
                    "manual_check": "Review AWS Compute Optimizer recommendations for right-sizing",
                    "severity": "LOW",
                    "remediation": "Enable AWS Compute Optimizer and act on right-sizing recommendations",
                    "remediation_steps": [
                        "Enable Compute Optimizer via console or Organizations",
                        "Review EC2, Lambda, RDS, ECS recommendations",
                        "Test downsized instances in staging before production",
                    ],
                    "references": ["https://docs.aws.amazon.com/compute-optimizer/latest/ug/what-is-compute-optimizer.html"],
                },
            ],
        },
        {
            "id": "WAF.COST",
            "title": "Cost Optimization Pillar",
            "controls": [
                {
                    "id": "WAF.COST.1",
                    "title": "Implement cloud financial management — Cost Explorer and Budgets enabled",
                    "config_rule": "",
                    "manual_check": "Verify AWS Budgets and Cost Explorer are configured with alerts",
                    "severity": "MEDIUM",
                    "remediation": "Set up AWS Budgets with alerts and enable Cost Explorer",
                    "remediation_steps": [
                        "Enable Cost Explorer in Billing console",
                        "Create monthly budget with 80% and 100% alert thresholds",
                        "Enable Savings Plans and Reserved Instance recommendations",
                        "Tag all resources with cost allocation tags (Owner, Environment, Project)",
                    ],
                    "references": ["https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html"],
                },
                {
                    "id": "WAF.COST.2",
                    "title": "Match supply with demand — use Auto Scaling groups",
                    "config_rule": "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED",
                    "severity": "LOW",
                    "remediation": "Ensure ASGs use ELB health checks to properly scale",
                    "remediation_steps": [
                        "Update ASG health check type from EC2 to ELB",
                        "Set appropriate scale-in/out policies based on CPU and request count",
                        "Use scheduled scaling for predictable traffic patterns",
                    ],
                    "references": ["https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-using-elb-healthcheck.html"],
                },
            ],
        },
        {
            "id": "WAF.OPS",
            "title": "Operational Excellence Pillar",
            "controls": [
                {
                    "id": "WAF.OPS.1",
                    "title": "Perform operations as code — CloudFormation or CDK in use",
                    "config_rule": "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK",
                    "severity": "MEDIUM",
                    "remediation": "Detect and remediate CloudFormation stack drift",
                    "remediation_steps": [
                        "CloudFormation → Stacks → Detect Drift",
                        "Review drifted resources and correct or import changes",
                        "Set up EventBridge rule to detect drift on schedule",
                    ],
                    "references": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html"],
                },
                {
                    "id": "WAF.OPS.2",
                    "title": "Anticipate failure — CloudWatch alarms configured for critical resources",
                    "config_rule": "CLOUDWATCH_ALARM_ACTION_CHECK",
                    "severity": "MEDIUM",
                    "remediation": "Ensure CloudWatch alarms have active actions (SNS, Auto Scaling, EC2)",
                    "remediation_steps": [
                        "Review all CloudWatch alarms without actions",
                        "Add SNS topic or Auto Scaling action to each alarm",
                        "Create composite alarms for correlated failure conditions",
                        "Set up CloudWatch dashboards for key operational metrics",
                    ],
                    "references": ["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"],
                },
                {
                    "id": "WAF.OPS.3",
                    "title": "Refine operations procedures frequently — Config rules up to date",
                    "config_rule": "CONFIG_ENABLED_IN_REGION",
                    "severity": "LOW",
                    "remediation": "Regularly review and update AWS Config rules to align with current standards",
                    "remediation_steps": [
                        "Review Config conformance packs quarterly",
                        "Enable AWS Security Hub for auto-updated controls",
                        "Integrate Config findings with ticketing system for automated remediation",
                    ],
                    "references": ["https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html"],
                },
            ],
        },
    ],
}
