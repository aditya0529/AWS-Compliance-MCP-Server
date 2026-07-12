"""
Shared pytest fixtures — moto mocks for AWS Config and Security Hub.
"""

from __future__ import annotations

import os
import pytest
import boto3
from moto import mock_aws

from aws_compliance_mcp.tools.config_tools import ConfigTools
from aws_compliance_mcp.tools.securityhub_tools import SecurityHubTools
from aws_compliance_mcp.tools.compliance_scanner import ComplianceScanner

# ── Environment ───────────────────────────────────────────────────────────────
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


# ── Config fixtures ───────────────────────────────────────────────────────────

@pytest.fixture()
def config_client():
    with mock_aws():
        client = boto3.client("config", region_name="us-east-1")
        # set up a configuration recorder so Config is "on"
        client.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": True},
            }
        )
        client.put_delivery_channel(
            DeliveryChannel={
                "name": "default",
                "s3BucketName": "config-bucket-test",
            }
        )
        yield client


@pytest.fixture()
def config_tools():
    with mock_aws():
        # set up recorder
        c = boto3.client("config", region_name="us-east-1")
        c.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": True},
            }
        )
        c.put_delivery_channel(
            DeliveryChannel={"name": "default", "s3BucketName": "config-bucket-test"}
        )
        # add two managed rules
        c.put_config_rule(
            ConfigRule={
                "ConfigRuleName": "CLOUD_TRAIL_ENABLED",
                "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_ENABLED"},
            }
        )
        c.put_config_rule(
            ConfigRule={
                "ConfigRuleName": "IAM_ROOT_ACCESS_KEY_CHECK",
                "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_ROOT_ACCESS_KEY_CHECK"},
            }
        )
        yield ConfigTools(region="us-east-1")


# ── Security Hub fixtures ─────────────────────────────────────────────────────

@pytest.fixture()
def securityhub_client():
    with mock_aws():
        client = boto3.client("securityhub", region_name="us-east-1")
        client.enable_security_hub(EnableDefaultStandards=False)
        yield client


@pytest.fixture()
def securityhub_with_findings():
    with mock_aws():
        client = boto3.client("securityhub", region_name="us-east-1")
        client.enable_security_hub(EnableDefaultStandards=False)
        # Import a sample finding
        client.batch_import_findings(
            Findings=[
                {
                    "SchemaVersion": "2018-10-08",
                    "Id": "test-finding-001",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "test-generator",
                    "AwsAccountId": "123456789012",
                    "Types": ["Software and Configuration Checks"],
                    "CreatedAt": "2024-01-01T00:00:00Z",
                    "UpdatedAt": "2024-01-01T00:00:00Z",
                    "Severity": {"Label": "CRITICAL", "Normalized": 90},
                    "Title": "Root account MFA not enabled",
                    "Description": "The root account does not have MFA enabled.",
                    "Resources": [
                        {"Type": "AwsAccount", "Id": "arn:aws:iam::123456789012:root"}
                    ],
                    "RecordState": "ACTIVE",
                    "Workflow": {"Status": "NEW"},
                    "Compliance": {"Status": "FAILED"},
                }
            ]
        )
        yield SecurityHubTools(region="us-east-1")


# ── Scanner fixture ───────────────────────────────────────────────────────────

@pytest.fixture()
def scanner():
    with mock_aws():
        # minimal Config setup so list_rules() returns empty list (not error)
        c = boto3.client("config", region_name="us-east-1")
        c.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": True},
            }
        )
        c.put_delivery_channel(
            DeliveryChannel={"name": "default", "s3BucketName": "config-bucket-test"}
        )
        sh = boto3.client("securityhub", region_name="us-east-1")
        sh.enable_security_hub(EnableDefaultStandards=False)
        yield ComplianceScanner(region="us-east-1")
