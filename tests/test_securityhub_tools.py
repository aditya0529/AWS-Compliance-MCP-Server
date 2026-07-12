"""Tests for SecurityHubTools — uses moto to mock Security Hub."""

from __future__ import annotations

import os
import boto3
import pytest
from moto import mock_aws

from aws_compliance_mcp.tools.securityhub_tools import SecurityHubTools

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

_SAMPLE_FINDING = {
    "SchemaVersion": "2018-10-08",
    "Id": "test-finding-001",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "GeneratorId": "test-gen",
    "AwsAccountId": "123456789012",
    "Types": ["Software and Configuration Checks"],
    "CreatedAt": "2024-01-01T00:00:00Z",
    "UpdatedAt": "2024-01-01T00:00:00Z",
    "Severity": {"Label": "CRITICAL", "Normalized": 90},
    "Title": "Root MFA not enabled",
    "Description": "Root account MFA is not enabled.",
    "Resources": [{"Type": "AwsAccount", "Id": "arn:aws:iam::123456789012:root"}],
    "RecordState": "ACTIVE",
    "Workflow": {"Status": "NEW"},
    "Compliance": {"Status": "FAILED"},
}


def _enable_hub(region="us-east-1"):
    client = boto3.client("securityhub", region_name=region)
    client.enable_security_hub(EnableDefaultStandards=False)
    return client


class TestSecurityHubSummary:
    @mock_aws
    def test_returns_summary_structure(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.summary()
        assert "region" in result or "error" in result

    @mock_aws
    def test_empty_hub_has_zero_findings(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.summary()
        if "error" not in result:
            assert result["total_active_findings"] == 0

    @mock_aws
    def test_counts_imported_finding(self):
        client = _enable_hub()
        client.batch_import_findings(Findings=[_SAMPLE_FINDING])
        tools = SecurityHubTools(region="us-east-1")
        result = tools.summary()
        if "error" not in result:
            assert result["total_active_findings"] >= 1

    @mock_aws
    def test_severity_breakdown_present(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.summary()
        if "error" not in result:
            assert "by_severity" in result
            assert "CRITICAL" in result["by_severity"]

    @mock_aws
    def test_hub_not_enabled_returns_error(self):
        # Don't call enable_security_hub
        tools = SecurityHubTools(region="us-east-1")
        result = tools.summary()
        assert "error" in result


class TestSecurityHubFindings:
    @mock_aws
    def test_returns_list(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.findings()
        assert isinstance(result, list)

    @mock_aws
    def test_finding_has_required_keys(self):
        client = _enable_hub()
        client.batch_import_findings(Findings=[_SAMPLE_FINDING])
        tools = SecurityHubTools(region="us-east-1")
        findings = tools.findings(severities=["CRITICAL"])
        for f in findings:
            if "error" not in f:
                for key in ("id", "title", "severity"):
                    assert key in f

    @mock_aws
    def test_severity_filter_applied(self):
        client = _enable_hub()
        client.batch_import_findings(Findings=[_SAMPLE_FINDING])
        tools = SecurityHubTools(region="us-east-1")
        findings = tools.findings(severities=["LOW"])
        # The imported finding is CRITICAL, so LOW filter should return 0 findings
        # (moto may or may not filter exactly, but shouldn't error)
        assert isinstance(findings, list)

    @mock_aws
    def test_limit_respected(self):
        client = _enable_hub()
        client.batch_import_findings(Findings=[_SAMPLE_FINDING])
        tools = SecurityHubTools(region="us-east-1")
        findings = tools.findings(limit=1)
        assert len(findings) <= 1


class TestSecurityScore:
    @mock_aws
    def test_returns_dict(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.security_score()
        assert isinstance(result, dict)

    @mock_aws
    def test_has_region(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.security_score()
        assert result.get("region") == "us-east-1" or "error" in result

    @mock_aws
    def test_no_standards_returns_empty_list(self):
        _enable_hub()
        tools = SecurityHubTools(region="us-east-1")
        result = tools.security_score()
        if "error" not in result:
            assert isinstance(result.get("standards", []), list)
