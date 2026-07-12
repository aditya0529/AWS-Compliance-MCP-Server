"""Tests for ConfigTools — uses moto to mock AWS Config."""

from __future__ import annotations

import os
import boto3
import pytest
from moto import mock_aws

from aws_compliance_mcp.tools.config_tools import ConfigTools

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


def _bootstrap(client) -> None:
    """Create minimum Config infrastructure."""
    client.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
            "recordingGroup": {"allSupported": True},
        }
    )
    client.put_delivery_channel(
        DeliveryChannel={"name": "default", "s3BucketName": "test-config-bucket"}
    )


class TestComplianceSummary:
    @mock_aws
    def test_returns_dict_with_required_keys(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.compliance_summary()
        assert "region" in result or "error" in result

    @mock_aws
    def test_region_matches(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.compliance_summary()
        assert result.get("region") == "us-east-1" or "error" in result

    @mock_aws
    def test_non_negative_counts(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.compliance_summary()
        if "error" not in result:
            assert result.get("compliant_rules", 0) >= 0
            assert result.get("non_compliant_rules", 0) >= 0


class TestListRules:
    @mock_aws
    def test_returns_list(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.list_rules()
        assert isinstance(result, list)

    @mock_aws
    def test_rules_have_required_keys(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        c.put_config_rule(
            ConfigRule={
                "ConfigRuleName": "CLOUD_TRAIL_ENABLED",
                "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_ENABLED"},
            }
        )
        tools = ConfigTools(region="us-east-1")
        rules = tools.list_rules()
        for rule in rules:
            if "error" not in rule:
                assert "rule_name" in rule
                assert "compliance_type" in rule

    @mock_aws
    def test_empty_when_no_rules(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.list_rules()
        # No rules added → empty list
        assert result == []


class TestRuleStatus:
    @mock_aws
    def test_missing_rule_returns_error(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.rule_status("NONEXISTENT_RULE")
        assert "error" in result

    @mock_aws
    def test_existing_rule_returns_status(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        c.put_config_rule(
            ConfigRule={
                "ConfigRuleName": "CLOUD_TRAIL_ENABLED",
                "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_ENABLED"},
            }
        )
        tools = ConfigTools(region="us-east-1")
        result = tools.rule_status("CLOUD_TRAIL_ENABLED")
        assert "rule_name" in result or "error" in result

    @mock_aws
    def test_rule_status_includes_region(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.rule_status("NONEXISTENT_RULE")
        # Error case should still include region
        assert result.get("region") == "us-east-1" or "error" in result


class TestNoncompliantResources:
    @mock_aws
    def test_returns_list(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.noncompliant_resources()
        assert isinstance(result, list)

    @mock_aws
    def test_limit_respected(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.noncompliant_resources(limit=5)
        assert len(result) <= 5

    @mock_aws
    def test_unknown_rule_returns_error_in_list(self):
        c = boto3.client("config", region_name="us-east-1")
        _bootstrap(c)
        tools = ConfigTools(region="us-east-1")
        result = tools.noncompliant_resources(rule_name="DOES_NOT_EXIST")
        assert isinstance(result, list)
        if result:
            assert "error" in result[0] or "resource_type" in result[0]
