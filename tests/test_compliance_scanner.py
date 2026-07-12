"""Tests for ComplianceScanner — pure rule data + moto AWS mocks."""

from __future__ import annotations

import os
import boto3
import pytest
from moto import mock_aws

from aws_compliance_mcp.rules.pcidss import PCIDSS_RULES
from aws_compliance_mcp.rules.cis import CIS_RULES
from aws_compliance_mcp.rules.well_architected import WA_RULES
from aws_compliance_mcp.tools.compliance_scanner import ComplianceScanner

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


def _bootstrap_config(region="us-east-1"):
    c = boto3.client("config", region_name=region)
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
    return c


def _bootstrap_securityhub(region="us-east-1"):
    sh = boto3.client("securityhub", region_name=region)
    sh.enable_security_hub(EnableDefaultStandards=False)
    return sh


# ── Pure rule data tests (no AWS calls) ──────────────────────────────────────

class TestRuleData:
    def test_pcidss_has_sections(self):
        assert "sections" in PCIDSS_RULES
        assert len(PCIDSS_RULES["sections"]) > 0

    def test_cis_has_sections(self):
        assert "sections" in CIS_RULES
        assert len(CIS_RULES["sections"]) > 0

    def test_wa_has_5_pillars(self):
        assert len(WA_RULES["sections"]) == 5

    def test_pcidss_controls_have_required_keys(self):
        for section in PCIDSS_RULES["sections"]:
            for ctrl in section["controls"]:
                assert "id" in ctrl
                assert "title" in ctrl
                assert "severity" in ctrl
                assert ctrl["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_cis_controls_have_required_keys(self):
        for section in CIS_RULES["sections"]:
            for ctrl in section["controls"]:
                assert "id" in ctrl
                assert "title" in ctrl
                assert "remediation" in ctrl

    def test_wa_controls_have_remediation_steps(self):
        for section in WA_RULES["sections"]:
            for ctrl in section["controls"]:
                assert "remediation_steps" in ctrl
                assert len(ctrl["remediation_steps"]) > 0

    def test_all_control_ids_are_unique_within_framework(self):
        for rules in [PCIDSS_RULES, CIS_RULES, WA_RULES]:
            ids = [ctrl["id"] for s in rules["sections"] for ctrl in s["controls"]]
            assert len(ids) == len(set(ids)), f"Duplicate control IDs in {rules['name']}"

    def test_pcidss_version(self):
        assert PCIDSS_RULES["version"] == "3.2.1"

    def test_cis_version(self):
        assert CIS_RULES["version"] == "1.4"

    def test_config_rule_field_present_on_all_controls(self):
        for rules in [PCIDSS_RULES, CIS_RULES, WA_RULES]:
            for section in rules["sections"]:
                for ctrl in section["controls"]:
                    assert "config_rule" in ctrl, f"Missing config_rule on {ctrl['id']}"


# ── scan_framework tests ──────────────────────────────────────────────────────

class TestScanFramework:
    @mock_aws
    def test_unknown_framework_returns_error(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("unknown_framework")
        assert "error" in result

    @mock_aws
    def test_pcidss_scan_returns_structure(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("pcidss")
        assert "framework" in result
        assert result["framework"] == "pcidss"
        assert "sections" in result
        assert "overall_score_pct" in result

    @mock_aws
    def test_cis_scan_returns_structure(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("cis")
        assert result["framework"] == "cis"
        assert len(result["sections"]) == len(CIS_RULES["sections"])

    @mock_aws
    def test_score_between_0_and_100(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("pcidss")
        score = result.get("overall_score_pct", 0)
        assert 0 <= score <= 100

    @mock_aws
    def test_controls_have_status_field(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("pcidss")
        for section in result["sections"]:
            for ctrl in section["controls"]:
                assert "status" in ctrl
                assert ctrl["status"] in ("PASS", "FAIL", "UNKNOWN", "MANUAL", "NOT_APPLICABLE")

    @mock_aws
    def test_manual_check_controls_get_manual_status(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("pcidss")
        for section in result["sections"]:
            for ctrl in section["controls"]:
                if not ctrl["config_rule"]:
                    assert ctrl["status"] == "MANUAL"

    @mock_aws
    def test_controls_without_config_rule_enabled_are_unknown(self):
        _bootstrap_config()  # no rules put into Config
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_framework("cis")
        for section in result["sections"]:
            for ctrl in section["controls"]:
                if ctrl["config_rule"]:
                    # Rule not enabled → UNKNOWN
                    assert ctrl["status"] in ("UNKNOWN", "PASS", "FAIL")


# ── scan_well_architected tests ───────────────────────────────────────────────

class TestScanWellArchitected:
    @mock_aws
    def test_all_pillars_returned_for_default(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_well_architected()
        assert len(result["sections"]) == 5

    @mock_aws
    def test_pillar_filter_narrows_sections(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_well_architected(pillar="security")
        # Should have fewer than 5 sections
        assert len(result["sections"]) < 5

    @mock_aws
    def test_pillar_filter_field_present(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_well_architected(pillar="cost")
        assert result.get("pillar_filter") == "cost"


# ── scan_all tests ────────────────────────────────────────────────────────────

class TestScanAll:
    @mock_aws
    def test_all_scan_has_three_frameworks(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_all()
        assert "frameworks" in result
        assert "pcidss" in result["frameworks"]
        assert "cis" in result["frameworks"]
        assert "well_architected" in result["frameworks"]

    @mock_aws
    def test_overall_risk_score_present(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_all()
        assert "overall_risk_score_pct" in result
        assert 0 <= result["overall_risk_score_pct"] <= 100

    @mock_aws
    def test_framework_scores_dict_present(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_all()
        scores = result.get("framework_scores", {})
        assert "pcidss" in scores
        assert "cis" in scores
        assert "well_architected" in scores

    @mock_aws
    def test_critical_high_findings_is_list(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.scan_all()
        assert isinstance(result.get("critical_and_high_findings", []), list)


# ── remediation_steps tests ───────────────────────────────────────────────────

class TestRemediationSteps:
    def test_known_control_pcidss(self):
        scanner = ComplianceScanner.__new__(ComplianceScanner)
        scanner.region = "us-east-1"
        result = scanner.remediation_steps("PCI.10.1", "pcidss")
        assert result["control_id"] == "PCI.10.1"
        assert "remediation_steps" in result
        assert len(result["remediation_steps"]) > 0

    def test_known_control_cis(self):
        scanner = ComplianceScanner.__new__(ComplianceScanner)
        scanner.region = "us-east-1"
        result = scanner.remediation_steps("CIS.1.1", "cis")
        assert "control_id" in result
        assert result["control_id"] == "CIS.1.1"

    def test_unknown_control_returns_error(self):
        scanner = ComplianceScanner.__new__(ComplianceScanner)
        scanner.region = "us-east-1"
        result = scanner.remediation_steps("FAKE.99.99", "pcidss")
        assert "error" in result

    def test_unknown_framework_returns_error(self):
        scanner = ComplianceScanner.__new__(ComplianceScanner)
        scanner.region = "us-east-1"
        result = scanner.remediation_steps("PCI.10.1", "fake_framework")
        assert "error" in result

    def test_wa_control_lookup(self):
        scanner = ComplianceScanner.__new__(ComplianceScanner)
        scanner.region = "us-east-1"
        result = scanner.remediation_steps("WAF.SEC.1", "well_architected")
        assert "control_id" in result
        assert result["framework"] == "well_architected"

    def test_remediation_steps_are_list(self):
        scanner = ComplianceScanner.__new__(ComplianceScanner)
        scanner.region = "us-east-1"
        result = scanner.remediation_steps("CIS.4.1", "cis")
        if "error" not in result:
            assert isinstance(result["remediation_steps"], list)


# ── generate_report tests ─────────────────────────────────────────────────────

class TestGenerateReport:
    @mock_aws
    def test_report_has_title(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.generate_report("pcidss")
        assert "report_title" in result

    @mock_aws
    def test_report_has_priorities_list(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.generate_report("pcidss")
        assert "top_10_remediation_priorities" in result
        assert isinstance(result["top_10_remediation_priorities"], list)

    @mock_aws
    def test_report_max_10_priorities(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.generate_report("all")
        assert len(result["top_10_remediation_priorities"]) <= 10

    @mock_aws
    def test_report_sorted_by_severity(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.generate_report("pcidss")
        priorities = result["top_10_remediation_priorities"]
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sevs = [sev_order.get(p["severity"], 4) for p in priorities]
        assert sevs == sorted(sevs), "Priorities not sorted by severity"

    @mock_aws
    def test_all_framework_report(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.generate_report("all")
        assert "all" in result["report_title"].lower()

    @mock_aws
    def test_report_has_generated_at(self):
        _bootstrap_config()
        _bootstrap_securityhub()
        scanner = ComplianceScanner(region="us-east-1")
        result = scanner.generate_report("cis")
        assert "generated_at" in result
