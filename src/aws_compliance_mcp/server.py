"""
AWS Compliance MCP Server
=========================
Exposes AWS Config, Security Hub, and custom compliance-rule scanning
as MCP tools so any MCP-compatible LLM client (Claude Desktop, Bedrock
Agents, CI pipelines) can query real-time infrastructure posture.

Run directly:
    python -m aws_compliance_mcp.server

Or via the installed script:
    aws-compliance-mcp
"""

from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from aws_compliance_mcp.tools.config_tools import ConfigTools
from aws_compliance_mcp.tools.securityhub_tools import SecurityHubTools
from aws_compliance_mcp.tools.compliance_scanner import ComplianceScanner

load_dotenv()

# ── MCP server instance ───────────────────────────────────────────────────────
mcp = FastMCP(
    "aws-compliance-scanner",
    instructions=(
        "You are an AWS compliance expert. Use the available tools to scan "
        "infrastructure against PCI-DSS, CIS Benchmarks, and AWS Well-Architected "
        "best practices. Always cite the specific control ID when reporting findings."
    ),
)

def _config(region: str) -> ConfigTools:
    return ConfigTools(region=region)

def _hub(region: str) -> SecurityHubTools:
    return SecurityHubTools(region=region)

def _scanner(region: str) -> ComplianceScanner:
    return ComplianceScanner(region=region)


# ── AWS Config tools ──────────────────────────────────────────────────────────

@mcp.tool()
def get_config_compliance_summary(region: str = "us-east-1") -> str:
    """Return overall Config rule compliance % and counts."""
    return json.dumps(_config(region).compliance_summary(), indent=2)


@mcp.tool()
def get_noncompliant_resources(rule_name: str = "", region: str = "us-east-1", limit: int = 50) -> str:
    """List NON_COMPLIANT resources in AWS Config, optionally filtered by rule name."""
    return json.dumps(_config(region).noncompliant_resources(rule_name=rule_name, limit=limit), indent=2)


@mcp.tool()
def get_config_rule_status(rule_name: str, region: str = "us-east-1") -> str:
    """Get compliance status + failing resources for a single Config rule."""
    return json.dumps(_config(region).rule_status(rule_name), indent=2)


@mcp.tool()
def list_config_rules(region: str = "us-east-1") -> str:
    """List all Config rules and their current compliance state."""
    return json.dumps(_config(region).list_rules(), indent=2)


# ── Security Hub tools ────────────────────────────────────────────────────────

@mcp.tool()
def get_security_hub_summary(region: str = "us-east-1") -> str:
    """Return Security Hub finding counts by severity and workflow status."""
    return json.dumps(_hub(region).summary(), indent=2)


@mcp.tool()
def get_security_hub_findings(
    severity: str = "CRITICAL,HIGH",
    standard: str = "",
    limit: int = 20,
    region: str = "us-east-1",
) -> str:
    """
    Fetch Security Hub findings filtered by severity and/or compliance standard.
    severity: comma-separated — CRITICAL, HIGH, MEDIUM, LOW
    standard: 'pci', 'cis', or 'aws-foundational'
    """
    return json.dumps(_hub(region).findings(
        severities=[s.strip().upper() for s in severity.split(",")],
        standard=standard,
        limit=limit,
    ), indent=2)


@mcp.tool()
def get_security_hub_score(region: str = "us-east-1") -> str:
    """Return security score and pass/fail ratio per enabled Security Hub standard."""
    return json.dumps(_hub(region).security_score(), indent=2)


# ── Compliance scanning tools ─────────────────────────────────────────────────

@mcp.tool()
def scan_pcidss_compliance(region: str = "us-east-1") -> str:
    """Full PCI-DSS v3.2.1 scan — per-requirement status and failing controls."""
    return json.dumps(_scanner(region).scan_framework("pcidss"), indent=2)


@mcp.tool()
def scan_cis_compliance(region: str = "us-east-1") -> str:
    """CIS AWS Foundations Benchmark v1.4 scan — per-section status."""
    return json.dumps(_scanner(region).scan_framework("cis"), indent=2)


@mcp.tool()
def scan_well_architected(pillar: str = "all", region: str = "us-east-1") -> str:
    """
    Well-Architected Framework scan.
    pillar: 'security', 'reliability', 'performance', 'cost', 'ops', or 'all'
    """
    return json.dumps(_scanner(region).scan_well_architected(pillar=pillar), indent=2)


@mcp.tool()
def scan_all_frameworks(region: str = "us-east-1") -> str:
    """Unified scan across PCI-DSS, CIS, and Well-Architected with overall risk score."""
    return json.dumps(_scanner(region).scan_all(), indent=2)


@mcp.tool()
def get_remediation_steps(control_id: str, framework: str = "pcidss", region: str = "us-east-1") -> str:
    """
    Step-by-step remediation for a specific control.
    control_id examples: 'PCI.10.1', 'CIS.1.1', 'WAF.SEC.1'
    framework: 'pcidss', 'cis', or 'well_architected'
    """
    return json.dumps(_scanner(region).remediation_steps(control_id=control_id, framework=framework), indent=2)


@mcp.tool()
def generate_audit_report(framework: str = "all", region: str = "us-east-1") -> str:
    """Audit-ready report with executive summary and top-10 remediation priorities."""
    return json.dumps(_scanner(region).generate_report(framework=framework), indent=2)


# ── MCP Resources ─────────────────────────────────────────────────────────────

@mcp.resource("compliance://pcidss/controls")
def pcidss_controls() -> str:
    """PCI-DSS v3.2.1 controls mapped to AWS Config rules."""
    from aws_compliance_mcp.rules.pcidss import PCIDSS_RULES
    return json.dumps(PCIDSS_RULES, indent=2)


@mcp.resource("compliance://cis/controls")
def cis_controls() -> str:
    """CIS AWS Foundations Benchmark v1.4 controls."""
    from aws_compliance_mcp.rules.cis import CIS_RULES
    return json.dumps(CIS_RULES, indent=2)


@mcp.resource("compliance://well-architected/pillars")
def wa_pillars() -> str:
    """AWS Well-Architected Framework pillar checks."""
    from aws_compliance_mcp.rules.well_architected import WA_RULES
    return json.dumps(WA_RULES, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
