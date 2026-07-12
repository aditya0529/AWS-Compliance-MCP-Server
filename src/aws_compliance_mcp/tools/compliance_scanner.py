"""
Compliance Scanner — orchestrates Config + Security Hub against framework rule mappings.
"""

from __future__ import annotations

import datetime
from typing import Any

from aws_compliance_mcp.tools.config_tools import ConfigTools
from aws_compliance_mcp.tools.securityhub_tools import SecurityHubTools
from aws_compliance_mcp.rules.pcidss import PCIDSS_RULES
from aws_compliance_mcp.rules.cis import CIS_RULES
from aws_compliance_mcp.rules.well_architected import WA_RULES

_FRAMEWORK_MAP = {
    "pcidss": PCIDSS_RULES,
    "cis": CIS_RULES,
    "well_architected": WA_RULES,
}


class ComplianceScanner:
    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        self._config = ConfigTools(region)
        self._hub = SecurityHubTools(region)

    def scan_framework(self, framework: str) -> dict[str, Any]:
        """Scan all controls in a framework and return pass/fail per section."""
        rules = _FRAMEWORK_MAP.get(framework)
        if rules is None:
            return {"error": f"Unknown framework: {framework}"}

        all_config_rules = {r["rule_name"]: r for r in self._config.list_rules()}
        sections: list[dict] = []
        total_controls = 0
        passing_controls = 0

        for section in rules["sections"]:
            section_pass = 0
            section_fail = 0
            control_results = []

            for ctrl in section["controls"]:
                total_controls += 1
                config_rule = ctrl.get("config_rule", "")
                status = "NOT_APPLICABLE"
                details = ""

                if config_rule and config_rule in all_config_rules:
                    ct = all_config_rules[config_rule]["compliance_type"]
                    status = "PASS" if ct == "COMPLIANT" else "FAIL"
                    details = f"Config rule '{config_rule}' is {ct}"
                elif config_rule:
                    status = "UNKNOWN"
                    details = f"Config rule '{config_rule}' not found or not enabled"
                else:
                    status = "MANUAL"
                    details = ctrl.get("manual_check", "Requires manual verification")

                if status == "PASS":
                    section_pass += 1
                    passing_controls += 1
                elif status in ("FAIL", "UNKNOWN"):
                    section_fail += 1

                control_results.append({
                    "control_id": ctrl["id"],
                    "title": ctrl["title"],
                    "status": status,
                    "config_rule": config_rule,
                    "details": details,
                    "remediation": ctrl.get("remediation", ""),
                    "severity": ctrl.get("severity", "MEDIUM"),
                })

            sections.append({
                "section_id": section["id"],
                "section_title": section["title"],
                "pass_count": section_pass,
                "fail_count": section_fail,
                "controls": control_results,
            })

        score = round(passing_controls / total_controls * 100, 1) if total_controls else 0.0
        return {
            "framework": framework,
            "framework_name": rules["name"],
            "region": self.region,
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "overall_score_pct": score,
            "total_controls": total_controls,
            "passing_controls": passing_controls,
            "failing_controls": total_controls - passing_controls,
            "sections": sections,
        }

    def scan_well_architected(self, pillar: str = "all") -> dict[str, Any]:
        result = self.scan_framework("well_architected")
        if pillar == "all" or "error" in result:
            return result
        filtered = [
            s for s in result.get("sections", [])
            if pillar.lower() in s["section_id"].lower() or pillar.lower() in s["section_title"].lower()
        ]
        result["sections"] = filtered
        result["pillar_filter"] = pillar
        return result

    def scan_all(self) -> dict[str, Any]:
        pci = self.scan_framework("pcidss")
        cis = self.scan_framework("cis")
        wa  = self.scan_framework("well_architected")

        critical_findings = []
        for fw_result in [pci, cis, wa]:
            fw = fw_result.get("framework", "")
            for section in fw_result.get("sections", []):
                for ctrl in section.get("controls", []):
                    if ctrl["status"] == "FAIL" and ctrl.get("severity") in ("CRITICAL", "HIGH"):
                        critical_findings.append({
                            "framework": fw,
                            "control_id": ctrl["control_id"],
                            "title": ctrl["title"],
                            "severity": ctrl["severity"],
                            "remediation": ctrl["remediation"],
                        })

        scores = {
            "pcidss": pci.get("overall_score_pct", 0),
            "cis": cis.get("overall_score_pct", 0),
            "well_architected": wa.get("overall_score_pct", 0),
        }
        return {
            "report_type": "unified_compliance_scan",
            "region": self.region,
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "overall_risk_score_pct": round(sum(scores.values()) / len(scores), 1),
            "framework_scores": scores,
            "critical_and_high_findings": critical_findings[:20],
            "total_critical_high": len(critical_findings),
            "frameworks": {"pcidss": pci, "cis": cis, "well_architected": wa},
        }

    def remediation_steps(self, control_id: str, framework: str) -> dict[str, Any]:
        rules = _FRAMEWORK_MAP.get(framework)
        if not rules:
            return {"error": f"Unknown framework: {framework}"}
        for section in rules["sections"]:
            for ctrl in section["controls"]:
                if ctrl["id"].lower() == control_id.lower():
                    return {
                        "control_id": ctrl["id"],
                        "title": ctrl["title"],
                        "framework": framework,
                        "severity": ctrl.get("severity", "MEDIUM"),
                        "config_rule": ctrl.get("config_rule", ""),
                        "remediation_summary": ctrl.get("remediation", ""),
                        "remediation_steps": ctrl.get("remediation_steps", []),
                        "references": ctrl.get("references", []),
                    }
        return {"error": f"Control '{control_id}' not found in framework '{framework}'"}

    def generate_report(self, framework: str = "all") -> dict[str, Any]:
        scan_result = self.scan_all() if framework == "all" else self.scan_framework(framework)
        priorities = []
        source = list(scan_result.get("frameworks", {}).values()) if framework == "all" else [scan_result]
        for fw_result in source:
            fw_name = fw_result.get("framework", framework)
            for section in fw_result.get("sections", []):
                for ctrl in section.get("controls", []):
                    if ctrl["status"] == "FAIL":
                        priorities.append({
                            "framework": fw_name,
                            "control_id": ctrl["control_id"],
                            "title": ctrl["title"],
                            "severity": ctrl.get("severity", "MEDIUM"),
                            "remediation": ctrl.get("remediation", ""),
                        })
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        priorities.sort(key=lambda x: sev_order.get(x["severity"], 4))
        return {
            "report_title": f"AWS Compliance Audit Report — {framework.upper()}",
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "region": self.region,
            "executive_summary": scan_result,
            "top_10_remediation_priorities": priorities[:10],
        }
