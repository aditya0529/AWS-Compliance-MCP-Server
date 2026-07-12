"""Security Hub API wrapper — findings, severity counts, security score."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from aws_compliance_mcp.aws_client import get_client

_STANDARD_FRAGMENTS: dict[str, str] = {
    "pci": "pci-dss",
    "cis": "cis-aws-foundations",
    "aws-foundational": "aws-foundational-security",
    "fsbp": "aws-foundational-security",
}


class SecurityHubTools:
    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        self._client = get_client("securityhub", region)

    def summary(self) -> dict[str, Any]:
        """Count findings by severity and workflow status."""
        severity_counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0
        }
        workflow_counts: dict[str, int] = {
            "NEW": 0, "NOTIFIED": 0, "RESOLVED": 0, "SUPPRESSED": 0
        }
        total = 0
        try:
            paginator = self._client.get_paginator("get_findings")
            for page in paginator.paginate(
                Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
                PaginationConfig={"MaxItems": 1000},
            ):
                for f in page.get("Findings", []):
                    sev = f.get("Severity", {}).get("Label", "INFORMATIONAL")
                    wf = f.get("Workflow", {}).get("Status", "NEW")
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                    if wf in workflow_counts:
                        workflow_counts[wf] += 1
                    total += 1
        except ClientError as exc:
            return {"error": str(exc), "region": self.region}
        return {
            "region": self.region,
            "total_active_findings": total,
            "by_severity": severity_counts,
            "by_workflow_status": workflow_counts,
        }

    def findings(self, severities: list[str] | None = None, standard: str = "", limit: int = 20) -> list[dict[str, Any]]:
        """Return findings filtered by severity and/or compliance standard."""
        if severities is None:
            severities = ["CRITICAL", "HIGH"]
        filters: dict[str, Any] = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "SeverityLabel": [{"Value": s, "Comparison": "EQUALS"} for s in severities],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        }
        if standard:
            fragment = _STANDARD_FRAGMENTS.get(standard.lower(), standard.lower())
            filters["ProductArn"] = [{"Value": fragment, "Comparison": "CONTAINS"}]
        results: list[dict] = []
        try:
            paginator = self._client.get_paginator("get_findings")
            for page in paginator.paginate(Filters=filters, PaginationConfig={"MaxItems": limit}):
                for f in page.get("Findings", []):
                    results.append(self._shape_finding(f))
                    if len(results) >= limit:
                        return results
        except ClientError as exc:
            return [{"error": str(exc)}]
        return results

    def security_score(self) -> dict[str, Any]:
        """Return enabled standards with their pass/fail control ratios."""
        try:
            resp = self._client.get_enabled_standards()
            standards = []
            for sub in resp.get("StandardsSubscriptions", []):
                arn = sub.get("StandardsSubscriptionArn", "")
                controls_resp = self._client.describe_standards_controls(StandardsSubscriptionArn=arn)
                controls = controls_resp.get("Controls", [])
                passed = sum(1 for c in controls if c.get("ControlStatus") == "ENABLED" and c.get("ComplianceStatus") == "PASSED")
                failed = sum(1 for c in controls if c.get("ComplianceStatus") == "FAILED")
                total_controls = len(controls)
                score = round(passed / total_controls * 100, 1) if total_controls else 0.0
                standards.append({
                    "standard_arn": sub.get("StandardsArn", ""),
                    "status": sub.get("StandardsStatus", ""),
                    "total_controls": total_controls,
                    "passed": passed,
                    "failed": failed,
                    "score_pct": score,
                })
            return {"region": self.region, "standards": standards}
        except ClientError as exc:
            return {"error": str(exc), "region": self.region}

    @staticmethod
    def _shape_finding(f: dict) -> dict[str, Any]:
        return {
            "id": f.get("Id", ""),
            "title": f.get("Title", ""),
            "severity": f.get("Severity", {}).get("Label", ""),
            "compliance_status": f.get("Compliance", {}).get("Status", ""),
            "resource_type": f.get("Resources", [{}])[0].get("Type", ""),
            "resource_id": f.get("Resources", [{}])[0].get("Id", ""),
            "remediation_url": f.get("Remediation", {}).get("Recommendation", {}).get("Url", ""),
            "description": f.get("Description", ""),
            "updated_at": f.get("UpdatedAt", ""),
        }
