"""AWS Config API wrapper — compliance summaries, rule status, resource listing."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from aws_compliance_mcp.aws_client import get_client


class ConfigTools:
    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        self._client = get_client("config", region)

    def compliance_summary(self) -> dict[str, Any]:
        """Return overall Config compliance counts."""
        try:
            resp = self._client.get_compliance_summary_by_config_rule()
            summary = resp.get("ComplianceSummary", {})
            compliant = summary.get("CompliantResourceCount", {}).get("CappedCount", 0)
            non_compliant = summary.get("NonCompliantResourceCount", {}).get("CappedCount", 0)
            total = compliant + non_compliant
            pct = round((compliant / total * 100), 1) if total else 0.0
            return {
                "region": self.region,
                "compliant_rules": compliant,
                "non_compliant_rules": non_compliant,
                "total_rules": total,
                "compliance_percentage": pct,
            }
        except ClientError as exc:
            return {"error": str(exc), "region": self.region}

    def list_rules(self) -> list[dict[str, Any]]:
        """Return all Config rules with their compliance status."""
        rules: list[dict] = []
        paginator = self._client.get_paginator("describe_compliance_by_config_rule")
        try:
            for page in paginator.paginate():
                for item in page.get("ComplianceByConfigRules", []):
                    compliance = item.get("Compliance", {})
                    rules.append(
                        {
                            "rule_name": item["ConfigRuleName"],
                            "compliance_type": compliance.get("ComplianceType", "NOT_APPLICABLE"),
                            "compliant_count": compliance.get("ComplianceContributorCount", {}).get(
                                "CappedCount", 0
                            ),
                        }
                    )
        except ClientError as exc:
            return [{"error": str(exc)}]
        return rules

    def rule_status(self, rule_name: str) -> dict[str, Any]:
        """Return detailed status for a single Config rule."""
        try:
            resp = self._client.describe_compliance_by_config_rule(
                ConfigRuleNames=[rule_name]
            )
            items = resp.get("ComplianceByConfigRules", [])
            if not items:
                return {"error": f"Rule '{rule_name}' not found", "region": self.region}
            item = items[0]
            compliance = item.get("Compliance", {})
            eval_resp = self._client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=["NON_COMPLIANT"],
                Limit=25,
            )
            non_compliant_resources = [
                {
                    "resource_type": e["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceType"],
                    "resource_id": e["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"],
                    "annotation": e.get("Annotation", ""),
                    "result_recorded_time": str(e.get("ResultRecordedTime", "")),
                }
                for e in eval_resp.get("EvaluationResults", [])
            ]
            return {
                "rule_name": rule_name,
                "compliance_type": compliance.get("ComplianceType", "NOT_APPLICABLE"),
                "non_compliant_resources": non_compliant_resources,
                "region": self.region,
            }
        except ClientError as exc:
            return {"error": str(exc), "rule_name": rule_name}

    def noncompliant_resources(self, rule_name: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Return resources that are NON_COMPLIANT, optionally filtered by rule."""
        results: list[dict] = []
        try:
            if rule_name:
                resp = self._client.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule_name,
                    ComplianceTypes=["NON_COMPLIANT"],
                    Limit=min(limit, 100),
                )
                for e in resp.get("EvaluationResults", []):
                    qual = e["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
                    results.append({
                        "rule_name": qual.get("ConfigRuleName", rule_name),
                        "resource_type": qual.get("ResourceType", ""),
                        "resource_id": qual.get("ResourceId", ""),
                        "annotation": e.get("Annotation", ""),
                    })
            else:
                paginator = self._client.get_paginator("describe_compliance_by_resource")
                for page in paginator.paginate(
                    ComplianceTypes=["NON_COMPLIANT"],
                    PaginationConfig={"MaxItems": limit},
                ):
                    for item in page.get("ComplianceByResources", []):
                        results.append({
                            "resource_type": item.get("ResourceType", ""),
                            "resource_id": item.get("ResourceId", ""),
                            "compliance_type": item.get("Compliance", {}).get("ComplianceType", ""),
                        })
        except ClientError as exc:
            return [{"error": str(exc)}]
        return results[:limit]
