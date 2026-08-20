#!/usr/bin/env python3
"""
Contextual Orchestration Agent PR Reviewer for AWS Data Perimeters.
Parses CloudFormation templates/diffs synthesized by CDK and evaluates data paths
against organizational policy objectives and exception manifests.
"""

import json
import os
import sys

POLICY_OBJECTIVE_PATH = os.path.join("policies", "data_perimeter_objective.json")
EXCEPTION_MANIFEST_PATH = os.path.join("policies", "exception_manifest.json")

def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def analyze_cloudformation_template(template_path):
    if not os.path.exists(template_path):
        print(f"[Error] Template file not found: {template_path}")
        return []

    with open(template_path, "r", encoding="utf-8") as f:
        template = json.load(f)

    resources = template.get("Resources", {})
    findings = []
    
    # Load exceptions
    exceptions_data = load_json(EXCEPTION_MANIFEST_PATH) or {}
    approved_exceptions = exceptions_data.get("approved_exceptions", [])
    approved_arns = [e.get("approved_bucket_arn") for e in approved_exceptions]

    for logical_id, resource in resources.items():
        res_type = resource.get("Type", "")
        props = resource.get("Properties", {})

        # Check IAM Roles & Policies for S3 write permissions
        if res_type == "AWS::IAM::Policy" or res_type == "AWS::IAM::Role":
            policies = []
            if res_type == "AWS::IAM::Policy":
                doc = props.get("PolicyDocument", {})
                policies.append(("Policy", logical_id, doc))
            elif res_type == "AWS::IAM::Role":
                for inline in props.get("Policies", []):
                    pdoc = inline.get("PolicyDocument", {})
                    pname = inline.get("PolicyName", logical_id)
                    policies.append((pname, logical_id, pdoc))

            for pname, role_id, doc in policies:
                for statement in doc.get("Statement", []):
                    effect = statement.get("Effect", "Allow")
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    has_s3_write = any("s3:PutObject" in act or "s3:*" in act or "*" in act for act in actions)
                    if effect == "Allow" and has_s3_write:
                        conditions = statement.get("Condition", {})
                        has_org_condition = False
                        
                        # Check for OrgID condition keys across common condition operators
                        for op, cond_map in conditions.items():
                            if isinstance(cond_map, dict):
                                if "aws:PrincipalOrgID" in cond_map or "aws:ResourceOrgID" in cond_map:
                                    has_org_condition = True
                                    break

                        # Check destination resource restrictions
                        resource_arn = statement.get("Resource", "*")
                        is_exception = resource_arn in approved_arns

                        if not has_org_condition and not is_exception:
                            findings.append({
                                "role_or_policy": role_id,
                                "policy_name": pname,
                                "action": actions,
                                "resource": resource_arn,
                                "missing_conditions": ["aws:PrincipalOrgID", "aws:ResourceOrgID"]
                            })

    return findings

def generate_markdown_finding(findings):
    if not findings:
        return (
            "## Data-Perimeter Review Finding: Compliant\n\n"
            "**Status:** PASSED\n\n"
            "All S3 data-path changes in this pull request contain valid organizational identity and resource "
            "condition keys (`aws:PrincipalOrgID` / `aws:ResourceOrgID`) or match approved exception manifests.\n"
        )

    finding = findings[0]
    comment = (
        "## Data-Perimeter Review Finding: Potential External Exfiltration Path\n\n"
        "**Status:** NEEDS HUMAN REVIEW\n\n"
        f"- **Affected resources:** IAM Resource `{finding['role_or_policy']}`, Policy `{finding['policy_name']}`.\n"
        f"- **Risk:** The role gains `s3:PutObject` permissions on `{finding['resource']}`, but the statement "
        "does not restrict principals or destinations using organizational condition keys (`aws:PrincipalOrgID` / `aws:ResourceOrgID`). "
        "If this role is subsequently exploited via a confused-deputy path, data can egress to an unmonitored external account.\n"
        "- **Remediation:** Add an `aws:ResourceOrgID` condition key via a Resource Control Policy (RCP), "
        "or an `aws:PrincipalOrgID` condition key, or confirm this change against the approved-vendor exception manifest (`EXC-2026-04`).\n"
        "- **Required action:** A human reviewer must verify exception scope or update the policy before merge.\n"
    )
    return comment

def main():
    template_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("cdk", "cdk.out", "DataPerimeterStack.template.json")
    print(f"[Agent] Reviewing CloudFormation template: {template_path}")
    
    findings = analyze_cloudformation_template(template_path)
    markdown_report = generate_markdown_finding(findings)

    print("\n" + "=" * 60)
    print(markdown_report)
    print("=" * 60 + "\n")

    # Output comment file for GitHub Actions or CLI runner
    with open("finding_comment.md", "w", encoding="utf-8") as f:
        f.write(markdown_report)
    print("[Agent] Finding written to finding_comment.md")

if __name__ == "__main__":
    main()
