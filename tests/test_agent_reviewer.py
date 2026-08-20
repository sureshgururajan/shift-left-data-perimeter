import unittest
import json
import os
import tempfile
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.agent_reviewer import (
    analyze_cloudformation_template,
    generate_markdown_finding,
    format_resource_target,
    resource_matches_exception,
)

class TestAgentReviewer(unittest.TestCase):

    def create_temp_template(self, resources_dict):
        fd, path = tempfile.mkstemp(suffix=".json")
        with open(fd, "w", encoding="utf-8") as f:
            json.dump({"Resources": resources_dict}, f)
        return path

    def test_compliant_policy_with_org_conditions(self):
        resources = {
            "CompliantRolePolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::internal-workload-bucket/*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:PrincipalOrgID": "o-org1234567",
                                        "aws:ResourceOrgID": "o-org1234567"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
        path = self.create_temp_template(resources)
        try:
            findings = analyze_cloudformation_template(path)
            self.assertEqual(len(findings), 0)
            markdown = generate_markdown_finding(findings)
            self.assertIn("PASSED", markdown)
            self.assertIn("Compliant", markdown)
        finally:
            os.remove(path)

    def test_non_compliant_policy_without_org_conditions(self):
        resources = {
            "NonCompliantRolePolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": {
                                    "Fn::Join": ["", [{"Fn::GetAtt": ["ProdBucket", "Arn"]}, "/*"]]
                                }
                            }
                        ]
                    }
                }
            }
        }
        path = self.create_temp_template(resources)
        try:
            findings = analyze_cloudformation_template(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["role_or_policy"], "NonCompliantRolePolicy")
            self.assertEqual(findings[0]["resource_formatted"], "ProdBucket.Arn/*")
            
            markdown = generate_markdown_finding(findings)
            self.assertIn("NEEDS HUMAN REVIEW", markdown)
            self.assertIn("Potential External Exfiltration Path", markdown)
            self.assertIn("ProdBucket.Arn/*", markdown)
        finally:
            os.remove(path)

    def test_approved_vendor_exception_matches(self):
        resources = {
            "VendorAnalyticsPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::approved-vendor-analytics/*"
                            }
                        ]
                    }
                }
            }
        }
        path = self.create_temp_template(resources)
        try:
            findings = analyze_cloudformation_template(path)
            self.assertEqual(len(findings), 0)
            markdown = generate_markdown_finding(findings)
            self.assertIn("PASSED", markdown)
        finally:
            os.remove(path)

    def test_unapproved_external_vendor_fails(self):
        resources = {
            "UnapprovedVendorPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::unauthorized-external-vendor/*"
                            }
                        ]
                    }
                }
            }
        }
        path = self.create_temp_template(resources)
        try:
            findings = analyze_cloudformation_template(path)
            self.assertEqual(len(findings), 1)
            markdown = generate_markdown_finding(findings)
            self.assertIn("NEEDS HUMAN REVIEW", markdown)
        finally:
            os.remove(path)

    def test_read_only_action_ignored(self):
        resources = {
            "ReadOnlyPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::external-dataset/*"
                            }
                        ]
                    }
                }
            }
        }
        path = self.create_temp_template(resources)
        try:
            findings = analyze_cloudformation_template(path)
            self.assertEqual(len(findings), 0)
        finally:
            os.remove(path)

if __name__ == "__main__":
    unittest.main()
