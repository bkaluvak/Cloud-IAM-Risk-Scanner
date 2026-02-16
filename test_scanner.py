#!/usr/bin/env python3
"""
Test script for IAM Risk Scanner
Demonstrates functionality with simulated data when AWS credentials aren't available
"""

import json
from datetime import datetime
from iam_risk_scanner import (
    RiskFinding, RiskLevel, CloudProvider, ReportGenerator
)


def create_sample_findings():
    """Create sample findings for demonstration"""
    findings = []
    
    # Critical: Full wildcard permissions
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="Role",
        principal_name="LegacyApplicationRole",
        principal_id="AROAI234567890EXAMPLE1",
        risk_type="Full Wildcard Permissions",
        risk_level=RiskLevel.CRITICAL.value,
        description="Policy allows all actions on all resources (*:* on *)",
        policy_name="AllowEverything",
        policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }),
        remediation="Apply least privilege principle - grant specific permissions",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # Critical: Administrator Access
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="User",
        principal_name="john.doe",
        principal_id="AIDAI234567890EXAMPLE2",
        risk_type="Administrator Access",
        risk_level=RiskLevel.CRITICAL.value,
        description="User has AdministratorAccess policy attached",
        policy_name="arn:aws:iam::aws:policy/AdministratorAccess",
        policy_document="AWS Managed Policy: AdministratorAccess",
        remediation="Use least privilege - grant only required permissions",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # Critical: Wildcard Trust Policy
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="Role",
        principal_name="PublicAssumeRole",
        principal_id="AROAI234567890EXAMPLE3",
        risk_type="Wildcard Trust Policy",
        risk_level=RiskLevel.CRITICAL.value,
        description="Role can be assumed by any AWS principal",
        policy_name="AssumeRolePolicyDocument",
        policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
            }]
        }),
        remediation="Restrict trust policy to specific principals",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # Critical: Privilege Escalation
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="User",
        principal_name="developer",
        principal_id="AIDAI234567890EXAMPLE4",
        risk_type="Privilege Escalation Risk",
        risk_level=RiskLevel.CRITICAL.value,
        description="Policy grants privilege escalation actions: iam:AttachUserPolicy, iam:CreateAccessKey",
        policy_name="DeveloperPolicy",
        policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "iam:AttachUserPolicy",
                    "iam:CreateAccessKey",
                    "iam:PutUserPolicy"
                ],
                "Resource": "*"
            }]
        }),
        remediation="Review and restrict privilege escalation permissions",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # High: No MFA
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="User",
        principal_name="jane.smith",
        principal_id="AIDAI234567890EXAMPLE5",
        risk_type="No MFA Enabled",
        risk_level=RiskLevel.HIGH.value,
        description="User has console access but no MFA device configured",
        policy_name="N/A",
        policy_document="Console access enabled",
        remediation="Enable MFA for all users with console access",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # High: Wildcard Actions
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="Role",
        principal_name="DataProcessingRole",
        principal_id="AROAI234567890EXAMPLE6",
        risk_type="Wildcard Actions",
        risk_level=RiskLevel.HIGH.value,
        description="Policy allows wildcard actions: s3:*",
        policy_name="S3FullAccess",
        policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::specific-bucket/*"
            }]
        }),
        remediation="Specify explicit actions instead of wildcards",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # High: Data Exfiltration Risk
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="User",
        principal_name="analyst",
        principal_id="AIDAI234567890EXAMPLE7",
        risk_type="Data Exfiltration Risk",
        risk_level=RiskLevel.HIGH.value,
        description="Policy allows broad data access: s3:GetObject, secretsmanager:GetSecretValue on *",
        policy_name="AnalystAccess",
        policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "secretsmanager:GetSecretValue",
                    "ssm:GetParameter"
                ],
                "Resource": "*"
            }]
        }),
        remediation="Restrict data access to specific resources",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # Medium: Cross-Account Access
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="Role",
        principal_name="PartnerAccessRole",
        principal_id="AROAI234567890EXAMPLE8",
        risk_type="Cross-Account Access",
        risk_level=RiskLevel.MEDIUM.value,
        description="Role can be assumed by account: 123456789012",
        policy_name="AssumeRolePolicyDocument",
        policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole"
            }]
        }),
        remediation="Review and validate cross-account access requirements",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    # Medium: Multiple Access Keys
    findings.append(RiskFinding(
        provider="AWS",
        principal_type="User",
        principal_name="service-account",
        principal_id="AIDAI234567890EXAMPLE9",
        risk_type="Multiple Access Keys",
        risk_level=RiskLevel.MEDIUM.value,
        description="User has 2 access keys",
        policy_name="N/A",
        policy_document=json.dumps([
            {"AccessKeyId": "AKIAI234567890EXAMPLE1", "Status": "Active"},
            {"AccessKeyId": "AKIAI234567890EXAMPLE2", "Status": "Active"}
        ]),
        remediation="Rotate and remove unused access keys",
        timestamp=datetime.utcnow().isoformat()
    ))
    
    return findings


def main():
    """Generate sample reports"""
    print("Generating sample IAM risk reports...\n")
    
    findings = create_sample_findings()
    
    # Generate reports
    ReportGenerator.generate_json(findings, "sample_iam_risks.json")
    ReportGenerator.generate_csv(findings, "sample_iam_risks.csv")
    ReportGenerator.print_summary(findings)
    
    print("\nSample reports generated:")
    print("  - sample_iam_risks.json")
    print("  - sample_iam_risks.csv")
    print("\nTo scan real AWS resources, run:")
    print("  python iam_risk_scanner.py --provider aws")


if __name__ == '__main__':
    main()
