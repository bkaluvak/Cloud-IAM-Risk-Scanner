#!/usr/bin/env python3
"""
Cloud IAM Risk Scanner
Enumerates principals, policies, and detects risky IAM patterns across cloud providers.
Outputs findings in CSV and JSON formats.
"""

import json
import csv
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"


@dataclass
class RiskFinding:
    """Represents a security risk finding"""
    provider: str
    principal_type: str
    principal_name: str
    principal_id: str
    risk_type: str
    risk_level: str
    description: str
    policy_name: str
    policy_document: str
    remediation: str
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RiskPattern:
    """Defines risky IAM patterns to detect"""
    
    # High-risk actions that could lead to privilege escalation
    PRIVILEGE_ESCALATION_ACTIONS = {
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'iam:UpdateLoginProfile',
        'iam:AttachUserPolicy',
        'iam:AttachRolePolicy',
        'iam:AttachGroupPolicy',
        'iam:PutUserPolicy',
        'iam:PutRolePolicy',
        'iam:PutGroupPolicy',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:PassRole',
        'sts:AssumeRole',
        'lambda:CreateFunction',
        'lambda:UpdateFunctionCode',
        'ec2:RunInstances',
        'iam:UpdateAssumeRolePolicy',
    }
    
    # Administrative actions
    ADMIN_ACTIONS = {
        'iam:*',
        'sts:*',
        'organizations:*',
        'account:*',
    }
    
    # Data access actions
    DATA_EXFILTRATION_ACTIONS = {
        's3:GetObject',
        's3:ListBucket',
        'rds:DownloadDBLogFilePortion',
        'secretsmanager:GetSecretValue',
        'ssm:GetParameter',
        'kms:Decrypt',
    }


class IAMRiskScanner:
    """Main scanner class for detecting IAM risks"""
    
    def __init__(self, provider: CloudProvider):
        self.provider = provider
        self.findings: List[RiskFinding] = []
        self.principals_scanned = 0
        
    def scan(self) -> List[RiskFinding]:
        """Main scan orchestrator"""
        logger.info(f"Starting IAM risk scan for {self.provider.value}")
        
        if self.provider == CloudProvider.AWS:
            self._scan_aws()
        elif self.provider == CloudProvider.AZURE:
            self._scan_azure()
        elif self.provider == CloudProvider.GCP:
            self._scan_gcp()
        
        logger.info(f"Scan complete. Found {len(self.findings)} risk findings across {self.principals_scanned} principals")
        return self.findings
    
    def _scan_aws(self):
        """Scan AWS IAM resources"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            logger.error("boto3 not installed. Run: pip install boto3")
            return
        
        try:
            iam = boto3.client('iam')
            logger.info("Connected to AWS IAM")
            
            # Scan users
            self._scan_aws_users(iam)
            
            # Scan roles
            self._scan_aws_roles(iam)
            
            # Scan groups
            self._scan_aws_groups(iam)
            
        except NoCredentialsError:
            logger.error("AWS credentials not found. Configure AWS CLI or environment variables.")
        except ClientError as e:
            logger.error(f"AWS API error: {e}")
        except Exception as e:
            logger.error(f"Error scanning AWS: {e}")
    
    def _scan_aws_users(self, iam):
        """Enumerate and analyze AWS IAM users"""
        logger.info("Scanning IAM users...")
        
        try:
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    self.principals_scanned += 1
                    username = user['UserName']
                    user_id = user['UserId']
                    
                    # Check inline policies
                    inline_policies = iam.list_user_policies(UserName=username)
                    for policy_name in inline_policies['PolicyNames']:
                        policy_doc = iam.get_user_policy(
                            UserName=username,
                            PolicyName=policy_name
                        )
                        self._analyze_aws_policy(
                            'User',
                            username,
                            user_id,
                            policy_name,
                            policy_doc['PolicyDocument']
                        )
                    
                    # Check attached managed policies
                    attached = iam.list_attached_user_policies(UserName=username)
                    for policy in attached['AttachedPolicies']:
                        self._analyze_aws_managed_policy(
                            'User',
                            username,
                            user_id,
                            policy['PolicyArn']
                        )
                    
                    # Check for access keys
                    access_keys = iam.list_access_keys(UserName=username)
                    if len(access_keys['AccessKeyMetadata']) > 1:
                        self._add_finding(
                            'User',
                            username,
                            user_id,
                            'Multiple Access Keys',
                            RiskLevel.MEDIUM,
                            f"User has {len(access_keys['AccessKeyMetadata'])} access keys",
                            'N/A',
                            json.dumps(access_keys['AccessKeyMetadata'], default=str),
                            'Rotate and remove unused access keys'
                        )
                    
                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=username)
                        # User has console access - check for MFA
                        mfa_devices = iam.list_mfa_devices(UserName=username)
                        if len(mfa_devices['MFADevices']) == 0:
                            self._add_finding(
                                'User',
                                username,
                                user_id,
                                'No MFA Enabled',
                                RiskLevel.HIGH,
                                'User has console access but no MFA device configured',
                                'N/A',
                                'Console access enabled',
                                'Enable MFA for all users with console access'
                            )
                    except iam.exceptions.NoSuchEntityException:
                        pass  # No console access
                        
        except Exception as e:
            logger.error(f"Error scanning users: {e}")
    
    def _scan_aws_roles(self, iam):
        """Enumerate and analyze AWS IAM roles"""
        logger.info("Scanning IAM roles...")
        
        try:
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    self.principals_scanned += 1
                    rolename = role['RoleName']
                    role_id = role['RoleId']
                    
                    # Analyze trust policy
                    trust_policy = role['AssumeRolePolicyDocument']
                    self._analyze_aws_trust_policy(rolename, role_id, trust_policy)
                    
                    # Check inline policies
                    inline_policies = iam.list_role_policies(RoleName=rolename)
                    for policy_name in inline_policies['PolicyNames']:
                        policy_doc = iam.get_role_policy(
                            RoleName=rolename,
                            PolicyName=policy_name
                        )
                        self._analyze_aws_policy(
                            'Role',
                            rolename,
                            role_id,
                            policy_name,
                            policy_doc['PolicyDocument']
                        )
                    
                    # Check attached managed policies
                    attached = iam.list_attached_role_policies(RoleName=rolename)
                    for policy in attached['AttachedPolicies']:
                        self._analyze_aws_managed_policy(
                            'Role',
                            rolename,
                            role_id,
                            policy['PolicyArn']
                        )
                        
        except Exception as e:
            logger.error(f"Error scanning roles: {e}")
    
    def _scan_aws_groups(self, iam):
        """Enumerate and analyze AWS IAM groups"""
        logger.info("Scanning IAM groups...")
        
        try:
            paginator = iam.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    self.principals_scanned += 1
                    groupname = group['GroupName']
                    group_id = group['GroupId']
                    
                    # Check inline policies
                    inline_policies = iam.list_group_policies(GroupName=groupname)
                    for policy_name in inline_policies['PolicyNames']:
                        policy_doc = iam.get_group_policy(
                            GroupName=groupname,
                            PolicyName=policy_name
                        )
                        self._analyze_aws_policy(
                            'Group',
                            groupname,
                            group_id,
                            policy_name,
                            policy_doc['PolicyDocument']
                        )
                    
                    # Check attached managed policies
                    attached = iam.list_attached_group_policies(GroupName=groupname)
                    for policy in attached['AttachedPolicies']:
                        self._analyze_aws_managed_policy(
                            'Group',
                            groupname,
                            group_id,
                            policy['PolicyArn']
                        )
                        
        except Exception as e:
            logger.error(f"Error scanning groups: {e}")
    
    def _analyze_aws_trust_policy(self, rolename: str, role_id: str, trust_policy: Dict):
        """Analyze AWS role trust policy for risks"""
        policy_str = json.dumps(trust_policy)
        
        for statement in trust_policy.get('Statement', []):
            effect = statement.get('Effect', '')
            if effect != 'Allow':
                continue
                
            principal = statement.get('Principal', {})
            
            # Check for wildcard principals
            if principal == '*' or principal.get('AWS') == '*':
                self._add_finding(
                    'Role',
                    rolename,
                    role_id,
                    'Wildcard Trust Policy',
                    RiskLevel.CRITICAL,
                    'Role can be assumed by any AWS principal',
                    'AssumeRolePolicyDocument',
                    policy_str,
                    'Restrict trust policy to specific principals'
                )
            
            # Check for cross-account access
            aws_principals = principal.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            
            for prin in aws_principals:
                if isinstance(prin, str) and ':' in prin:
                    # Extract account ID
                    parts = prin.split(':')
                    if len(parts) >= 5:
                        account_id = parts[4]
                        # This is a basic check - in production, compare against known account IDs
                        self._add_finding(
                            'Role',
                            rolename,
                            role_id,
                            'Cross-Account Access',
                            RiskLevel.MEDIUM,
                            f'Role can be assumed by account: {account_id}',
                            'AssumeRolePolicyDocument',
                            policy_str,
                            'Review and validate cross-account access requirements'
                        )
    
    def _analyze_aws_managed_policy(self, principal_type: str, principal_name: str, 
                                     principal_id: str, policy_arn: str):
        """Analyze AWS managed policy attachment"""
        import boto3
        iam = boto3.client('iam')
        
        try:
            # Check for AWS managed admin policies
            if 'AdministratorAccess' in policy_arn:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Administrator Access',
                    RiskLevel.CRITICAL,
                    f'{principal_type} has AdministratorAccess policy attached',
                    policy_arn,
                    'AWS Managed Policy: AdministratorAccess',
                    'Use least privilege - grant only required permissions'
                )
            elif 'PowerUserAccess' in policy_arn:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Power User Access',
                    RiskLevel.HIGH,
                    f'{principal_type} has PowerUserAccess policy attached',
                    policy_arn,
                    'AWS Managed Policy: PowerUserAccess',
                    'Review permissions and apply least privilege'
                )
            
            # Get policy version for custom managed policies
            if not policy_arn.startswith('arn:aws:iam::aws:policy'):
                policy = iam.get_policy(PolicyArn=policy_arn)
                version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['Policy']['DefaultVersionId']
                )
                self._analyze_aws_policy(
                    principal_type,
                    principal_name,
                    principal_id,
                    policy_arn,
                    version['PolicyVersion']['Document']
                )
                
        except Exception as e:
            logger.warning(f"Error analyzing managed policy {policy_arn}: {e}")
    
    def _analyze_aws_policy(self, principal_type: str, principal_name: str, 
                            principal_id: str, policy_name: str, policy_doc: Dict):
        """Analyze AWS policy document for risky patterns"""
        policy_str = json.dumps(policy_doc)
        
        for statement in policy_doc.get('Statement', []):
            effect = statement.get('Effect', '')
            if effect != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for wildcards
            has_wildcard_action = any('*' in action for action in actions)
            has_wildcard_resource = any(resource == '*' for resource in resources)
            
            if has_wildcard_action and has_wildcard_resource:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Full Wildcard Permissions',
                    RiskLevel.CRITICAL,
                    'Policy allows all actions on all resources (*:* on *)',
                    policy_name,
                    policy_str,
                    'Apply least privilege principle - grant specific permissions'
                )
            elif has_wildcard_action:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Wildcard Actions',
                    RiskLevel.HIGH,
                    f'Policy allows wildcard actions: {", ".join(a for a in actions if "*" in a)}',
                    policy_name,
                    policy_str,
                    'Specify explicit actions instead of wildcards'
                )
            elif has_wildcard_resource:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Wildcard Resources',
                    RiskLevel.HIGH,
                    'Policy allows actions on all resources (*)',
                    policy_name,
                    policy_str,
                    'Specify explicit resource ARNs'
                )
            
            # Check for privilege escalation actions
            priv_esc_actions = [a for a in actions 
                               if a in RiskPattern.PRIVILEGE_ESCALATION_ACTIONS]
            if priv_esc_actions:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Privilege Escalation Risk',
                    RiskLevel.CRITICAL,
                    f'Policy grants privilege escalation actions: {", ".join(priv_esc_actions)}',
                    policy_name,
                    policy_str,
                    'Review and restrict privilege escalation permissions'
                )
            
            # Check for data exfiltration risks
            data_actions = [a for a in actions 
                           if a in RiskPattern.DATA_EXFILTRATION_ACTIONS]
            if data_actions and has_wildcard_resource:
                self._add_finding(
                    principal_type,
                    principal_name,
                    principal_id,
                    'Data Exfiltration Risk',
                    RiskLevel.HIGH,
                    f'Policy allows broad data access: {", ".join(data_actions)} on *',
                    policy_name,
                    policy_str,
                    'Restrict data access to specific resources'
                )
    
    def _scan_azure(self):
        """Scan Azure AD and RBAC"""
        logger.warning("Azure scanning not yet implemented. Install: pip install azure-identity azure-mgmt-authorization")
        # Placeholder for Azure implementation
        
    def _scan_gcp(self):
        """Scan GCP IAM"""
        logger.warning("GCP scanning not yet implemented. Install: pip install google-cloud-iam")
        # Placeholder for GCP implementation
    
    def _add_finding(self, principal_type: str, principal_name: str, principal_id: str,
                     risk_type: str, risk_level: RiskLevel, description: str,
                     policy_name: str, policy_document: str, remediation: str):
        """Add a risk finding to the results"""
        finding = RiskFinding(
            provider=self.provider.value,
            principal_type=principal_type,
            principal_name=principal_name,
            principal_id=principal_id,
            risk_type=risk_type,
            risk_level=risk_level.value,
            description=description,
            policy_name=policy_name,
            policy_document=policy_document,
            remediation=remediation,
            timestamp=datetime.utcnow().isoformat()
        )
        self.findings.append(finding)
        logger.debug(f"Found {risk_level.value} risk: {risk_type} for {principal_type} {principal_name}")


class ReportGenerator:
    """Generate reports from scan findings"""
    
    @staticmethod
    def generate_json(findings: List[RiskFinding], output_file: str):
        """Generate JSON report"""
        report = {
            'scan_metadata': {
                'scan_time': datetime.utcnow().isoformat(),
                'total_findings': len(findings),
                'findings_by_severity': ReportGenerator._count_by_severity(findings)
            },
            'findings': [f.to_dict() for f in findings]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to: {output_file}")
    
    @staticmethod
    def generate_csv(findings: List[RiskFinding], output_file: str):
        """Generate CSV report"""
        if not findings:
            logger.warning("No findings to write to CSV")
            return
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'provider', 'principal_type', 'principal_name', 'principal_id',
                'risk_type', 'risk_level', 'description', 'policy_name',
                'policy_document', 'remediation', 'timestamp'
            ])
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding.to_dict())
        
        logger.info(f"CSV report saved to: {output_file}")
    
    @staticmethod
    def _count_by_severity(findings: List[RiskFinding]) -> Dict[str, int]:
        """Count findings by severity level"""
        counts = {level.value: 0 for level in RiskLevel}
        for finding in findings:
            counts[finding.risk_level] += 1
        return counts
    
    @staticmethod
    def print_summary(findings: List[RiskFinding]):
        """Print summary to console"""
        severity_counts = ReportGenerator._count_by_severity(findings)
        
        print("\n" + "="*70)
        print("IAM RISK SCAN SUMMARY")
        print("="*70)
        print(f"Total Findings: {len(findings)}")
        print("\nFindings by Severity:")
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            count = severity_counts[level.value]
            if count > 0:
                print(f"  {level.value:10s}: {count}")
        
        if findings:
            print("\nTop Risks:")
            critical_findings = [f for f in findings if f.risk_level == RiskLevel.CRITICAL.value]
            high_findings = [f for f in findings if f.risk_level == RiskLevel.HIGH.value]
            
            for finding in (critical_findings + high_findings)[:10]:
                print(f"\n  [{finding.risk_level}] {finding.risk_type}")
                print(f"    Principal: {finding.principal_type} - {finding.principal_name}")
                print(f"    {finding.description}")
        
        print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Cloud IAM Risk Scanner - Detect risky IAM configurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan AWS with default outputs
  python iam_risk_scanner.py --provider aws
  
  # Scan with custom output files
  python iam_risk_scanner.py --provider aws --json-output findings.json --csv-output findings.csv
  
  # Verbose logging
  python iam_risk_scanner.py --provider aws --verbose
        '''
    )
    
    parser.add_argument(
        '--provider',
        choices=['aws', 'azure', 'gcp'],
        required=True,
        help='Cloud provider to scan'
    )
    
    parser.add_argument(
        '--json-output',
        default='iam_risks.json',
        help='JSON output file (default: iam_risks.json)'
    )
    
    parser.add_argument(
        '--csv-output',
        default='iam_risks.csv',
        help='CSV output file (default: iam_risks.csv)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Map provider string to enum
    provider_map = {
        'aws': CloudProvider.AWS,
        'azure': CloudProvider.AZURE,
        'gcp': CloudProvider.GCP
    }
    
    provider = provider_map[args.provider]
    
    # Run scan
    scanner = IAMRiskScanner(provider)
    findings = scanner.scan()
    
    # Generate reports
    ReportGenerator.generate_json(findings, args.json_output)
    ReportGenerator.generate_csv(findings, args.csv_output)
    ReportGenerator.print_summary(findings)
    
    # Exit with error code if critical findings
    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL.value)
    if critical_count > 0:
        logger.warning(f"Found {critical_count} CRITICAL findings!")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == '__main__':
    main()
