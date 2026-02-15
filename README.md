# Cloud-IAM-Risk-Scanner

# Cloud IAM Risk Scanner

A comprehensive security tool that enumerates cloud IAM principals, analyzes policies, detects risky patterns, and outputs findings in CSV and JSON formats.

## Features

- **Multi-Cloud Support**: AWS (implemented), Azure and GCP (extensible)
- **Comprehensive Enumeration**: Scans users, roles, groups, and service accounts
- **Risk Detection**: Identifies multiple security risks including:
  - Wildcard permissions (`*:*` on `*`)
  - Privilege escalation paths
  - Missing MFA on console users
  - Overly permissive policies
  - Cross-account access risks
  - Administrator/PowerUser access
  - Data exfiltration risks
  - Multiple access keys
- **Flexible Output**: JSON and CSV reports with full evidence
- **Risk Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW, INFO

## Installation

### Prerequisites

- Python 3.7+
- Cloud provider credentials configured

### Install Dependencies

```bash
pip install -r requirements.txt
```

For AWS scanning, ensure you have:
```bash
pip install boto3
```

## Configuration

### AWS Setup

1. **Configure AWS credentials** using one of these methods:

   ```bash
   # Method 1: AWS CLI
   aws configure
   
   # Method 2: Environment variables
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   
   # Method 3: IAM role (for EC2/Lambda)
   # Credentials automatically available
   ```

2. **Required IAM permissions** for the scanning principal:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "iam:ListUsers",
           "iam:ListRoles",
           "iam:ListGroups",
           "iam:ListUserPolicies",
           "iam:ListRolePolicies",
           "iam:ListGroupPolicies",
           "iam:ListAttachedUserPolicies",
           "iam:ListAttachedRolePolicies",
           "iam:ListAttachedGroupPolicies",
           "iam:GetUserPolicy",
           "iam:GetRolePolicy",
           "iam:GetGroupPolicy",
           "iam:GetPolicy",
           "iam:GetPolicyVersion",
           "iam:ListAccessKeys",
           "iam:GetLoginProfile",
           "iam:ListMFADevices"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

### Azure Setup (Coming Soon)

```bash
pip install azure-identity azure-mgmt-authorization
az login
```

### GCP Setup (Coming Soon)

```bash
pip install google-cloud-iam
gcloud auth application-default login
```

## Usage

### Basic Scan

```bash
# Scan AWS IAM
python iam_risk_scanner.py --provider aws

# Scan with verbose logging
python iam_risk_scanner.py --provider aws --verbose
```

### Custom Output Files

```bash
python iam_risk_scanner.py --provider aws \
  --json-output my_findings.json \
  --csv-output my_findings.csv
```

### Command-Line Options

```
usage: iam_risk_scanner.py [-h] --provider {aws,azure,gcp}
                          [--json-output JSON_OUTPUT]
                          [--csv-output CSV_OUTPUT]
                          [--verbose]

Options:
  --provider {aws,azure,gcp}
                        Cloud provider to scan (required)
  --json-output FILE    JSON output file (default: iam_risks.json)
  --csv-output FILE     CSV output file (default: iam_risks.csv)
  --verbose            Enable verbose logging
```

## Output Formats

### JSON Output

```json
{
  "scan_metadata": {
    "scan_time": "2024-02-14T10:30:00.000000",
    "total_findings": 15,
    "findings_by_severity": {
      "CRITICAL": 3,
      "HIGH": 5,
      "MEDIUM": 4,
      "LOW": 2,
      "INFO": 1
    }
  },
  "findings": [
    {
      "provider": "AWS",
      "principal_type": "User",
      "principal_name": "admin-user",
      "principal_id": "AIDAI234567890EXAMPLE",
      "risk_type": "Administrator Access",
      "risk_level": "CRITICAL",
      "description": "User has AdministratorAccess policy attached",
      "policy_name": "arn:aws:iam::aws:policy/AdministratorAccess",
      "policy_document": "AWS Managed Policy: AdministratorAccess",
      "remediation": "Use least privilege - grant only required permissions",
      "timestamp": "2024-02-14T10:30:15.123456"
    }
  ]
}
```

### CSV Output

The CSV file contains the same information in tabular format:

| provider | principal_type | principal_name | principal_id | risk_type | risk_level | description | policy_name | policy_document | remediation | timestamp |
|----------|----------------|----------------|--------------|-----------|------------|-------------|-------------|-----------------|-------------|-----------|
| AWS | User | admin-user | AIDAI... | Administrator Access | CRITICAL | User has AdministratorAccess... | arn:aws:... | AWS Managed... | Use least privilege... | 2024-02-14... |

## Risk Types Detected

### CRITICAL Risks

1. **Full Wildcard Permissions** - `*:*` on `*`
2. **Administrator Access** - AdministratorAccess policy
3. **Wildcard Trust Policy** - Role assumable by any principal
4. **Privilege Escalation Risk** - Dangerous IAM modification permissions

### HIGH Risks

1. **Wildcard Actions** - `service:*` permissions
2. **Wildcard Resources** - Actions on all resources
3. **Power User Access** - PowerUserAccess policy
4. **No MFA Enabled** - Console access without MFA
5. **Data Exfiltration Risk** - Broad data access permissions

### MEDIUM Risks

1. **Cross-Account Access** - External account trust relationships
2. **Multiple Access Keys** - More than one active access key

## Example Output

```
======================================================================
IAM RISK SCAN SUMMARY
======================================================================
Total Findings: 23

Findings by Severity:
  CRITICAL  : 5
  HIGH      : 8
  MEDIUM    : 7
  LOW       : 3

Top Risks:

  [CRITICAL] Full Wildcard Permissions
    Principal: Role - LegacyApplicationRole
    Policy allows all actions on all resources (*:* on *)

  [CRITICAL] Administrator Access
    Principal: User - john.doe
    User has AdministratorAccess policy attached

  [HIGH] No MFA Enabled
    Principal: User - jane.smith
    User has console access but no MFA device configured

======================================================================
```

## Risk Patterns

The scanner detects the following patterns:

### Privilege Escalation Actions
- `iam:CreateAccessKey`
- `iam:AttachUserPolicy`
- `iam:CreatePolicyVersion`
- `iam:PassRole`
- `lambda:CreateFunction`
- `ec2:RunInstances`
- And more...

### Data Access Actions
- `s3:GetObject`
- `secretsmanager:GetSecretValue`
- `ssm:GetParameter`
- `kms:Decrypt`
- And more...

## Best Practices

1. **Run regularly**: Schedule scans weekly or after infrastructure changes
2. **Review CRITICAL findings immediately**: These pose immediate security risks
3. **Implement least privilege**: Grant only necessary permissions
4. **Enable MFA**: Require MFA for all console users
5. **Rotate keys**: Remove unused access keys and rotate regularly
6. **Audit cross-account access**: Validate external trust relationships
7. **Use managed policies carefully**: Avoid broad AWS managed policies

## Remediation Guide

### For Wildcard Permissions
Replace wildcards with specific services and resources:
```json
// Bad
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

// Good
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

### For Missing MFA
1. Enable virtual MFA device in IAM console
2. Enforce MFA via IAM policy conditions
3. Use AWS Organizations SCP to require MFA

### For Privilege Escalation
Review and restrict dangerous combinations:
- `iam:PassRole` + `lambda:CreateFunction`
- `iam:AttachUserPolicy` + policy creation permissions
- `iam:CreateAccessKey` on other users

## Integration

### CI/CD Pipeline

```yaml
# .github/workflows/iam-scan.yml
name: IAM Security Scan
on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run IAM scan
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          python iam_risk_scanner.py --provider aws
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: iam-scan-results
          path: |
            iam_risks.json
            iam_risks.csv
```

### Lambda Function

Deploy as a serverless function for automated scanning:

```python
import json
from iam_risk_scanner import IAMRiskScanner, CloudProvider, ReportGenerator

def lambda_handler(event, context):
    scanner = IAMRiskScanner(CloudProvider.AWS)
    findings = scanner.scan()
    
    # Upload to S3
    import boto3
    s3 = boto3.client('s3')
    
    report = {
        'scan_metadata': {
            'scan_time': datetime.utcnow().isoformat(),
            'total_findings': len(findings)
        },
        'findings': [f.to_dict() for f in findings]
    }
    
    s3.put_object(
        Bucket='security-scan-results',
        Key=f'iam-scan-{datetime.utcnow().date()}.json',
        Body=json.dumps(report)
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'Scan complete: {len(findings)} findings')
    }
```

## Troubleshooting

### "NoCredentialsError"
- Ensure AWS credentials are configured
- Verify credentials have necessary IAM permissions

### "AccessDenied" errors
- Check scanning principal has read permissions
- Review required IAM permissions in Configuration section

### No findings returned
- Verify there are IAM resources in the account
- Check that policies are attached to principals
- Enable verbose logging with `--verbose`

## Limitations

- **Read-only**: Tool only reads IAM configuration, never modifies
- **AWS-focused**: Azure and GCP support coming soon
- **Snapshot**: Captures point-in-time state
- **False positives**: Some findings may be acceptable for specific use cases
- **Rate limiting**: May hit AWS API rate limits on large accounts

## Contributing

Contributions welcome! Areas for improvement:
- Azure IAM scanning implementation
- GCP IAM scanning implementation
- Additional risk patterns
- Risk scoring/prioritization
- HTML report generation
- Integration with SIEM tools

## Security Considerations

- **Never commit credentials** to version control
- **Use read-only permissions** for scanning
- **Secure output files** - they contain sensitive information
- **Review findings carefully** before sharing
- **Rotate scanning credentials** regularly

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions, please open an issue on GitHub.
