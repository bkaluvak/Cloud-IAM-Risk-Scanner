# Quick Start Guide - IAM Risk Scanner

## 🚀 Get Started in 5 Minutes

### 1. Install Dependencies

```bash
pip install boto3
```

### 2. Configure AWS Credentials

**Option A: AWS CLI**
```bash
aws configure
```

**Option B: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_DEFAULT_REGION="us-east-1"
```

### 3. Run the Scanner

```bash
# Basic scan
python iam_risk_scanner.py --provider aws

# With verbose output
python iam_risk_scanner.py --provider aws --verbose
```

### 4. Review Results

The scanner creates two output files:
- `iam_risks.json` - Detailed JSON report
- `iam_risks.csv` - Spreadsheet-friendly format

## 📊 Testing Without AWS Credentials

Want to see how it works first? Run the test script:

```bash
python test_scanner.py
```

This generates sample reports with example findings.

## 🔍 What Gets Scanned?

✅ IAM Users (inline policies, attached policies, access keys, MFA status)
✅ IAM Roles (trust policies, inline policies, attached policies)  
✅ IAM Groups (inline policies, attached policies)

## ⚠️ Common Risks Detected

| Risk Level | Risk Type | Description |
|------------|-----------|-------------|
| 🔴 CRITICAL | Full Wildcard | `*:*` on `*` permissions |
| 🔴 CRITICAL | Admin Access | AdministratorAccess policy |
| 🔴 CRITICAL | Wildcard Trust | Role assumable by anyone |
| 🔴 CRITICAL | Privilege Escalation | IAM modification permissions |
| 🟠 HIGH | No MFA | Console access without MFA |
| 🟠 HIGH | Wildcard Actions | `service:*` permissions |
| 🟡 MEDIUM | Multiple Keys | More than one access key |

## 🛡️ Required IAM Permissions

Your scanning user/role needs these read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:List*",
      "iam:Get*"
    ],
    "Resource": "*"
  }]
}
```

See `scanner_iam_policy.json` for the complete policy.

## 📈 Understanding Results

### Console Summary
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
```

### JSON Report Structure
```json
{
  "scan_metadata": {
    "scan_time": "2024-02-14T10:30:00",
    "total_findings": 23,
    "findings_by_severity": {...}
  },
  "findings": [...]
}
```

## 🔧 Troubleshooting

**Problem**: "NoCredentialsError"
**Solution**: Configure AWS credentials (see step 2)

**Problem**: "AccessDenied"  
**Solution**: Add required IAM permissions to your user/role

**Problem**: "No findings returned"
**Solution**: Run with `--verbose` to see what's being scanned

## 📝 Next Steps

1. **Review CRITICAL findings** - These need immediate attention
2. **Create remediation tickets** - Use the remediation column
3. **Schedule regular scans** - Run weekly or after changes
4. **Integrate into CI/CD** - See README.md for examples

## 💡 Pro Tips

- Run the scanner from a read-only IAM role
- Store reports securely (they contain sensitive info)
- Compare reports over time to track improvements
- Filter CSV by risk_level for prioritization
- Use findings as input for security reviews

## 🆘 Need Help?

- Full documentation: See `README.md`
- AWS IAM policy: See `scanner_iam_policy.json`
- Sample data: Run `test_scanner.py`

---

**Remember**: This tool is read-only and never modifies your IAM configuration. It's safe to run in production accounts.
