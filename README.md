# AMI Lineage Governance Framework - Complete Solution

This comprehensive solution implements AMI lineage tracking and governance across AWS Organizations using Neptune graph database, Lambda functions, AWS Config, Security Hub, and Service Control Policies.

## Architecture Overview

The solution follows a multi-account architecture pattern:

- **Organization Account**: Manages SCPs and organization-wide EventBridge rules
- **Security Tooling Account**: Hosts Neptune database, Lambda functions, API Gateway, and Security Hub
- **Child Accounts**: Deploy Config rules, local EventBridge rules, and IAM roles

## Key Components

### Core Infrastructure
- **Neptune Graph Database**: Stores AMI relationships and metadata
- **Lambda Functions**: Process events, handle API requests, evaluate compliance
- **API Gateway**: Provides REST API for lineage queries and security context
- **EventBridge**: Captures AMI events across accounts and regions

### Governance & Compliance
- **Service Control Policies**: Enforce preventive controls on AMI usage
- **AWS Config Rules**: Continuous compliance monitoring
- **Security Hub**: Centralized security findings and compliance dashboard
- **SNS**: Notifications and alerts for non-compliant AMIs

### Security Features
- **Cross-account IAM roles**: Secure access between accounts
- **VPC isolation**: Neptune database in private subnets
- **Encryption**: At-rest and in-transit encryption for all data
- **Audit logging**: Complete audit trail via CloudTrail

## Deployment Structure

```
Organization Account
├── Service Control Policies (SCPs)
├── Organization-wide EventBridge Rules
└── Cross-account IAM Trust Policies

Security Tooling Account
├── Neptune Graph Database
├── Lambda Functions
├── API Gateway
├── Security Hub Custom Insights
├── SNS Topics
└── VPC Infrastructure

Child Accounts (Member Accounts)
├── AWS Config Rules
├── Local EventBridge Rules
├── Cross-account IAM Roles
└── CloudTrail Integration
```

## Quick Start

### Prerequisites
- AWS Organizations with all features enabled
- AWS CLI configured with appropriate permissions
- Python 3.9+ for Lambda functions
- CloudFormation deployment capabilities

### Deployment Order

1. **Organization Account Setup**
   ```bash
   cd deployment-scripts/organization
   ./deploy-organization-resources.sh
   ```

2. **Security Tooling Account Setup**
   ```bash
   cd deployment-scripts/shared
   ./deploy-shared-resources.sh
   ```

3. **Child Accounts Setup**
   ```bash
   cd deployment-scripts/child-account
   ./deploy-child-account-resources.sh
   ```

## Configuration Guide

### Organization Account Configuration
- Deploy Service Control Policies for AMI governance
- Set up organization-wide EventBridge rules
- Configure cross-account trust relationships

### Child Account Configuration
- Deploy AWS Config rules for compliance monitoring
- Set up local EventBridge rules for AMI events
- Configure IAM roles for cross-account access

### Security Tooling Account Configuration
- Deploy Neptune database with proper security
- Set up Lambda functions for event processing
- Configure API Gateway for external access
- Integrate with Security Hub for findings

## API Usage Examples

### Check AMI Security Context
```bash
curl -X GET "https://api.example.com/v1/ami/ami-1234567890abcdef0/security-context" \
  -H "Authorization: Bearer <token>"
```

### Assess Security Impact
```bash
curl -X POST "https://api.example.com/v1/security-impact" \
  -H "Content-Type: application/json" \
  -d '{
    "ami_id": "ami-1234567890abcdef0",
    "finding_type": "CVE",
    "finding_id": "CVE-2024-XXXX",
    "severity": "CRITICAL"
  }'
```

### Compliance Assessment
```bash
curl -X POST "https://api.example.com/v1/compliance-assessment" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": ["required_tags", "approved_source_validation"],
    "scope": "ORGANIZATION"
  }'
```

## Monitoring and Alerting

- **CloudWatch Dashboards**: Monitor system health and performance
- **SNS Notifications**: Real-time alerts for compliance violations
- **Security Hub Findings**: Centralized security posture management
- **Config Compliance**: Continuous compliance monitoring

## Security Considerations

- All data encrypted at rest and in transit
- Least privilege IAM permissions
- VPC isolation for sensitive components
- Comprehensive audit logging
- Regular security assessments

### Testing and Production Deployment

**⚠️ Important: Test in Lower Environments First**

Before deploying this solution to production, we strongly recommend:

1. **Deploy in Development/Test Environment**: Test the complete solution in a non-production AWS organization or isolated accounts to validate functionality and security controls
2. **Validate Security Controls**: Verify that Service Control Policies, Config rules, and Lambda functions work as expected without impacting production workloads
3. **Test Compliance Scenarios**: Simulate various AMI compliance scenarios to ensure the solution behaves correctly
4. **Performance Testing**: Validate Neptune database performance and Lambda function execution times with your expected AMI volume

**Production Customization Requirements**

This solution provides a foundational framework that should be customized for your specific requirements:

- **IAM Permissions**: Review and adjust IAM roles and policies to align with your organization's security standards
- **Compliance Rules**: Modify AWS Config rules and compliance checks to match your specific governance requirements
- **Notification Channels**: Configure SNS topics and notification endpoints according to your operational procedures
- **Retention Policies**: Adjust data retention periods for Neptune database and CloudWatch logs based on your compliance needs
- **Network Configuration**: Customize VPC settings, security groups, and network ACLs to fit your network architecture
- **Encryption Keys**: Replace default KMS keys with your organization's managed keys
- **Monitoring Thresholds**: Tune CloudWatch alarms and monitoring thresholds for your environment

## Support and Troubleshooting

See the documentation folder for:
- Detailed architecture diagrams
- Deployment troubleshooting guide
- Operations manual
- API reference documentation

## License

This solution is provided under the MIT License. See LICENSE file for details.
