# AMI Lineage Governance Framework - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the AMI Lineage Governance Framework across your AWS Organization.

## Architecture Summary

The solution uses a multi-account architecture:

- **Organization Account**: Service Control Policies and organization-wide EventBridge rules
- **Security Tooling Account**: Neptune database, Lambda functions, API Gateway, Security Hub
- **Child Accounts**: Config rules, local EventBridge rules, IAM roles

## Prerequisites

### General Requirements
- AWS Organizations with all features enabled
- AWS CLI configured with appropriate permissions
- Python 3.9+ installed
- jq and zip utilities installed

### Account-Specific Requirements

#### Organization Account
- Organization management account access
- Permissions to create SCPs and attach them to OUs
- EventBridge permissions

#### Security Tooling Account
- VPC with private subnets (minimum 2 AZs)
- Permissions to create Neptune, Lambda, API Gateway, Security Hub resources
- S3 bucket creation permissions

#### Child Accounts
- Config service permissions
- IAM role creation permissions
- EventBridge permissions

## Deployment Order

### 1. Organization Account Setup

**What gets deployed:**
- Service Control Policies for AMI governance
- Organization-wide EventBridge rules
- Cross-account trust policies

**Resources created:**
- SCP: `AMI-Lineage-Governance-Policy`
- EventBridge custom bus: `ami-lineage-events`
- IAM role: `AMI-Lineage-CrossAccount-Role`
- EventBridge rules for AMI events

**Commands:**
```bash
cd deployment-scripts/organization
./deploy-organization-resources.sh
```

**Manual steps after deployment:**
1. Attach the created SCP to appropriate OUs
2. Save the Event Bus ARN and Cross-account Role ARN for next steps

### 2. Security Tooling Account Setup

**What gets deployed:**
- Neptune graph database cluster
- Lambda functions (event processor, API handler, compliance evaluator)
- API Gateway with REST endpoints
- SNS topics for notifications
- Security Hub integration

**Resources created:**
- Neptune cluster with read replica
- 3 Lambda functions in VPC
- API Gateway with multiple endpoints
- SNS topics for compliance, security, and errors
- Security Hub custom product and insights
- S3 bucket for Lambda packages

**Commands:**
```bash
cd deployment-scripts/shared
./deploy-shared-resources.sh
```

**Information needed:**
- Organization Account ID
- VPC ID and private subnet IDs
- Notification email (optional)
- Slack webhook URL (optional)

### 3. Child Accounts Setup

**What gets deployed:**
- AWS Config rules for compliance monitoring
- Cross-account IAM roles
- Local EventBridge rules (if needed)

**Resources created:**
- Config recorder and delivery channel
- 6 Config rules for AMI compliance
- S3 bucket for Config
- IAM roles for cross-account access
- CloudWatch dashboard

**Commands:**
```bash
cd deployment-scripts/child-account
./deploy-child-account-resources.sh
```

**Information needed:**
- Security Tooling Account ID
- Compliance Evaluator Lambda ARN

## Configuration Details

### Organization Account Configuration

#### Service Control Policies
The SCP enforces:
- Only approved AMIs can be used for EC2 instances
- AMI creation requires proper tagging
- Marketplace AMI validation
- Emergency override capabilities

#### EventBridge Rules
Captures events for:
- AMI creation (`CreateImage`, `CopyImage`)
- AMI modification (tagging events)
- AMI deregistration
- EC2 instance launches

### Security Tooling Account Configuration

#### Neptune Database
- Encrypted cluster with read replica
- VPC isolation with security groups
- Audit logging enabled
- Automated backups

#### Lambda Functions

**Event Processor:**
- Processes AMI lifecycle events
- Updates Neptune graph
- Sends compliance notifications

**API Handler:**
- Provides REST API endpoints
- Queries Neptune for lineage data
- Performs security impact assessments

**Compliance Evaluator:**
- Evaluates Config rule compliance
- Creates Security Hub findings
- Generates compliance reports

#### API Gateway Endpoints
- `GET /api/v1/ami/{ami_id}/security-context`
- `GET /api/v1/ami/{ami_id}/lineage`
- `POST /api/v1/security-impact`
- `POST /api/v1/compliance-assessment`
- `POST /api/v1/ami/search`

#### SNS Topics
- **Compliance notifications**: Config rule violations
- **Security alerts**: Security findings and vulnerabilities
- **System errors**: Infrastructure and processing errors

### Child Account Configuration

#### AWS Config Rules
1. **ami-required-tags**: Validates required tags
2. **ami-approval-status**: Checks approval status
3. **ami-security-scan-status**: Validates security scan results
4. **ami-naming-convention**: Enforces naming standards
5. **ami-lineage-verification**: Ensures lineage tracking
6. **instance-ami-compliance**: Validates instance AMI compliance

#### Cross-Account Roles
- Read-only access to EC2 resources
- EventBridge permissions for event forwarding
- Config service permissions

## Post-Deployment Configuration

### 1. Security Hub Setup
- Enable Security Hub in all regions
- Configure custom insights
- Set up finding aggregation

### 2. EventBridge Configuration
- Configure member accounts to forward events to organization bus
- Set up cross-region event replication if needed

### 3. Notification Setup
- Configure email subscriptions
- Set up Slack integration
- Configure PagerDuty or other alerting systems

### 4. API Access
- Configure API Gateway authentication (Cognito)
- Set up API keys and usage plans
- Configure CORS for web applications

## Testing the Deployment

### 1. Create Test AMI
```bash
# Create AMI without proper tags (should trigger compliance violation)
aws ec2 create-image --instance-id i-1234567890abcdef0 --name test-ami-no-tags

# Create AMI with proper tags
aws ec2 create-image --instance-id i-1234567890abcdef0 --name test-ami-compliant
aws ec2 create-tags --resources ami-xxxxxxxxx --tags Key=Creator,Value=TestUser Key=Source,Value=CUSTOM Key=ApprovalStatus,Value=Approved Key=SecurityScan,Value=PASSED Key=Environment,Value=TEST
```

### 2. Test API Endpoints
```bash
# Get security context
curl -X GET "https://your-api-gateway-url/v1/ami/ami-xxxxxxxxx/security-context"

# Perform compliance assessment
curl -X POST "https://your-api-gateway-url/v1/compliance-assessment" \
  -H "Content-Type: application/json" \
  -d '{"rules": ["required_tags", "approval_status"], "scope": "ACCOUNT"}'
```

### 3. Verify Notifications
- Check email for compliance notifications
- Verify Slack messages (if configured)
- Review Security Hub findings

## Troubleshooting

### Common Issues

1. **Neptune connectivity issues**
   - Verify VPC configuration and security groups
   - Check Lambda function VPC settings

2. **Config rule failures**
   - Verify Lambda permissions
   - Check Config service role permissions

3. **EventBridge events not processing**
   - Verify cross-account permissions
   - Check EventBridge rule patterns

4. **API Gateway errors**
   - Check Lambda function logs
   - Verify API Gateway integration settings

### Monitoring and Logs

- **CloudWatch Logs**: Lambda function execution logs
- **CloudWatch Metrics**: API Gateway and Lambda metrics
- **Config Compliance**: Compliance dashboard
- **Security Hub**: Security findings and insights

## Maintenance

### Regular Tasks
1. Review and update compliance rules
2. Monitor Neptune database performance
3. Update Lambda function dependencies
4. Review and rotate API keys
5. Update SCP policies as needed

### Scaling Considerations
- Neptune read replicas for high query load
- Lambda concurrency limits
- API Gateway throttling limits
- EventBridge rule limits

## Security Considerations

### Data Protection
- All data encrypted at rest and in transit
- VPC isolation for sensitive components
- Least privilege IAM permissions

### Access Control
- API Gateway authentication required
- Cross-account roles with minimal permissions
- Regular access reviews

### Monitoring
- CloudTrail logging for all API calls
- Config compliance monitoring
- Security Hub findings tracking
