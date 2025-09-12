# AMI Lineage Governance Framework - Solution Summary

## What We've Built

A comprehensive AMI lineage tracking and governance solution that addresses all requirements from the specifications:

### Core Capabilities
✅ **AMI Relationship Tracking** - Complete lineage across accounts/regions using Neptune graph database  
✅ **Compliance Enforcement** - Service Control Policies and Config rules for policy enforcement  
✅ **Security Impact Assessment** - Blast radius analysis for vulnerabilities using graph traversal  
✅ **AMI Validation & Approval** - Automated approval workflows with Security Hub integration  
✅ **Multi-Account Management** - Organization-wide deployment with centralized governance  
✅ **Audit & Reporting** - Comprehensive logging and compliance reporting  

## Architecture Components

### Organization Account (Management Account)
- **Service Control Policies**: Prevent non-compliant AMI usage
- **EventBridge Rules**: Capture AMI events organization-wide
- **Cross-Account Roles**: Enable secure access from Security Tooling Account

### Security Tooling Account (Central Hub)
- **Neptune Graph Database**: Stores AMI relationships and metadata
- **Lambda Functions**: Process events, handle APIs, evaluate compliance
- **API Gateway**: REST endpoints for lineage queries and security assessments
- **SNS Topics**: Notifications for compliance violations and security alerts
- **Security Hub Integration**: Custom findings and insights

### Child Accounts (Member Accounts)
- **AWS Config Rules**: Continuous compliance monitoring
- **Cross-Account IAM Roles**: Secure access for central processing
- **Local EventBridge Rules**: Forward events to organization bus

## Key Features

### 1. Real-Time Event Processing
- Captures AMI creation, modification, and deregistration events
- Updates graph database in real-time
- Triggers compliance evaluations automatically

### 2. Comprehensive API
```
GET  /api/v1/ami/{ami_id}/security-context     # Get AMI security details
GET  /api/v1/ami/{ami_id}/lineage              # Get AMI lineage tree
POST /api/v1/security-impact                   # Assess security impact
POST /api/v1/compliance-assessment             # Run compliance checks
POST /api/v1/ami/search                        # Search AMIs by criteria
```

### 3. Advanced Compliance Rules
- **Required Tags**: Creator, Source, ApprovalStatus, SecurityScan, Environment
- **Approval Status**: Must be "Approved" for production use
- **Security Scan**: Must pass security scanning
- **Naming Convention**: Enforces organizational standards
- **Lineage Verification**: Ensures proper tracking

### 4. Security Hub Integration
- Custom product for AMI governance findings
- Automated insights for compliance trends
- Custom actions for AMI approval/quarantine
- Integration with existing security workflows

### 5. Multi-Channel Notifications
- Email notifications for compliance violations
- Slack integration for real-time alerts
- Security Hub findings for security teams
- CloudWatch alarms for system health

## Deployment Process

### Quick Start
1. **Organization Account**: `./deploy-organization-resources.sh`
2. **Security Tooling Account**: `./deploy-shared-resources.sh`  
3. **Child Accounts**: `./deploy-child-account-resources.sh`

### What Each Script Does

#### Organization Account Script
- Creates and deploys Service Control Policy
- Sets up organization-wide EventBridge rules
- Creates cross-account trust relationships
- **Manual step**: Attach SCP to appropriate OUs

#### Security Tooling Account Script
- Deploys Neptune database cluster in VPC
- Packages and deploys Lambda functions
- Creates API Gateway with authentication
- Sets up SNS topics and subscriptions
- Configures Security Hub integration

#### Child Account Script
- Deploys AWS Config rules for compliance
- Creates cross-account IAM roles
- Sets up Config delivery channel and S3 bucket
- Creates CloudWatch dashboard

## Security Features

### Data Protection
- Neptune encryption at rest and in transit
- VPC isolation for database access
- KMS encryption for SNS topics
- S3 bucket encryption for Config data

### Access Control
- Least privilege IAM roles throughout
- Cross-account access with external IDs
- API Gateway authentication (optional Cognito)
- Service Control Policies for preventive controls

### Monitoring & Audit
- Complete CloudTrail integration
- Config compliance tracking
- Security Hub findings management
- CloudWatch dashboards and alarms

## Usage Examples

### Check AMI Compliance
```bash
aws lambda invoke \
  --function-name ami-compliance-evaluator \
  --payload '{"resource_id": "ami-1234567890abcdef0", "resource_type": "AWS::EC2::Image"}' \
  response.json
```

### Get Security Context
```bash
curl -X GET "https://api-gateway-url/v1/ami/ami-1234567890abcdef0/security-context?include_compliance=true"
```

### Assess Security Impact
```bash
curl -X POST "https://api-gateway-url/v1/security-impact" \
  -H "Content-Type: application/json" \
  -d '{
    "ami_id": "ami-1234567890abcdef0",
    "finding_type": "CVE",
    "finding_id": "CVE-2024-XXXX",
    "severity": "CRITICAL"
  }'
```

## Monitoring & Dashboards

### CloudWatch Dashboards Created
- **API Gateway Metrics**: Request counts, latency, errors
- **Config Compliance**: Rule compliance status
- **SNS Metrics**: Message delivery status
- **Security Hub**: Finding trends and insights

### Key Metrics to Monitor
- AMI compliance percentage
- API response times
- Neptune query performance
- Event processing latency
- Notification delivery success

## Customization Points

### Compliance Rules
- Modify required tags in Config rules
- Adjust naming convention patterns
- Add custom compliance checks

### Notifications
- Add additional SNS subscriptions
- Integrate with PagerDuty or other systems
- Customize message formats

### API Security
- Add Cognito User Pool authentication
- Implement API key management
- Add rate limiting and throttling

## Cost Considerations

### Primary Cost Drivers
- **Neptune**: Database cluster and instances (~$200-500/month)
- **Lambda**: Function executions (usage-based)
- **API Gateway**: API calls (usage-based)
- **Config**: Configuration items and rule evaluations
- **Data Transfer**: Cross-AZ and cross-region transfers

### Cost Optimization
- Use Neptune read replicas only if needed
- Implement Lambda reserved concurrency
- Use API Gateway caching
- Optimize Config rule evaluation frequency

## Next Steps After Deployment

1. **Test the Solution**
   - Create test AMIs with and without proper tags
   - Verify compliance notifications
   - Test API endpoints

2. **Configure Security Hub**
   - Enable in all required regions
   - Set up finding aggregation
   - Configure custom actions

3. **Set Up Monitoring**
   - Configure CloudWatch alarms
   - Set up notification channels
   - Create operational dashboards

4. **Train Teams**
   - Document API usage for developers
   - Train security teams on Security Hub integration
   - Create runbooks for common operations

## Support and Troubleshooting

### Common Issues
- **Neptune Connectivity**: Check VPC configuration and security groups
- **Config Rule Failures**: Verify Lambda permissions and Config service role
- **API Errors**: Check Lambda logs and API Gateway integration

### Log Locations
- Lambda Functions: `/aws/lambda/function-name`
- API Gateway: `/aws/apigateway/api-id`
- Config: AWS Config console
- Security Hub: Security Hub console

This solution provides enterprise-grade AMI governance with comprehensive tracking, compliance enforcement, and security integration across your entire AWS organization.
