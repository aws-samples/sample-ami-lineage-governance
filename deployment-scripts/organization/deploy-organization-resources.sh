#!/bin/bash

# AMI Lineage Governance - Organization Account Deployment Script
# This script deploys resources to the AWS Organizations management account

set -e

# Configuration
ORGANIZATION_ACCOUNT_ID=""
SECURITY_TOOLING_ACCOUNT_ID=""
REGION="us-east-1"
STACK_PREFIX="ami-lineage-org"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed. Please install it first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured or invalid."
        exit 1
    fi
    
    # Get current account ID
    CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    print_status "Current AWS Account: $CURRENT_ACCOUNT"
    
    # Check if this is the organization management account
    if ! aws organizations describe-organization &> /dev/null; then
        print_error "This account is not the organization management account or Organizations is not enabled."
        exit 1
    fi
    
    ORGANIZATION_ACCOUNT_ID=$CURRENT_ACCOUNT
    print_status "Organization management account confirmed: $ORGANIZATION_ACCOUNT_ID"
}

# Function to get user input
get_user_input() {
    print_status "Getting deployment configuration..."
    
    # Get Security Tooling Account ID
    if [ -z "$SECURITY_TOOLING_ACCOUNT_ID" ]; then
        read -p "Enter Security Tooling Account ID: " SECURITY_TOOLING_ACCOUNT_ID
    fi
    
    # Validate account ID format
    if [[ ! $SECURITY_TOOLING_ACCOUNT_ID =~ ^[0-9]{12}$ ]]; then
        print_error "Invalid account ID format. Must be 12 digits."
        exit 1
    fi
    
    # Get deployment region
    read -p "Enter deployment region (default: us-east-1): " input_region
    if [ ! -z "$input_region" ]; then
        REGION=$input_region
    fi
    
    print_status "Configuration:"
    print_status "  Organization Account: $ORGANIZATION_ACCOUNT_ID"
    print_status "  Security Tooling Account: $SECURITY_TOOLING_ACCOUNT_ID"
    print_status "  Region: $REGION"
    
    read -p "Continue with deployment? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_status "Deployment cancelled."
        exit 0
    fi
}

# Function to deploy Service Control Policies
deploy_scps() {
    print_status "Deploying Service Control Policies..."
    
    # Create SCP for AMI governance
    SCP_NAME="AMI-Lineage-Governance-Policy"
    SCP_DESCRIPTION="Service Control Policy for AMI lineage governance"
    
    # Check if SCP already exists
    existing_scp=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query "Policies[?Name=='$SCP_NAME'].Id" --output text 2>/dev/null || echo "")
    
    # Try basic SCP first for testing
    SCP_FILE="../../organization-account/scps/ami-governance-scp-basic.json"
    
    if [ ! -z "$existing_scp" ]; then
        print_warning "SCP '$SCP_NAME' already exists. Updating..."
        if aws organizations update-policy \
            --policy-id "$existing_scp" \
            --policy-document file://"$SCP_FILE" \
            --description "$SCP_DESCRIPTION" 2>/dev/null; then
            SCP_ID=$existing_scp
            print_status "SCP updated successfully"
        else
            print_error "Failed to update SCP. Trying to create new one..."
            existing_scp=""
        fi
    fi
    
    if [ -z "$existing_scp" ]; then
        print_status "Creating new SCP '$SCP_NAME'..."
        if SCP_ID=$(aws organizations create-policy \
            --name "$SCP_NAME" \
            --description "$SCP_DESCRIPTION" \
            --type SERVICE_CONTROL_POLICY \
            --content file://"$SCP_FILE" \
            --query 'Policy.PolicySummary.Id' \
            --output text 2>/dev/null); then
            print_status "SCP created successfully"
        else
            print_error "Failed to create SCP. Continuing without SCP..."
            print_warning "You can create the SCP manually later using the JSON files in organization-account/scps/"
            SCP_ID="FAILED"
        fi
    fi
    
    if [ "$SCP_ID" != "FAILED" ]; then
        print_status "SCP ID: $SCP_ID"
        print_warning "SCP created but not attached. Please attach to appropriate OUs manually."
        print_status "SCP ID to attach: $SCP_ID"
    fi
}

# Function to deploy EventBridge rules
deploy_eventbridge_rules() {
    print_status "Deploying organization-wide EventBridge rules..."
    
    STACK_NAME="${STACK_PREFIX}-eventbridge"
    
    # Deploy CloudFormation stack
    aws cloudformation deploy \
        --template-file ../../organization-account/eventbridge/organization-eventbridge-rules.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            SecurityToolingAccountId="$SECURITY_TOOLING_ACCOUNT_ID" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    # Get outputs
    EVENT_BUS_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`EventBusArn`].OutputValue' \
        --output text \
        --region "$REGION")
    
    print_status "EventBridge rules deployed successfully"
    print_status "Event Bus ARN: $EVENT_BUS_ARN"
}

# Function to create cross-account trust policies
create_cross_account_policies() {
    print_status "Creating cross-account trust policies..."
    
    # Create trust policy for Security Tooling Account
    TRUST_POLICY_NAME="AMI-Lineage-CrossAccount-Trust"
    
    # Create the trust policy document
    cat > /tmp/trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${SECURITY_TOOLING_ACCOUNT_ID}:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "ami-lineage-governance"
                }
            }
        }
    ]
}
EOF
    
    # Create IAM role for cross-account access
    ROLE_NAME="AMI-Lineage-CrossAccount-Role"
    
    # Check if role exists
    if aws iam get-role --role-name "$ROLE_NAME" &> /dev/null; then
        print_warning "Role '$ROLE_NAME' already exists. Updating trust policy..."
        aws iam update-assume-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-document file:///tmp/trust-policy.json
    else
        print_status "Creating cross-account role '$ROLE_NAME'..."
        aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document file:///tmp/trust-policy.json \
            --description "Cross-account role for AMI lineage governance"
        
        # Attach necessary policies
        aws iam attach-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess"
        
        # Create custom policy for EventBridge
        cat > /tmp/eventbridge-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "events:PutEvents",
                "events:ListRules",
                "events:DescribeRule"
            ],
            "Resource": "*"
        }
    ]
}
EOF
        
        aws iam put-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-name "EventBridgeAccess" \
            --policy-document file:///tmp/eventbridge-policy.json
    fi
    
    CROSS_ACCOUNT_ROLE_ARN="arn:aws:iam::${ORGANIZATION_ACCOUNT_ID}:role/${ROLE_NAME}"
    print_status "Cross-account role ARN: $CROSS_ACCOUNT_ROLE_ARN"
    
    # Clean up temporary files
    rm -f /tmp/trust-policy.json /tmp/eventbridge-policy.json
}

# Function to validate deployment
validate_deployment() {
    print_status "Validating deployment..."
    
    # Check if EventBridge stack exists and is in good state
    STACK_NAME="${STACK_PREFIX}-eventbridge"
    STACK_STATUS=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].StackStatus' \
        --output text \
        --region "$REGION" 2>/dev/null || echo "NOT_FOUND")
    
    if [ "$STACK_STATUS" = "CREATE_COMPLETE" ] || [ "$STACK_STATUS" = "UPDATE_COMPLETE" ]; then
        print_status "EventBridge stack is healthy: $STACK_STATUS"
    else
        print_error "EventBridge stack is not healthy: $STACK_STATUS"
        return 1
    fi
    
    # Check if cross-account role exists
    if aws iam get-role --role-name "AMI-Lineage-CrossAccount-Role" &> /dev/null; then
        print_status "Cross-account role exists and is accessible"
    else
        print_error "Cross-account role not found or not accessible"
        return 1
    fi
    
    print_status "Deployment validation completed successfully"
}

# Function to display next steps
display_next_steps() {
    print_status "Organization account deployment completed successfully!"
    echo
    print_status "Next Steps:"
    echo "1. Deploy shared resources in Security Tooling Account ($SECURITY_TOOLING_ACCOUNT_ID)"
    echo "2. Deploy child account resources in member accounts"
    echo "3. Attach the SCP (ID: $SCP_ID) to appropriate OUs"
    echo "4. Configure EventBridge rules in member accounts to forward events"
    echo
    print_status "Important Information:"
    echo "- Event Bus ARN: $EVENT_BUS_ARN"
    echo "- Cross-account Role ARN: $CROSS_ACCOUNT_ROLE_ARN"
    echo "- SCP ID: $SCP_ID"
    echo
    print_warning "Remember to save these values for use in subsequent deployments!"
}

# Main execution
main() {
    print_status "Starting AMI Lineage Governance - Organization Account Deployment"
    echo
    
    check_prerequisites
    get_user_input
    
    print_status "Starting deployment..."
    
    deploy_scps
    deploy_eventbridge_rules
    create_cross_account_policies
    validate_deployment
    
    display_next_steps
    
    print_status "Deployment completed successfully!"
}

# Run main function
main "$@"
