#!/bin/bash

# AMI Lineage Governance - Child Account Deployment Script
# This script deploys resources to AWS member accounts

set -euo pipefail

# Configuration
SECURITY_TOOLING_ACCOUNT_ID=""
COMPLIANCE_EVALUATOR_ARN=""
REGION="us-east-1"
STACK_PREFIX="ami-lineage-child"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
    
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed."
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured."
        exit 1
    fi
    
    CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    print_status "Current AWS Account: $CURRENT_ACCOUNT"
}

# Function to get user input
get_user_input() {
    print_status "Getting deployment configuration..."
    
    read -p "Enter Security Tooling Account ID: " SECURITY_TOOLING_ACCOUNT_ID
    read -p "Enter deployment region (default: us-east-1): " input_region
    
    if [ ! -z "$input_region" ]; then
        REGION=$input_region
    fi
    
    print_status "Configuration confirmed"
}

# Function to deploy Config rules
deploy_config_rules() {
    print_status "Deploying AWS Config rules..."
    
    STACK_NAME="${STACK_PREFIX}-config"
    
    aws cloudformation deploy \
        --template-file ../../child-accounts/config-rules/ami-compliance-config-rules-simple.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            SecurityToolingAccountId="$SECURITY_TOOLING_ACCOUNT_ID" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    print_status "Config rules deployed successfully"
}

# Function to create IAM roles
create_iam_roles() {
    print_status "Creating cross-account IAM roles..."
    
    # Create trust policy
    cat > /tmp/trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${SECURITY_TOOLING_ACCOUNT_ID}:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
    
    # Create role
    ROLE_NAME="AMI-Lineage-Child-Account-Role"
    
    if aws iam get-role --role-name "$ROLE_NAME" &> /dev/null; then
        print_warning "Role already exists"
    else
        aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document file:///tmp/trust-policy.json
        
        aws iam attach-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess"
    fi
    
    rm -f /tmp/trust-policy.json
    print_status "IAM roles created successfully"
}

# Main execution
main() {
    print_status "Starting Child Account Deployment"
    
    check_prerequisites
    get_user_input
    deploy_config_rules
    create_iam_roles
    
    print_status "Child account deployment completed!"
}

main "$@"
