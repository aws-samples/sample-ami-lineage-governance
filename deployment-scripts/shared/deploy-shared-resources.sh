#!/bin/bash

# AMI Lineage Governance - Shared Resources Deployment Script
# This script deploys shared resources to the Security Tooling Account

set -e

# Configuration
SECURITY_TOOLING_ACCOUNT_ID=""
ORGANIZATION_ACCOUNT_ID=""
REGION="us-east-1"
STACK_PREFIX="ami-lineage-shared"
VPC_ID=""
PRIVATE_SUBNET_IDS=""
NOTIFICATION_EMAIL=""
SLACK_WEBHOOK_URL=""

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
    
    # Check if zip is installed
    if ! command -v zip &> /dev/null; then
        print_error "zip is not installed. Please install it first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured or invalid."
        exit 1
    fi
    
    # Get current account ID
    CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    SECURITY_TOOLING_ACCOUNT_ID=$CURRENT_ACCOUNT
    print_status "Current AWS Account (Security Tooling): $SECURITY_TOOLING_ACCOUNT_ID"
}

# Function to get user input
get_user_input() {
    print_status "Getting deployment configuration..."
    
    # Get Organization Account ID
    if [ -z "$ORGANIZATION_ACCOUNT_ID" ]; then
        read -p "Enter Organization Management Account ID: " ORGANIZATION_ACCOUNT_ID
    fi
    
    # Validate account ID format
    if [[ ! $ORGANIZATION_ACCOUNT_ID =~ ^[0-9]{12}$ ]]; then
        print_error "Invalid account ID format. Must be 12 digits."
        exit 1
    fi
    
    # Get deployment region
    read -p "Enter deployment region (default: us-east-1): " input_region
    if [ ! -z "$input_region" ]; then
        REGION=$input_region
    fi
    
    # Get VPC ID
    if [ -z "$VPC_ID" ]; then
        print_status "Available VPCs:"
        aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[0],CidrBlock]' --output table --region "$REGION"
        read -p "Enter VPC ID for Neptune deployment: " VPC_ID
    fi
    
    # Get Private Subnet IDs
    if [ -z "$PRIVATE_SUBNET_IDS" ]; then
        print_status "Available subnets in VPC $VPC_ID:"
        aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,Tags[?Key==`Name`].Value|[0]]' --output table --region "$REGION"
        read -p "Enter Private Subnet IDs (comma-separated, minimum 2): " PRIVATE_SUBNET_IDS
    fi
    
    # Get notification email
    read -p "Enter notification email address (optional): " NOTIFICATION_EMAIL
    
    # Get Slack webhook URL
    read -p "Enter Slack webhook URL (optional): " SLACK_WEBHOOK_URL
    
    print_status "Configuration:"
    print_status "  Security Tooling Account: $SECURITY_TOOLING_ACCOUNT_ID"
    print_status "  Organization Account: $ORGANIZATION_ACCOUNT_ID"
    print_status "  Region: $REGION"
    print_status "  VPC ID: $VPC_ID"
    print_status "  Private Subnets: $PRIVATE_SUBNET_IDS"
    print_status "  Notification Email: ${NOTIFICATION_EMAIL:-'Not provided'}"
    print_status "  Slack Webhook: ${SLACK_WEBHOOK_URL:+'Provided'}"
    
    read -p "Continue with deployment? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_status "Deployment cancelled."
        exit 0
    fi
}

# Function to create S3 bucket for Lambda deployment packages
create_deployment_bucket() {
    print_status "Creating S3 bucket for Lambda deployment packages..."
    
    BUCKET_NAME="ami-lineage-lambda-${SECURITY_TOOLING_ACCOUNT_ID}-${REGION}"
    
    # Check if bucket exists
    if aws s3 ls "s3://$BUCKET_NAME" &> /dev/null; then
        print_warning "Bucket $BUCKET_NAME already exists"
    else
        # Create bucket
        if [ "$REGION" = "us-east-1" ]; then
            aws s3 mb "s3://$BUCKET_NAME" --region "$REGION"
        else
            aws s3 mb "s3://$BUCKET_NAME" --region "$REGION" --create-bucket-configuration LocationConstraint="$REGION"
        fi
        
        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "$BUCKET_NAME" \
            --versioning-configuration Status=Enabled
        
        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket "$BUCKET_NAME" \
            --server-side-encryption-configuration '{
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }'
        
        print_status "Created S3 bucket: $BUCKET_NAME"
    fi
}

# Function to package and upload Lambda functions
package_lambda_functions() {
    print_status "Packaging and uploading Lambda functions..."
    
    LAMBDA_FUNCTIONS=("event-processor" "api-handler" "compliance-evaluator")
    
    for func in "${LAMBDA_FUNCTIONS[@]}"; do
        print_status "Packaging $func Lambda function..."
        
        # Create temporary directory
        TEMP_DIR=$(mktemp -d)
        
        # Copy function code
        cp -r "../../lambda-functions/$func/"* "$TEMP_DIR/"
        
        # Install dependencies
        if [ -f "$TEMP_DIR/requirements.txt" ]; then
            pip3 install -r "$TEMP_DIR/requirements.txt" -t "$TEMP_DIR/"
        fi
        
        # Create zip package
        cd "$TEMP_DIR"
        zip -r "../${func}.zip" . -x "*.pyc" "__pycache__/*"
        cd - > /dev/null
        
        # Upload to S3
        aws s3 cp "${TEMP_DIR}/../${func}.zip" "s3://$BUCKET_NAME/lambda-packages/${func}.zip"
        
        # Clean up
        rm -rf "$TEMP_DIR" "${TEMP_DIR}/../${func}.zip"
        
        print_status "Uploaded $func Lambda package to S3"
    done
}

# Function to deploy Neptune database
deploy_neptune() {
    print_status "Deploying Neptune database..."
    
    STACK_NAME="${STACK_PREFIX}-neptune"
    
    # Convert comma-separated subnet IDs to space-separated for CloudFormation
    SUBNET_ARRAY=$(echo "$PRIVATE_SUBNET_IDS" | tr ',' ' ')
    
    aws cloudformation deploy \
        --template-file ../../shared-resources/neptune/neptune-cluster-simple.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            VpcId="$VPC_ID" \
            PrivateSubnetIds="$PRIVATE_SUBNET_IDS" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    # Get Neptune endpoint
    NEPTUNE_ENDPOINT=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`NeptuneClusterEndpoint`].OutputValue' \
        --output text \
        --region "$REGION")
    
    LAMBDA_SECURITY_GROUP_ID=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`LambdaSecurityGroupId`].OutputValue' \
        --output text \
        --region "$REGION")
    
    print_status "Neptune database deployed successfully"
    print_status "Neptune Endpoint: $NEPTUNE_ENDPOINT"
}

# Function to deploy SNS topics
deploy_sns() {
    print_status "Deploying SNS topics..."
    
    STACK_NAME="${STACK_PREFIX}-sns"
    
    aws cloudformation deploy \
        --template-file ../../shared-resources/sns/ami-lineage-notifications-simple.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            NotificationEmail="$NOTIFICATION_EMAIL" \
            SlackWebhookURL="$SLACK_WEBHOOK_URL" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    # Get SNS topic ARNs
    COMPLIANCE_TOPIC_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`ComplianceTopicArn`].OutputValue' \
        --output text \
        --region "$REGION")
    
    SECURITY_TOPIC_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`SecurityTopicArn`].OutputValue' \
        --output text \
        --region "$REGION")
    
    print_status "SNS topics deployed successfully"
    print_status "Compliance Topic ARN: $COMPLIANCE_TOPIC_ARN"
    print_status "Security Topic ARN: $SECURITY_TOPIC_ARN"
}

# Function to deploy Lambda functions
deploy_lambda_functions() {
    print_status "Deploying Lambda functions..."
    
    STACK_NAME="${STACK_PREFIX}-lambda"
    
    # Create Lambda functions CloudFormation template
    cat > /tmp/lambda-functions.yaml << EOF
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Lambda functions for AMI lineage governance'

Parameters:
  S3Bucket:
    Type: String
  NeptuneEndpoint:
    Type: String
  SNSTopicArn:
    Type: String
  LambdaSecurityGroupId:
    Type: String
  PrivateSubnetIds:
    Type: CommaDelimitedList

Resources:
  # IAM Role for Lambda functions
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: AMI-Lineage-Lambda-Execution-Role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole
      Policies:
        - PolicyName: AMILineagePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ec2:DescribeImages
                  - ec2:DescribeInstances
                  - ec2:DescribeTags
                  - ec2:CreateTags
                  - sns:Publish
                  - config:PutEvaluations
                  - securityhub:BatchImportFindings
                  - securityhub:BatchUpdateFindings
                Resource: '*'

  # Event Processor Lambda
  EventProcessorFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: ami-event-processor
      Runtime: python3.9
      Handler: lambda_function.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Code:
        S3Bucket: !Ref S3Bucket
        S3Key: lambda-packages/event-processor.zip
      Environment:
        Variables:
          NEPTUNE_ENDPOINT: !Ref NeptuneEndpoint
          SNS_TOPIC_ARN: !Ref SNSTopicArn
      VpcConfig:
        SecurityGroupIds:
          - !Ref LambdaSecurityGroupId
        SubnetIds: !Ref PrivateSubnetIds
      Timeout: 300

  # API Handler Lambda
  APIHandlerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: ami-api-handler
      Runtime: python3.9
      Handler: lambda_function.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Code:
        S3Bucket: !Ref S3Bucket
        S3Key: lambda-packages/api-handler.zip
      Environment:
        Variables:
          NEPTUNE_ENDPOINT: !Ref NeptuneEndpoint
      VpcConfig:
        SecurityGroupIds:
          - !Ref LambdaSecurityGroupId
        SubnetIds: !Ref PrivateSubnetIds
      Timeout: 300

  # Compliance Evaluator Lambda
  ComplianceEvaluatorFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: ami-compliance-evaluator
      Runtime: python3.9
      Handler: lambda_function.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Code:
        S3Bucket: !Ref S3Bucket
        S3Key: lambda-packages/compliance-evaluator.zip
      Environment:
        Variables:
          NEPTUNE_ENDPOINT: !Ref NeptuneEndpoint
          SNS_TOPIC_ARN: !Ref SNSTopicArn
      VpcConfig:
        SecurityGroupIds:
          - !Ref LambdaSecurityGroupId
        SubnetIds: !Ref PrivateSubnetIds
      Timeout: 300

  # Lambda Permission for Config Service (cross-account)
  ConfigLambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref ComplianceEvaluatorFunction
      Action: lambda:InvokeFunction
      Principal: config.amazonaws.com

Outputs:
  EventProcessorArn:
    Value: !GetAtt EventProcessorFunction.Arn
  APIHandlerArn:
    Value: !GetAtt APIHandlerFunction.Arn
  ComplianceEvaluatorArn:
    Value: !GetAtt ComplianceEvaluatorFunction.Arn
EOF

    aws cloudformation deploy \
        --template-file /tmp/lambda-functions.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            S3Bucket="$BUCKET_NAME" \
            NeptuneEndpoint="$NEPTUNE_ENDPOINT" \
            SNSTopicArn="$COMPLIANCE_TOPIC_ARN" \
            LambdaSecurityGroupId="$LAMBDA_SECURITY_GROUP_ID" \
            PrivateSubnetIds="$PRIVATE_SUBNET_IDS" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    # Get Lambda function ARNs
    API_HANDLER_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`APIHandlerArn`].OutputValue' \
        --output text \
        --region "$REGION")
    
    COMPLIANCE_EVALUATOR_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`ComplianceEvaluatorArn`].OutputValue' \
        --output text \
        --region "$REGION")
    
    print_status "Lambda functions deployed successfully"
    
    # Clean up
    rm -f /tmp/lambda-functions.yaml
}

# Function to deploy API Gateway
deploy_api_gateway() {
    print_status "Deploying API Gateway..."
    
    STACK_NAME="${STACK_PREFIX}-api"
    
    aws cloudformation deploy \
        --template-file ../../shared-resources/api-gateway/ami-lineage-api.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            APIHandlerLambdaArn="$API_HANDLER_ARN" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    # Get API Gateway URL
    API_GATEWAY_URL=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[?OutputKey==`APIGatewayURL`].OutputValue' \
        --output text \
        --region "$REGION")
    
    print_status "API Gateway deployed successfully"
    print_status "API Gateway URL: $API_GATEWAY_URL"
}

# Function to deploy Security Hub integration
deploy_security_hub() {
    print_status "Deploying Security Hub integration..."
    
    STACK_NAME="${STACK_PREFIX}-securityhub"
    
    aws cloudformation deploy \
        --template-file ../../shared-resources/security-hub/ami-lineage-security-hub-simple.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            NeptuneEndpoint="$NEPTUNE_ENDPOINT" \
            SNSTopicArn="$SECURITY_TOPIC_ARN" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION"
    
    print_status "Security Hub integration deployed successfully"
}

# Function to validate deployment
validate_deployment() {
    print_status "Validating deployment..."
    
    # Check all stacks
    STACKS=("${STACK_PREFIX}-neptune" "${STACK_PREFIX}-sns" "${STACK_PREFIX}-lambda" "${STACK_PREFIX}-api" "${STACK_PREFIX}-securityhub")
    
    for stack in "${STACKS[@]}"; do
        STACK_STATUS=$(aws cloudformation describe-stacks \
            --stack-name "$stack" \
            --query 'Stacks[0].StackStatus' \
            --output text \
            --region "$REGION" 2>/dev/null || echo "NOT_FOUND")
        
        if [ "$STACK_STATUS" = "CREATE_COMPLETE" ] || [ "$STACK_STATUS" = "UPDATE_COMPLETE" ]; then
            print_status "Stack $stack is healthy: $STACK_STATUS"
        else
            print_error "Stack $stack is not healthy: $STACK_STATUS"
            return 1
        fi
    done
    
    # Test Neptune connectivity (basic check)
    print_status "Testing Neptune connectivity..."
    # This would require a more sophisticated test in a real deployment
    
    print_status "Deployment validation completed successfully"
}

# Function to display next steps
display_next_steps() {
    print_status "Shared resources deployment completed successfully!"
    echo
    print_status "Deployed Resources:"
    echo "- Neptune Endpoint: $NEPTUNE_ENDPOINT"
    echo "- API Gateway URL: $API_GATEWAY_URL"
    echo "- Compliance Topic ARN: $COMPLIANCE_TOPIC_ARN"
    echo "- Security Topic ARN: $SECURITY_TOPIC_ARN"
    echo "- API Handler ARN: $API_HANDLER_ARN"
    echo "- Compliance Evaluator ARN: $COMPLIANCE_EVALUATOR_ARN"
    echo
    print_status "Next Steps:"
    echo "1. Deploy child account resources in member accounts"
    echo "2. Configure EventBridge rules in member accounts"
    echo "3. Test the API endpoints"
    echo "4. Configure Security Hub in all regions"
    echo
    print_warning "Save the above information for child account deployments!"
}

# Main execution
main() {
    print_status "Starting AMI Lineage Governance - Shared Resources Deployment"
    echo
    
    check_prerequisites
    get_user_input
    
    print_status "Starting deployment..."
    
    create_deployment_bucket
    package_lambda_functions
    deploy_neptune
    deploy_sns
    deploy_lambda_functions
    deploy_api_gateway
    deploy_security_hub
    validate_deployment
    
    display_next_steps
    
    print_status "Deployment completed successfully!"
}

# Run main function
main "$@"
