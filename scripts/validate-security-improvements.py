#!/usr/bin/env python3
"""
Security Configuration Validation Script for AMI Lineage CloudFormation Templates

This script validates that the CloudFormation templates follow security best practices:
1. Lambda functions have DLQ and concurrency limits configured
2. IAM policies follow least privilege principles  
3. Security group egress rules are explicit
4. Encryption is enabled where appropriate
"""

import yaml
import json
import sys
import os
from pathlib import Path

def load_yaml_template(file_path):
    """Load and parse a YAML CloudFormation template."""
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None

def validate_lambda_security(template, template_name):
    """Validate Lambda function security configurations."""
    issues = []
    resources = template.get('Resources', {})
    
    lambda_functions = {k: v for k, v in resources.items() 
                       if v.get('Type') == 'AWS::Lambda::Function'}
    
    for func_name, func_config in lambda_functions.items():
        properties = func_config.get('Properties', {})
        
        # Check for Dead Letter Queue configuration
        if 'DeadLetterConfig' not in properties:
            issues.append(f"{template_name}: Lambda function {func_name} missing DeadLetterConfig")
        
        # Check for concurrency limits
        if 'ReservedConcurrencyLimit' not in properties:
            issues.append(f"{template_name}: Lambda function {func_name} missing ReservedConcurrencyLimit")
        
        # Check for VPC configuration (if applicable)
        if template_name.endswith('lambda-functions-secure.yaml'):
            if 'VpcConfig' not in properties:
                issues.append(f"{template_name}: Lambda function {func_name} missing VpcConfig")
        
        # Check for timeout limits
        timeout = properties.get('Timeout', 0)
        if timeout > 300:
            issues.append(f"{template_name}: Lambda function {func_name} has excessive timeout: {timeout}s")
    
    return issues

def validate_iam_policies(template, template_name):
    """Validate IAM policies follow least privilege principles."""
    issues = []
    resources = template.get('Resources', {})
    
    iam_roles = {k: v for k, v in resources.items() 
                 if v.get('Type') == 'AWS::IAM::Role'}
    
    for role_name, role_config in iam_roles.items():
        properties = role_config.get('Properties', {})
        
        # Check assume role policy has conditions
        assume_policy = properties.get('AssumeRolePolicyDocument', {})
        statements = assume_policy.get('Statement', [])
        
        for statement in statements:
            if 'Condition' not in statement:
                issues.append(f"{template_name}: Role {role_name} assume role policy missing conditions")
        
        # Check inline policies
        policies = properties.get('Policies', [])
        
        for policy in policies:
            policy_doc = policy.get('PolicyDocument', {})
            policy_statements = policy_doc.get('Statement', [])
            
            for statement in policy_statements:
                # Check for overly broad resource permissions
                resources_list = statement.get('Resource', [])
                if isinstance(resources_list, str):
                    resources_list = [resources_list]
                
                for resource in resources_list:
                    if resource == '*' and statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check if wildcard resource has appropriate conditions
                        if 'Condition' not in statement:
                            # Allow certain safe actions without conditions
                            safe_wildcard_actions = [
                                'ec2:Describe*',
                                'autoscaling:Describe*',
                                'xray:PutTraceSegments',
                                'xray:PutTelemetryRecords'
                            ]
                            
                            unsafe_actions = []
                            for action in actions:
                                if not any(action.startswith(safe.replace('*', '')) 
                                         for safe in safe_wildcard_actions):
                                    unsafe_actions.append(action)
                            
                            if unsafe_actions:
                                issues.append(f"{template_name}: Role {role_name} has overly broad permissions for actions {unsafe_actions} without conditions")
    
    return issues

def validate_security_groups(template, template_name):
    """Validate security group configurations."""
    issues = []
    resources = template.get('Resources', {})
    
    security_groups = {k: v for k, v in resources.items() 
                      if v.get('Type') == 'AWS::EC2::SecurityGroup'}
    
    for sg_name, sg_config in security_groups.items():
        properties = sg_config.get('Properties', {})
        egress_rules = properties.get('SecurityGroupEgress', [])
        
        for rule in egress_rules:
            # Check for overly permissive egress rules
            if rule.get('CidrIp') == '0.0.0.0/0':
                port = rule.get('FromPort')
                description = rule.get('Description', '')
                
                # Only allow 0.0.0.0/0 for HTTPS with proper description
                if port != 443 or 'AWS API' not in description:
                    issues.append(f"{template_name}: Security group {sg_name} has overly permissive egress rule to 0.0.0.0/0")
            
            # Check for missing descriptions
            if not rule.get('Description'):
                issues.append(f"{template_name}: Security group {sg_name} has egress rule without description")
    
    return issues

def validate_encryption(template, template_name):
    """Validate encryption configurations."""
    issues = []
    resources = template.get('Resources', {})
    
    # Check SQS queues have encryption
    sqs_queues = {k: v for k, v in resources.items() 
                  if v.get('Type') == 'AWS::SQS::Queue'}
    
    for queue_name, queue_config in sqs_queues.items():
        properties = queue_config.get('Properties', {})
        if 'KmsMasterKeyId' not in properties:
            issues.append(f"{template_name}: SQS queue {queue_name} missing KMS encryption")
    
    # Check Neptune clusters have encryption
    neptune_clusters = {k: v for k, v in resources.items() 
                       if v.get('Type') == 'AWS::Neptune::DBCluster'}
    
    for cluster_name, cluster_config in neptune_clusters.items():
        properties = cluster_config.get('Properties', {})
        if not properties.get('StorageEncrypted'):
            issues.append(f"{template_name}: Neptune cluster {cluster_name} missing storage encryption")
    
    # Check S3 buckets have encryption
    s3_buckets = {k: v for k, v in resources.items() 
                  if v.get('Type') == 'AWS::S3::Bucket'}
    
    for bucket_name, bucket_config in s3_buckets.items():
        properties = bucket_config.get('Properties', {})
        if 'BucketEncryption' not in properties:
            issues.append(f"{template_name}: S3 bucket {bucket_name} missing encryption configuration")
    
    # Check CloudWatch Log Groups have encryption
    log_groups = {k: v for k, v in resources.items() 
                  if v.get('Type') == 'AWS::Logs::LogGroup'}
    
    for log_group_name, log_group_config in log_groups.items():
        properties = log_group_config.get('Properties', {})
        if 'KmsKeyId' not in properties:
            issues.append(f"{template_name}: CloudWatch Log Group {log_group_name} missing KMS encryption")
    
    return issues

def validate_resource_policies(template, template_name):
    """Validate resource policies are appropriately restrictive."""
    issues = []
    resources = template.get('Resources', {})
    
    # Check API Gateway resource policies
    api_gateways = {k: v for k, v in resources.items() 
                    if v.get('Type') == 'AWS::ApiGateway::RestApi'}
    
    for api_name, api_config in api_gateways.items():
        properties = api_config.get('Properties', {})
        policy = properties.get('Policy', {})
        
        if policy:
            statements = policy.get('Statement', [])
            for statement in statements:
                # Check for secure transport enforcement
                if statement.get('Effect') == 'Allow':
                    # Should have a corresponding Deny statement for non-secure transport
                    secure_transport_enforced = any(
                        s.get('Effect') == 'Deny' and 
                        s.get('Condition', {}).get('Bool', {}).get('aws:SecureTransport') == 'false'
                        for s in statements
                    )
                    if not secure_transport_enforced:
                        issues.append(f"{template_name}: API Gateway {api_name} missing secure transport enforcement")
    
    return issues

def main():
    """Main validation function."""
    template_files = [
        'final_solution/shared-resources/neptune/neptune-cluster.yaml',
        'final_solution/shared-resources/api-gateway/ami-lineage-api.yaml',
        'final_solution/shared-resources/sns/ami-lineage-notifications.yaml',
        'final_solution/child-accounts/config-rules/ami-compliance-config-rules.yaml',
        'final_solution/lambda-functions/lambda-functions-secure.yaml'
    ]
    
    all_issues = []
    
    for template_file in template_files:
        if not os.path.exists(template_file):
            print(f"Warning: Template file {template_file} not found")
            continue
        
        print(f"Validating {template_file}...")
        template = load_yaml_template(template_file)
        
        if template is None:
            continue
        
        # Run all validation checks
        issues = []
        issues.extend(validate_lambda_security(template, template_file))
        issues.extend(validate_iam_policies(template, template_file))
        issues.extend(validate_security_groups(template, template_file))
        issues.extend(validate_encryption(template, template_file))
        issues.extend(validate_resource_policies(template, template_file))
        
        if issues:
            all_issues.extend(issues)
            print(f"  Found {len(issues)} security issues")
            for issue in issues:
                print(f"    - {issue}")
        else:
            print(f"  ✓ No security issues found")
    
    print(f"\nValidation complete. Total issues found: {len(all_issues)}")
    
    if all_issues:
        print("\nSummary of all issues:")
        for issue in all_issues:
            print(f"  - {issue}")
        return 1
    else:
        print("✓ All security validations passed!")
        return 0

if __name__ == "__main__":
    sys.exit(main())