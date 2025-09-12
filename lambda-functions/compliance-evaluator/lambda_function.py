import json
import boto3
import os
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, List, Optional
from gremlin_python.driver import client
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from gremlin_python.process.traversal import T, P

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create structured logging formatter
class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'function': record.funcName,
            'line': record.lineno,
            'module': record.module
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'ami_id'):
            log_entry['ami_id'] = record.ami_id
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
        if hasattr(record, 'resource_id'):
            log_entry['resource_id'] = record.resource_id
        if hasattr(record, 'compliance_rule'):
            log_entry['compliance_rule'] = record.compliance_rule
            
        return json.dumps(log_entry)

# Apply structured formatter to logger
handler = logging.StreamHandler()
handler.setFormatter(StructuredFormatter())
logger.handlers = [handler]

# Environment variables
NEPTUNE_ENDPOINT = os.environ['NEPTUNE_ENDPOINT']
NEPTUNE_PORT = os.environ.get('NEPTUNE_PORT', '8182')
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# Initialize AWS clients
config_client = boto3.client('config')
securityhub_client = boto3.client('securityhub')
sns_client = boto3.client('sns')
ec2_client = boto3.client('ec2')

class NeptuneConnection:
    def __init__(self):
        self.connection = None
        self.g = None
    
    def connect(self):
        try:
            self.connection = DriverRemoteConnection(
                f'wss://{NEPTUNE_ENDPOINT}:{NEPTUNE_PORT}/gremlin',
                'g'
            )
            self.g = traversal().withRemote(self.connection)
            logger.info("Successfully connected to Neptune")
        except Exception as e:
            logger.warning(f"Failed to connect to Neptune: {str(e)}")
            raise
    
    def close(self):
        if self.connection:
            self.connection.close()

def lambda_handler(event, context):
    """
    Main Lambda handler for compliance evaluation
    """
    correlation_id = context.aws_request_id if context else 'unknown'
    
    logger.info("Processing compliance evaluation", extra={
        'correlation_id': correlation_id,
        'event_source': event.get('source', 'direct')
    })
    
    neptune_conn = NeptuneConnection()
    
    try:
        neptune_conn.connect()
        
        # Determine the source of the event
        if 'configRuleInvokingEvent' in event:
            # AWS Config rule evaluation
            return handle_config_rule_evaluation(event, neptune_conn.g, correlation_id)
        elif 'source' in event and event['source'] == 'aws.events':
            # EventBridge scheduled evaluation
            return handle_scheduled_evaluation(event, neptune_conn.g, correlation_id)
        else:
            # Direct invocation
            return handle_direct_evaluation(event, neptune_conn.g, correlation_id)
    
    except Exception as e:
        logger.error(f"Critical error in compliance evaluation: {str(e)}", extra={
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__,
            'traceback': traceback.format_exc()
        })
        send_error_notification(str(e), correlation_id)
        raise
    
    finally:
        neptune_conn.close()

def handle_config_rule_evaluation(event: Dict, g, correlation_id: str) -> Dict:
    """
    Handle AWS Config rule evaluation
    """
    try:
        config_item = json.loads(event['configRuleInvokingEvent'])['configurationItem']
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
        
        resource_type = config_item['resourceType']
        resource_id = config_item['resourceId']
        
        logger.info("Evaluating Config rule", extra={
            'resource_type': resource_type,
            'resource_id': resource_id,
            'correlation_id': correlation_id
        })
        
        if resource_type == 'AWS::EC2::Image':
            # Evaluate AMI compliance
            compliance_result = evaluate_ami_compliance(g, resource_id, rule_parameters, correlation_id)
        elif resource_type == 'AWS::EC2::Instance':
            # Evaluate instance AMI compliance
            compliance_result = evaluate_instance_ami_compliance(g, resource_id, rule_parameters, correlation_id)
        else:
            logger.warning("Unsupported resource type", extra={
                'resource_type': resource_type,
                'correlation_id': correlation_id
            })
            return create_config_response('NOT_APPLICABLE', 'Unsupported resource type')
        
        # Send result back to Config
        send_config_evaluation(event, compliance_result, correlation_id)
        
        # Create Security Hub finding if non-compliant
        if compliance_result['compliance_type'] == 'NON_COMPLIANT':
            create_compliance_finding(resource_id, resource_type, compliance_result, correlation_id)
        
        return compliance_result
    
    except Exception as e:
        logger.warning(f"Failed to handle Config rule evaluation: {str(e)}", extra={
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_scheduled_evaluation(event: Dict, g) -> Dict:
    """
    Handle scheduled compliance evaluation
    """
    try:
        # Perform organization-wide compliance assessment
        compliance_results = perform_organization_compliance_assessment(g)
        
        # Send summary notification
        send_compliance_summary_notification(compliance_results)
        
        # Create Security Hub insights
        create_compliance_insights(compliance_results)
        
        return {
            'statusCode': 200,
            'body': json.dumps(compliance_results)
        }
    
    except Exception as e:
        logger.warning(f"Error handling scheduled evaluation: {str(e)}")
        raise

def handle_direct_evaluation(event: Dict, g) -> Dict:
    """
    Handle direct compliance evaluation request
    """
    try:
        resource_id = event.get('resource_id')
        resource_type = event.get('resource_type', 'AWS::EC2::Image')
        evaluation_rules = event.get('rules', [])
        
        if not resource_id:
            return {'error': 'resource_id is required'}
        
        if resource_type == 'AWS::EC2::Image':
            compliance_result = evaluate_ami_compliance(g, resource_id, {'rules': evaluation_rules})
        else:
            return {'error': f'Unsupported resource type: {resource_type}'}
        
        return compliance_result
    
    except Exception as e:
        logger.warning(f"Error handling direct evaluation: {str(e)}")
        raise

def evaluate_ami_compliance(g, ami_id: str, rule_parameters: Dict, correlation_id: str = None) -> Dict:
    """
    Evaluate AMI compliance against organizational policies
    """
    try:
        # Get AMI data from Neptune
        ami_data = g.V().has('ami', 'ami_id', ami_id).valueMap().toList()
        
        if not ami_data:
            # AMI not in Neptune, get from EC2 API
            ami_details = get_ami_from_ec2(ami_id)
            if not ami_details:
                logger.warning("AMI not found", extra={
                    'ami_id': ami_id,
                    'correlation_id': correlation_id
                })
                return create_config_response('NOT_APPLICABLE', 'AMI not found')
            ami_data = [convert_ec2_ami_to_neptune_format(ami_details)]
        
        ami_info = ami_data[0]
        
        # Evaluate compliance rules
        compliance_results = []
        overall_compliance = True
        
        # Rule 1: Required tags
        required_tags_result = evaluate_required_tags(ami_info, correlation_id)
        compliance_results.append(required_tags_result)
        if not required_tags_result['compliant']:
            overall_compliance = False
        
        # Rule 2: Approval status
        approval_result = evaluate_approval_status(ami_info, correlation_id)
        compliance_results.append(approval_result)
        if not approval_result['compliant']:
            overall_compliance = False
        
        # Rule 3: Security scan status
        security_scan_result = evaluate_security_scan_status(ami_info, correlation_id)
        compliance_results.append(security_scan_result)
        if not security_scan_result['compliant']:
            overall_compliance = False
        
        # Rule 4: Naming convention
        naming_result = evaluate_naming_convention(ami_info, correlation_id)
        compliance_results.append(naming_result)
        if not naming_result['compliant']:
            overall_compliance = False
        
        # Rule 5: Lineage verification
        lineage_result = evaluate_lineage_verification(g, ami_id, ami_info, correlation_id)
        compliance_results.append(lineage_result)
        if not lineage_result['compliant']:
            overall_compliance = False
        
        compliance_type = 'COMPLIANT' if overall_compliance else 'NON_COMPLIANT'
        
        logger.info("AMI compliance evaluation completed", extra={
            'ami_id': ami_id,
            'overall_compliant': overall_compliance,
            'correlation_id': correlation_id
        })
        
        return create_config_response(compliance_type, 'AMI compliance evaluation completed', {
            'ami_id': ami_id,
            'overall_compliant': overall_compliance,
            'rule_results': compliance_results,
            'evaluation_timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.warning(f"Failed to evaluate AMI compliance: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        return create_config_response('NOT_APPLICABLE', f'Error evaluating compliance: {str(e)}')

def evaluate_instance_ami_compliance(g, instance_id: str, rule_parameters: Dict) -> Dict:
    """
    Evaluate instance AMI compliance
    """
    try:
        # Get instance data from Neptune or EC2
        instance_data = g.V().has('instance', 'instance_id', instance_id).valueMap().toList()
        
        if not instance_data:
            # Get from EC2 API
            instance_details = get_instance_from_ec2(instance_id)
            if not instance_details:
                return create_config_response('NOT_APPLICABLE', 'Instance not found')
            ami_id = instance_details.get('ImageId')
        else:
            ami_id = instance_data[0].get('ami_id', [''])[0]
        
        if not ami_id:
            return create_config_response('NON_COMPLIANT', 'Instance has no associated AMI')
        
        # Evaluate the AMI compliance
        return evaluate_ami_compliance(g, ami_id, rule_parameters)
    
    except Exception as e:
        logger.error(f"Error evaluating instance AMI compliance: {str(e)}")
        return create_config_response('NOT_APPLICABLE', f'Error evaluating compliance: {str(e)}')

def evaluate_required_tags(ami_info: Dict, correlation_id: str = None) -> Dict:
    """
    Evaluate required tags compliance rule
    """
    required_tags = ['creator', 'source', 'approval_status', 'security_scan', 'environment']
    missing_tags = []
    
    for tag in required_tags:
        if tag not in ami_info or not ami_info[tag]:
            missing_tags.append(tag)
    
    is_compliant = len(missing_tags) == 0
    
    logger.info("Required tags evaluation completed", extra={
        'compliance_rule': 'required_tags',
        'compliant': is_compliant,
        'missing_tags_count': len(missing_tags),
        'correlation_id': correlation_id
    })
    
    return {
        'rule_name': 'required_tags',
        'compliant': is_compliant,
        'details': {
            'missing_tags': missing_tags,
            'required_tags': required_tags
        }
    }

def evaluate_approval_status(ami_info: Dict, correlation_id: str = None) -> Dict:
    """
    Evaluate approval status compliance rule
    """
    approval_status = ami_info.get('approval_status', [''])[0] if isinstance(ami_info.get('approval_status', ['']), list) else ami_info.get('approval_status', '')
    is_compliant = approval_status == 'Approved'
    
    logger.info("Approval status evaluation completed", extra={
        'compliance_rule': 'approval_status',
        'compliant': is_compliant,
        'current_status': approval_status,
        'correlation_id': correlation_id
    })
    
    return {
        'rule_name': 'approval_status',
        'compliant': is_compliant,
        'details': {
            'current_status': approval_status,
            'required_status': 'Approved'
        }
    }

def evaluate_security_scan_status(ami_info: Dict) -> Dict:
    """
    Evaluate security scan status compliance rule
    """
    security_scan = ami_info.get('security_scan', [''])[0] if isinstance(ami_info.get('security_scan', ['']), list) else ami_info.get('security_scan', '')
    
    return {
        'rule_name': 'security_scan_status',
        'compliant': security_scan == 'PASSED',
        'details': {
            'current_status': security_scan,
            'required_status': 'PASSED'
        }
    }

def evaluate_naming_convention(ami_info: Dict) -> Dict:
    """
    Evaluate naming convention compliance rule
    """
    name = ami_info.get('name', [''])[0] if isinstance(ami_info.get('name', ['']), list) else ami_info.get('name', '')
    
    # Example naming convention: must contain environment and version
    environment = ami_info.get('environment', [''])[0] if isinstance(ami_info.get('environment', ['']), list) else ami_info.get('environment', '')
    
    # Basic naming convention check
    naming_compliant = (
        len(name) > 5 and
        environment.lower() in name.lower() and
        any(char.isdigit() for char in name)  # Contains version number
    )
    
    return {
        'rule_name': 'naming_convention',
        'compliant': naming_compliant,
        'details': {
            'ami_name': name,
            'environment': environment,
            'convention': 'Name must contain environment and version number'
        }
    }

def evaluate_lineage_verification(g, ami_id: str, ami_info: Dict, correlation_id: str = None) -> Dict:
    """
    Evaluate lineage verification compliance rule
    """
    try:
        # Check if AMI has lineage information
        has_lineage = g.V().has('ami', 'ami_id', ami_id).bothE().hasNext()
        
        creation_method = ami_info.get('creation_method', [''])[0] if isinstance(ami_info.get('creation_method', ['']), list) else ami_info.get('creation_method', '')
        
        is_compliant = has_lineage and bool(creation_method)
        
        logger.info("Lineage verification evaluation completed", extra={
            'compliance_rule': 'lineage_verification',
            'compliant': is_compliant,
            'has_lineage_data': has_lineage,
            'ami_id': ami_id,
            'correlation_id': correlation_id
        })
        
        return {
            'rule_name': 'lineage_verification',
            'compliant': is_compliant,
            'details': {
                'has_lineage_data': has_lineage,
                'creation_method': creation_method
            }
        }
    
    except Exception as e:
        logger.warning(f"Failed to evaluate lineage verification: {str(e)}", extra={
            'compliance_rule': 'lineage_verification',
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        return {
            'rule_name': 'lineage_verification',
            'compliant': False,
            'details': {
                'error': str(e)
            }
        }

def perform_organization_compliance_assessment(g) -> Dict:
    """
    Perform organization-wide compliance assessment
    """
    try:
        # Get all AMIs in the organization
        all_amis = g.V().hasLabel('ami').valueMap().toList()
        
        total_amis = len(all_amis)
        compliant_amis = 0
        rule_statistics = {
            'required_tags': {'compliant': 0, 'non_compliant': 0},
            'approval_status': {'compliant': 0, 'non_compliant': 0},
            'security_scan_status': {'compliant': 0, 'non_compliant': 0},
            'naming_convention': {'compliant': 0, 'non_compliant': 0},
            'lineage_verification': {'compliant': 0, 'non_compliant': 0}
        }
        
        non_compliant_resources = []
        
        for ami in all_amis:
            ami_id = ami['ami_id'][0] if isinstance(ami['ami_id'], list) else ami['ami_id']
            
            # Evaluate each rule
            required_tags_result = evaluate_required_tags(ami)
            approval_result = evaluate_approval_status(ami)
            security_scan_result = evaluate_security_scan_status(ami)
            naming_result = evaluate_naming_convention(ami)
            lineage_result = evaluate_lineage_verification(g, ami_id, ami)
            
            # Update statistics
            for rule_result in [required_tags_result, approval_result, security_scan_result, naming_result, lineage_result]:
                rule_name = rule_result['rule_name']
                if rule_result['compliant']:
                    rule_statistics[rule_name]['compliant'] += 1
                else:
                    rule_statistics[rule_name]['non_compliant'] += 1
            
            # Check overall compliance
            overall_compliant = all([
                required_tags_result['compliant'],
                approval_result['compliant'],
                security_scan_result['compliant'],
                naming_result['compliant'],
                lineage_result['compliant']
            ])
            
            if overall_compliant:
                compliant_amis += 1
            else:
                # Add to non-compliant resources
                violations = [r['rule_name'] for r in [required_tags_result, approval_result, security_scan_result, naming_result, lineage_result] if not r['compliant']]
                
                non_compliant_resources.append({
                    'ami_id': ami_id,
                    'account_id': ami.get('account_id', [''])[0] if isinstance(ami.get('account_id', ['']), list) else ami.get('account_id', ''),
                    'region': ami.get('region', [''])[0] if isinstance(ami.get('region', ['']), list) else ami.get('region', ''),
                    'violations': violations
                })
        
        compliance_percentage = (compliant_amis / total_amis * 100) if total_amis > 0 else 0
        
        return {
            'assessment_timestamp': datetime.utcnow().isoformat(),
            'compliance_summary': {
                'total_amis': total_amis,
                'compliant_amis': compliant_amis,
                'non_compliant_amis': total_amis - compliant_amis,
                'compliance_percentage': round(compliance_percentage, 2)
            },
            'rule_statistics': rule_statistics,
            'non_compliant_resources': non_compliant_resources[:100]  # Limit to first 100
        }
    
    except Exception as e:
        logger.warning(f"Error performing organization compliance assessment: {str(e)}")
        raise

def get_ami_from_ec2(ami_id: str) -> Optional[Dict]:
    """
    Get AMI details from EC2 API
    """
    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])
        if response['Images']:
            return response['Images'][0]
        return None
    except Exception as e:
        logger.error(f"Error getting AMI from EC2: {str(e)}")
        return None

def get_instance_from_ec2(instance_id: str) -> Optional[Dict]:
    """
    Get instance details from EC2 API
    """
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if response['Reservations'] and response['Reservations'][0]['Instances']:
            return response['Reservations'][0]['Instances'][0]
        return None
    except Exception as e:
        logger.error(f"Error getting instance from EC2: {str(e)}")
        return None

def convert_ec2_ami_to_neptune_format(ami_details: Dict) -> Dict:
    """
    Convert EC2 AMI details to Neptune format
    """
    tags = {tag['Key'].lower(): tag['Value'] for tag in ami_details.get('Tags', [])}
    
    return {
        'ami_id': ami_details['ImageId'],
        'name': ami_details.get('Name', ''),
        'account_id': ami_details.get('OwnerId', ''),
        'region': os.environ.get('AWS_REGION', ''),
        'creation_date': ami_details.get('CreationDate', ''),
        'creator': tags.get('creator', ''),
        'source': tags.get('source', 'UNKNOWN'),
        'approval_status': tags.get('approvalstatus', 'PENDING'),
        'security_scan': tags.get('securityscan', 'PENDING'),
        'environment': tags.get('environment', ''),
        'creation_method': 'UNKNOWN'
    }

def send_config_evaluation(event: Dict, compliance_result: Dict):
    """
    Send evaluation result back to AWS Config
    """
    try:
        config_client.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': event['configRuleInvokingEvent']['configurationItem']['resourceType'],
                    'ComplianceResourceId': event['configRuleInvokingEvent']['configurationItem']['resourceId'],
                    'ComplianceType': compliance_result['compliance_type'],
                    'Annotation': compliance_result['annotation'],
                    'OrderingTimestamp': datetime.utcnow()
                }
            ],
            ResultToken=event['resultToken']
        )
        
        logger.info("Successfully sent evaluation to Config")
    
    except Exception as e:
        logger.error(f"Error sending evaluation to Config: {str(e)}")

def create_compliance_finding(resource_id: str, resource_type: str, compliance_result: Dict):
    """
    Create Security Hub finding for compliance violation
    """
    try:
        finding = {
            'SchemaVersion': '2018-10-08',
            'Id': f'ami-compliance/{resource_id}',
            'ProductArn': f'arn:aws:securityhub:{os.environ.get("AWS_REGION")}:{os.environ.get("AWS_ACCOUNT_ID")}:product/{os.environ.get("AWS_ACCOUNT_ID")}/default',
            'GeneratorId': 'ami-compliance-evaluator',
            'AwsAccountId': os.environ.get('AWS_ACCOUNT_ID'),
            'Types': ['Sensitive Data Identifications/Compliance'],
            'FirstObservedAt': datetime.utcnow().isoformat() + 'Z',
            'LastObservedAt': datetime.utcnow().isoformat() + 'Z',
            'CreatedAt': datetime.utcnow().isoformat() + 'Z',
            'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
            'Severity': {
                'Label': 'MEDIUM'
            },
            'Title': f'AMI Compliance Violation: {resource_id}',
            'Description': compliance_result.get('annotation', 'AMI does not meet compliance requirements'),
            'Resources': [
                {
                    'Type': 'AwsEc2Image' if resource_type == 'AWS::EC2::Image' else 'AwsEc2Instance',
                    'Id': f'arn:aws:ec2:{os.environ.get("AWS_REGION")}:{os.environ.get("AWS_ACCOUNT_ID")}:{"image" if resource_type == "AWS::EC2::Image" else "instance"}/{resource_id}',
                    'Region': os.environ.get('AWS_REGION'),
                    'Details': {
                        'Other': compliance_result.get('details', {})
                    }
                }
            ]
        }
        
        securityhub_client.batch_import_findings(Findings=[finding])
        logger.info(f"Created Security Hub finding for resource: {resource_id}")
    
    except Exception as e:
        logger.error(f"Error creating Security Hub finding: {str(e)}")

def create_compliance_insights(compliance_results: Dict):
    """
    Create Security Hub insights for compliance trends
    """
    try:
        # Create insight for overall compliance
        insight = {
            'Name': 'AMI Compliance Overview',
            'Filters': {
                'GeneratorId': [
                    {
                        'Value': 'ami-compliance-evaluator',
                        'Comparison': 'EQUALS'
                    }
                ]
            },
            'GroupByAttribute': 'ComplianceStatus'
        }
        
        securityhub_client.create_insight(**insight)
        logger.info("Created Security Hub compliance insight")
    
    except Exception as e:
        logger.error(f"Error creating Security Hub insight: {str(e)}")

def send_compliance_summary_notification(compliance_results: Dict):
    """
    Send compliance summary notification via SNS
    """
    try:
        message = {
            'assessment_type': 'organization_compliance_summary',
            'timestamp': compliance_results['assessment_timestamp'],
            'summary': compliance_results['compliance_summary'],
            'top_violations': compliance_results['non_compliant_resources'][:10]
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='AMI Compliance Assessment Summary',
            Message=json.dumps(message, indent=2)
        )
        
        logger.info("Sent compliance summary notification")
    
    except Exception as e:
        logger.error(f"Error sending compliance summary notification: {str(e)}")

def send_error_notification(error_message: str, correlation_id: str = None):
    """
    Send error notification via SNS
    """
    try:
        message = {
            'error': error_message,
            'timestamp': datetime.utcnow().isoformat(),
            'function': 'ami-compliance-evaluator',
            'correlation_id': correlation_id
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='AMI Compliance Evaluation Error',
            Message=json.dumps(message, indent=2)
        )
        
        logger.info("Error notification sent", extra={
            'correlation_id': correlation_id,
            'notification_type': 'error'
        })
    
    except Exception as e:
        logger.warning(f"Failed to send error notification: {str(e)}", extra={
            'correlation_id': correlation_id,
            'original_error': error_message,
            'exception_type': type(e).__name__
        })

def create_config_response(compliance_type: str, annotation: str, details: Optional[Dict] = None) -> Dict:
    """
    Create AWS Config evaluation response
    """
    return {
        'compliance_type': compliance_type,
        'annotation': annotation,
        'details': details or {}
    }
