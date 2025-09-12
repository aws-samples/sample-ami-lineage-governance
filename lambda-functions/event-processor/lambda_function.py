import json
import boto3
import os
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional
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
        if hasattr(record, 'event_name'):
            log_entry['event_name'] = record.event_name
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
            
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
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')

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
    Main Lambda handler for processing AMI events
    """
    correlation_id = context.aws_request_id if context else 'unknown'
    
    logger.info("Processing AMI events", extra={
        'correlation_id': correlation_id,
        'event_count': len(event.get('Records', [event]))
    })
    
    neptune_conn = NeptuneConnection()
    
    try:
        neptune_conn.connect()
        
        # Process each record in the event
        processed_count = 0
        for record in event.get('Records', [event]):
            try:
                process_ami_event(record, neptune_conn.g, correlation_id)
                processed_count += 1
            except Exception as record_error:
                logger.warning(f"Failed to process individual record: {str(record_error)}", extra={
                    'correlation_id': correlation_id,
                    'record_index': processed_count
                })
                # Continue processing other records
                continue
        
        logger.info(f"Successfully processed {processed_count} AMI events", extra={
            'correlation_id': correlation_id,
            'processed_count': processed_count
        })
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed AMI events',
                'processed_count': processed_count,
                'correlation_id': correlation_id
            })
        }
    
    except Exception as e:
        logger.error(f"Critical error processing AMI events: {str(e)}", extra={
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__,
            'traceback': traceback.format_exc()
        })
        send_error_notification(str(e), correlation_id)
        raise
    
    finally:
        neptune_conn.close()

def process_ami_event(event_record: Dict[str, Any], g, correlation_id: str = None):
    """
    Process individual AMI event and update Neptune graph
    """
    try:
        # Extract event details
        if 'detail' in event_record:
            detail = event_record['detail']
            event_name = detail.get('eventName')
            source_ip = detail.get('sourceIPAddress')
            user_identity = detail.get('userIdentity', {})
            request_parameters = detail.get('requestParameters', {})
            response_elements = detail.get('responseElements', {})
        else:
            # Direct event format
            event_name = event_record.get('eventName')
            detail = event_record
            request_parameters = event_record.get('requestParameters', {})
            response_elements = event_record.get('responseElements', {})
        
        logger.info("Processing AMI event", extra={
            'event_name': event_name,
            'correlation_id': correlation_id,
            'source_ip': source_ip
        })
        
        # Route to appropriate handler based on event type
        if event_name == 'CreateImage':
            handle_create_image_event(detail, request_parameters, response_elements, g, correlation_id)
        elif event_name == 'CopyImage':
            handle_copy_image_event(detail, request_parameters, response_elements, g, correlation_id)
        elif event_name == 'CreateRestoreImageTask':
            handle_restore_image_event(detail, request_parameters, response_elements, g, correlation_id)
        elif event_name in ['CreateTags', 'DeleteTags']:
            handle_tag_event(detail, request_parameters, response_elements, g, correlation_id)
        elif event_name == 'DeregisterImage':
            handle_deregister_image_event(detail, request_parameters, response_elements, g, correlation_id)
        elif event_name == 'RunInstances':
            handle_instance_launch_event(detail, request_parameters, response_elements, g, correlation_id)
        else:
            logger.warning("Unhandled event type", extra={
                'event_name': event_name,
                'correlation_id': correlation_id
            })
    
    except Exception as e:
        logger.warning(f"Failed to process event record: {str(e)}", extra={
            'event_name': event_name if 'event_name' in locals() else 'unknown',
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_create_image_event(detail: Dict, request_params: Dict, response_elements: Dict, g, correlation_id: str = None):
    """
    Handle AMI creation events
    """
    ami_id = response_elements.get('imageId')
    instance_id = request_params.get('instanceId')
    ami_name = request_params.get('name')
    
    if not ami_id:
        logger.warning("No AMI ID found in CreateImage event", extra={
            'correlation_id': correlation_id,
            'event_type': 'CreateImage'
        })
        return
    
    try:
        # Get additional AMI details from EC2 API
        ami_details = get_ami_details(ami_id)
        
        # Create or update AMI node in Neptune
        create_ami_node(g, ami_id, ami_details, 'CREATE', correlation_id)
        
        # If created from instance, establish relationship
        if instance_id:
            # Get instance details to find source AMI
            instance_details = get_instance_details(instance_id)
            if instance_details and 'ImageId' in instance_details:
                source_ami_id = instance_details['ImageId']
                create_ami_relationship(g, source_ami_id, ami_id, 'DERIVED_FROM', 'CreateImage', correlation_id)
        
        # Check compliance and send notifications if needed
        check_ami_compliance(ami_id, ami_details, correlation_id)
        
        logger.info("Successfully processed CreateImage event", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'instance_id': instance_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to handle CreateImage event: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_copy_image_event(detail: Dict, request_params: Dict, response_elements: Dict, g, correlation_id: str = None):
    """
    Handle AMI copy events
    """
    ami_id = response_elements.get('imageId')
    source_ami_id = request_params.get('sourceImageId')
    source_region = request_params.get('sourceRegion')
    
    if not ami_id or not source_ami_id:
        logger.warning("Missing AMI IDs in CopyImage event", extra={
            'ami_id': ami_id,
            'source_ami_id': source_ami_id,
            'correlation_id': correlation_id
        })
        return
    
    try:
        # Get AMI details
        ami_details = get_ami_details(ami_id)
        
        # Create AMI node
        create_ami_node(g, ami_id, ami_details, 'COPY', correlation_id)
        
        # Create relationship to source AMI
        create_ami_relationship(g, source_ami_id, ami_id, 'COPY_OF', 'CopyImage', correlation_id)
        
        # Check compliance
        check_ami_compliance(ami_id, ami_details, correlation_id)
        
        logger.info("Successfully processed CopyImage event", extra={
            'ami_id': ami_id,
            'source_ami_id': source_ami_id,
            'source_region': source_region,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to handle CopyImage event: {str(e)}", extra={
            'ami_id': ami_id,
            'source_ami_id': source_ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_restore_image_event(detail: Dict, request_params: Dict, response_elements: Dict, g, correlation_id: str = None):
    """
    Handle AMI restore from snapshot events
    """
    ami_id = response_elements.get('imageId')
    snapshot_id = request_params.get('snapshotId')
    
    if not ami_id:
        logger.warning("No AMI ID found in CreateRestoreImageTask event", extra={
            'correlation_id': correlation_id,
            'event_type': 'CreateRestoreImageTask'
        })
        return
    
    try:
        # Get AMI details
        ami_details = get_ami_details(ami_id)
        
        # Create AMI node
        create_ami_node(g, ami_id, ami_details, 'RESTORE', correlation_id)
        
        # Check compliance
        check_ami_compliance(ami_id, ami_details, correlation_id)
        
        logger.info("Successfully processed CreateRestoreImageTask event", extra={
            'ami_id': ami_id,
            'snapshot_id': snapshot_id,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to handle CreateRestoreImageTask event: {str(e)}", extra={
            'ami_id': ami_id,
            'snapshot_id': snapshot_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_tag_event(detail: Dict, request_params: Dict, response_elements: Dict, g, correlation_id: str = None):
    """
    Handle AMI tagging events
    """
    try:
        resources = request_params.get('resourcesSet', {}).get('items', [])
        tags = request_params.get('tagSet', {}).get('items', [])
        
        processed_amis = []
        for resource in resources:
            resource_id = resource.get('resourceId')
            if resource_id and resource_id.startswith('ami-'):
                # Update AMI node with new tags
                ami_details = get_ami_details(resource_id)
                update_ami_node_tags(g, resource_id, ami_details, correlation_id)
                processed_amis.append(resource_id)
                
                # Check if approval status changed
                for tag in tags:
                    if tag.get('key') == 'Approval' and tag.get('value') == 'Approved':
                        send_approval_notification(resource_id, correlation_id)
        
        logger.info("Successfully processed tag event", extra={
            'processed_amis': processed_amis,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to handle tag event: {str(e)}", extra={
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_deregister_image_event(detail: Dict, request_params: Dict, response_elements: Dict, g, correlation_id: str = None):
    """
    Handle AMI deregistration events
    """
    ami_id = request_params.get('imageId')
    
    if not ami_id:
        logger.warning("No AMI ID found in DeregisterImage event", extra={
            'correlation_id': correlation_id,
            'event_type': 'DeregisterImage'
        })
        return
    
    try:
        # Mark AMI as deregistered in Neptune (don't delete for audit purposes)
        mark_ami_deregistered(g, ami_id, correlation_id)
        
        logger.info("Successfully processed DeregisterImage event", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to handle DeregisterImage event: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def handle_instance_launch_event(detail: Dict, request_params: Dict, response_elements: Dict, g, correlation_id: str = None):
    """
    Handle EC2 instance launch events to track AMI usage
    """
    try:
        instances = response_elements.get('instancesSet', {}).get('items', [])
        processed_instances = []
        
        for instance in instances:
            instance_id = instance.get('instanceId')
            ami_id = instance.get('imageId')
            
            if instance_id and ami_id:
                # Create instance node and relationship to AMI
                create_instance_node(g, instance_id, instance, ami_id, correlation_id)
                create_instance_ami_relationship(g, instance_id, ami_id, correlation_id)
                processed_instances.append(instance_id)
        
        logger.info("Successfully processed instance launch event", extra={
            'processed_instances': processed_instances,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to handle instance launch event: {str(e)}", extra={
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def create_ami_node(g, ami_id: str, ami_details: Dict, creation_method: str, correlation_id: str = None):
    """
    Create or update AMI node in Neptune graph
    """
    try:
        # Extract relevant information from AMI details
        tags = {tag['Key']: tag['Value'] for tag in ami_details.get('Tags', [])}
        
        # Create or update the AMI vertex
        g.V().has('ami', 'ami_id', ami_id).fold().coalesce(
            __.unfold(),
            __.addV('ami').property('ami_id', ami_id)
        ).property('region', ami_details.get('Region', os.environ.get('AWS_REGION'))).property(
            'account_id', ami_details.get('OwnerId', '')
        ).property('name', ami_details.get('Name', '')).property(
            'creation_date', ami_details.get('CreationDate', '')
        ).property('creator', ami_details.get('CreatorRequestId', '')).property(
            'source', tags.get('Source', 'UNKNOWN')
        ).property('approval_status', tags.get('ApprovalStatus', 'PENDING')).property(
            'security_scan', tags.get('SecurityScan', 'PENDING')
        ).property('base_ami', tags.get('BaseAMI', '')).property(
            'environment', tags.get('Environment', '')
        ).property('creation_method', creation_method).property(
            'state', ami_details.get('State', 'available')
        ).property('last_updated', datetime.utcnow().isoformat()).iterate()
        
        logger.info("Created/updated AMI node", extra={
            'ami_id': ami_id,
            'creation_method': creation_method,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to create AMI node: {str(e)}", extra={
            'ami_id': ami_id,
            'creation_method': creation_method,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def create_ami_relationship(g, source_ami_id: str, target_ami_id: str, relationship_type: str, creation_method: str, correlation_id: str = None):
    """
    Create relationship between AMIs in Neptune graph
    """
    try:
        # Create edge between source and target AMI
        g.V().has('ami', 'ami_id', source_ami_id).as_('source').V().has(
            'ami', 'ami_id', target_ami_id
        ).as_('target').addE(relationship_type).from_('source').to('target').property(
            'creation_method', creation_method
        ).property('creation_date', datetime.utcnow().isoformat()).iterate()
        
        logger.info("Created AMI relationship", extra={
            'source_ami_id': source_ami_id,
            'target_ami_id': target_ami_id,
            'relationship_type': relationship_type,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to create AMI relationship: {str(e)}", extra={
            'source_ami_id': source_ami_id,
            'target_ami_id': target_ami_id,
            'relationship_type': relationship_type,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def create_instance_node(g, instance_id: str, instance_details: Dict, ami_id: str, correlation_id: str = None):
    """
    Create instance node in Neptune graph
    """
    try:
        tags = {tag['Key']: tag['Value'] for tag in instance_details.get('tagSet', {}).get('items', [])}
        
        g.V().has('instance', 'instance_id', instance_id).fold().coalesce(
            __.unfold(),
            __.addV('instance').property('instance_id', instance_id)
        ).property('region', os.environ.get('AWS_REGION')).property(
            'account_id', instance_details.get('ownerId', '')
        ).property('ami_id', ami_id).property(
            'launch_time', instance_details.get('launchTime', '')
        ).property('state', instance_details.get('instanceState', {}).get('name', '')).property(
            'instance_type', instance_details.get('instanceType', '')
        ).property('last_updated', datetime.utcnow().isoformat()).iterate()
        
        logger.info("Created/updated instance node", extra={
            'instance_id': instance_id,
            'ami_id': ami_id,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to create instance node: {str(e)}", extra={
            'instance_id': instance_id,
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def create_instance_ami_relationship(g, instance_id: str, ami_id: str, correlation_id: str = None):
    """
    Create relationship between instance and AMI
    """
    try:
        g.V().has('instance', 'instance_id', instance_id).as_('instance').V().has(
            'ami', 'ami_id', ami_id
        ).as_('ami').addE('USES').from_('instance').to('ami').property(
            'creation_date', datetime.utcnow().isoformat()
        ).iterate()
        
        logger.info("Created instance-AMI relationship", extra={
            'instance_id': instance_id,
            'ami_id': ami_id,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to create instance-AMI relationship: {str(e)}", extra={
            'instance_id': instance_id,
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def get_ami_details(ami_id: str) -> Dict[str, Any]:
    """
    Get AMI details from EC2 API
    """
    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])
        if response['Images']:
            return response['Images'][0]
        else:
            logger.warning("AMI not found in EC2", extra={'ami_id': ami_id})
            return {}
    except Exception as e:
        logger.warning(f"Failed to get AMI details: {str(e)}", extra={
            'ami_id': ami_id,
            'exception_type': type(e).__name__
        })
        return {}

def get_instance_details(instance_id: str) -> Optional[Dict[str, Any]]:
    """
    Get instance details from EC2 API
    """
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if response['Reservations'] and response['Reservations'][0]['Instances']:
            return response['Reservations'][0]['Instances'][0]
        else:
            logger.warning(f"Instance not found: {instance_id}")
            return None
    except Exception as e:
        logger.error(f"Error getting instance details for {instance_id}: {str(e)}")
        return None

def update_ami_node_tags(g, ami_id: str, ami_details: Dict, correlation_id: str = None):
    """
    Update AMI node with latest tag information
    """
    try:
        tags = {tag['Key']: tag['Value'] for tag in ami_details.get('Tags', [])}
        
        g.V().has('ami', 'ami_id', ami_id).property(
            'approval_status', tags.get('ApprovalStatus', 'PENDING')
        ).property('security_scan', tags.get('SecurityScan', 'PENDING')).property(
            'source', tags.get('Source', 'UNKNOWN')
        ).property('base_ami', tags.get('BaseAMI', '')).property(
            'environment', tags.get('Environment', '')
        ).property('last_updated', datetime.utcnow().isoformat()).iterate()
        
        logger.info("Updated AMI node tags", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to update AMI node tags: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def mark_ami_deregistered(g, ami_id: str, correlation_id: str = None):
    """
    Mark AMI as deregistered in Neptune graph
    """
    try:
        g.V().has('ami', 'ami_id', ami_id).property('state', 'deregistered').property(
            'deregistration_date', datetime.utcnow().isoformat()
        ).property('last_updated', datetime.utcnow().isoformat()).iterate()
        
        logger.info("Marked AMI as deregistered", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to mark AMI as deregistered: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def check_ami_compliance(ami_id: str, ami_details: Dict, correlation_id: str = None):
    """
    Check AMI compliance and send notifications if needed
    """
    try:
        tags = {tag['Key']: tag['Value'] for tag in ami_details.get('Tags', [])}
        
        # Check required tags
        required_tags = ['Creator', 'Source', 'ApprovalStatus', 'SecurityScan', 'Environment']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        # Check approval status
        approval_status = tags.get('ApprovalStatus', 'PENDING')
        
        if missing_tags or approval_status != 'Approved':
            send_compliance_notification(ami_id, missing_tags, approval_status, correlation_id)
        else:
            logger.info("AMI compliance check passed", extra={
                'ami_id': ami_id,
                'correlation_id': correlation_id
            })
    
    except Exception as e:
        logger.warning(f"Failed to check AMI compliance: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })

def send_compliance_notification(ami_id: str, missing_tags: list, approval_status: str, correlation_id: str = None):
    """
    Send compliance notification via SNS
    """
    try:
        message = {
            'ami_id': ami_id,
            'compliance_issues': {
                'missing_tags': missing_tags,
                'approval_status': approval_status
            },
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': correlation_id
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'AMI Compliance Issue: {ami_id}',
            Message=json.dumps(message, indent=2)
        )
        
        logger.info("Compliance notification sent", extra={
            'ami_id': ami_id,
            'missing_tags_count': len(missing_tags),
            'approval_status': approval_status,
            'correlation_id': correlation_id
        })
    
    except Exception as e:
        logger.warning(f"Failed to send compliance notification: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })

def send_approval_notification(ami_id: str, correlation_id: str = None):
    """
    Send approval notification via SNS
    """
    try:
        message = {
            'ami_id': ami_id,
            'status': 'approved',
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': correlation_id
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'AMI Approved: {ami_id}',
            Message=json.dumps(message, indent=2)
        )
        
        logger.info("Approval notification sent", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'notification_type': 'approval'
        })
    
    except Exception as e:
        logger.warning(f"Failed to send approval notification: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })

def send_error_notification(error_message: str, correlation_id: str = None):
    """
    Send error notification via SNS
    """
    try:
        message = {
            'error': error_message,
            'timestamp': datetime.utcnow().isoformat(),
            'function': 'ami-event-processor',
            'correlation_id': correlation_id
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='AMI Lineage Processing Error',
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
