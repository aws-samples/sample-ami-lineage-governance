import json
import boto3
import os
import logging
import traceback
import re
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
        if hasattr(record, 'api_path'):
            log_entry['api_path'] = record.api_path
        if hasattr(record, 'http_method'):
            log_entry['http_method'] = record.http_method
            
        return json.dumps(log_entry)

# Apply structured formatter to logger
handler = logging.StreamHandler()
handler.setFormatter(StructuredFormatter())
logger.handlers = [handler]

# Environment variables
NEPTUNE_ENDPOINT = os.environ['NEPTUNE_ENDPOINT']
NEPTUNE_PORT = os.environ.get('NEPTUNE_PORT', '8182')

# Initialize AWS clients
ec2_client = boto3.client('ec2')
securityhub_client = boto3.client('securityhub')

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
    Main Lambda handler for API requests
    """
    correlation_id = context.aws_request_id if context else 'unknown'
    
    # Parse the API Gateway event
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    path_parameters = event.get('pathParameters') or {}
    query_parameters = event.get('queryStringParameters') or {}
    body = event.get('body')

    safe_path = re.sub(r'[\r\n\t]', '', str(path)[:100])
    safe_method = re.sub(r'[\r\n\t]', '', str(http_method)[:10])
    
    logger.info("Processing API request", extra={
        'correlation_id': correlation_id,
        'http_method': safe_method,
        'api_path': safe_path
    })
    
    try:
        if body:
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in request body", extra={
                    'correlation_id': correlation_id,
                    'api_path': path
                })
                return create_response(400, {'error': 'Invalid JSON in request body'})
        
        # Route the request
        if path.startswith('/api/v1/ami/') and path.endswith('/security-context'):
            return handle_security_context_request(path_parameters, query_parameters, correlation_id)
        elif path == '/api/v1/security-impact' and http_method == 'POST':
            return handle_security_impact_request(body, correlation_id)
        elif path == '/api/v1/compliance-assessment' and http_method == 'POST':
            return handle_compliance_assessment_request(body, correlation_id)
        elif path.startswith('/api/v1/ami/') and path.endswith('/lineage'):
            return handle_lineage_request(path_parameters, query_parameters, correlation_id)
        elif path == '/api/v1/ami/search' and http_method == 'POST':
            return handle_ami_search_request(body, correlation_id)
        else:
            logger.warning("Endpoint not found", extra={
                'correlation_id': correlation_id,
                'api_path': path,
                'http_method': http_method
            })
            return create_response(404, {'error': 'Endpoint not found'})
    
    except Exception as e:
        logger.error(f"Critical error processing API request: {str(e)}", extra={
            'correlation_id': correlation_id,
            'api_path': path,
            'http_method': http_method,
            'exception_type': type(e).__name__,
            'traceback': traceback.format_exc()
        })
        return create_response(500, {'error': 'Internal server error', 'correlation_id': correlation_id})

def handle_security_context_request(path_params: Dict, query_params: Dict, correlation_id: str):
    """
    Handle security context API requests
    """
    neptune_conn = NeptuneConnection()
    ami_id = path_params.get('ami_id')
    
    if not ami_id:
        logger.warning("AMI ID is required", extra={
            'correlation_id': correlation_id,
            'endpoint': 'security-context'
        })
        return create_response(400, {'error': 'AMI ID is required'})
    
    try:
        include_compliance = query_params.get('include_compliance', 'false').lower() == 'true'
        
        neptune_conn.connect()
        
        # Get AMI security context
        security_context = get_ami_security_context(neptune_conn.g, ami_id, include_compliance, correlation_id)
        
        if not security_context:
            logger.warning("AMI not found", extra={
                'ami_id': ami_id,
                'correlation_id': correlation_id
            })
            return create_response(404, {'error': 'AMI not found'})
        
        logger.info("Security context retrieved successfully", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'include_compliance': include_compliance
        })
        
        return create_response(200, security_context)
    
    except Exception as e:
        logger.warning(f"Failed to retrieve security context: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        return create_response(500, {'error': 'Failed to retrieve security context'})
    
    finally:
        neptune_conn.close()

def handle_security_impact_request(body: Dict):
    """
    Handle security impact assessment requests
    """
    neptune_conn = NeptuneConnection()
    
    try:
        if not body:
            return create_response(400, {'error': 'Request body is required'})
        
        ami_id = body.get('ami_id')
        finding_type = body.get('finding_type')
        finding_id = body.get('finding_id')
        severity = body.get('severity', 'MEDIUM')
        
        if not ami_id:
            return create_response(400, {'error': 'AMI ID is required'})
        
        neptune_conn.connect()
        
        # Assess security impact
        impact_assessment = assess_security_impact(neptune_conn.g, ami_id, finding_type, finding_id, severity)
        
        # Create Security Hub finding
        create_security_hub_finding(ami_id, finding_type, finding_id, severity, impact_assessment)
        
        return create_response(200, impact_assessment)
    
    except Exception as e:
        logger.error(f"Error handling security impact request: {str(e)}")
        return create_response(500, {'error': 'Failed to assess security impact'})
    
    finally:
        neptune_conn.close()

def handle_compliance_assessment_request(body: Dict):
    """
    Handle compliance assessment requests
    """
    neptune_conn = NeptuneConnection()
    
    try:
        if not body:
            return create_response(400, {'error': 'Request body is required'})
        
        rules = body.get('rules', [])
        scope = body.get('scope', 'ACCOUNT')
        
        neptune_conn.connect()
        
        # Perform compliance assessment
        compliance_results = perform_compliance_assessment(neptune_conn.g, rules, scope)
        
        return create_response(200, compliance_results)
    
    except Exception as e:
        logger.error(f"Error handling compliance assessment request: {str(e)}")
        return create_response(500, {'error': 'Failed to perform compliance assessment'})
    
    finally:
        neptune_conn.close()

def handle_lineage_request(path_params: Dict, query_params: Dict):
    """
    Handle AMI lineage requests
    """
    neptune_conn = NeptuneConnection()
    
    try:
        ami_id = path_params.get('ami_id')
        if not ami_id:
            return create_response(400, {'error': 'AMI ID is required'})
        
        direction = query_params.get('direction', 'both')  # ancestors, descendants, both
        depth = int(query_params.get('depth', '10'))
        
        neptune_conn.connect()
        
        # Get AMI lineage
        lineage_data = get_ami_lineage(neptune_conn.g, ami_id, direction, depth)
        
        return create_response(200, lineage_data)
    
    except Exception as e:
        logger.error(f"Error handling lineage request: {str(e)}")
        return create_response(500, {'error': 'Failed to retrieve AMI lineage'})
    
    finally:
        neptune_conn.close()

def handle_ami_search_request(body: Dict):
    """
    Handle AMI search requests
    """
    neptune_conn = NeptuneConnection()
    
    try:
        if not body:
            return create_response(400, {'error': 'Request body is required'})
        
        filters = body.get('filters', {})
        limit = body.get('limit', 100)
        
        neptune_conn.connect()
        
        # Search AMIs
        search_results = search_amis(neptune_conn.g, filters, limit)
        
        return create_response(200, search_results)
    
    except Exception as e:
        logger.error(f"Error handling AMI search request: {str(e)}")
        return create_response(500, {'error': 'Failed to search AMIs'})
    
    finally:
        neptune_conn.close()

def get_ami_security_context(g, ami_id: str, include_compliance: bool = False, correlation_id: str = None) -> Optional[Dict]:
    """
    Get comprehensive security context for an AMI
    """
    try:
        # Get AMI node data
        ami_data = g.V().has('ami', 'ami_id', ami_id).valueMap().toList()
        
        if not ami_data:
            return None
        
        ami_info = ami_data[0]
        
        # Get source validation information
        source_validation = validate_ami_source(ami_id, ami_info, correlation_id)
        
        # Get compliance status if requested
        compliance_status = {}
        if include_compliance:
            compliance_status = get_ami_compliance_status(g, ami_id, ami_info, correlation_id)
        
        # Get vulnerability status
        vulnerability_status = get_ami_vulnerability_status(ami_id, correlation_id)
        
        # Get lineage data
        lineage_data = get_basic_lineage_data(g, ami_id, correlation_id)
        
        return {
            'ami_id': ami_id,
            'security_context': {
                'source_validation': source_validation,
                'compliance_status': compliance_status,
                'vulnerability_status': vulnerability_status
            },
            'lineage_data': lineage_data,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.warning(f"Failed to get AMI security context: {str(e)}", extra={
            'ami_id': ami_id,
            'correlation_id': correlation_id,
            'exception_type': type(e).__name__
        })
        raise

def validate_ami_source(ami_id: str, ami_info: Dict) -> Dict:
    """
    Validate AMI source and authenticity
    """
    try:
        # Get AMI details from EC2 API
        response = ec2_client.describe_images(ImageIds=[ami_id])
        
        if not response['Images']:
            return {'marketplace_verified': False, 'trusted_account': False, 'approval_status': 'UNKNOWN'}
        
        ami_details = response['Images'][0]
        owner_id = ami_details.get('OwnerId', '')
        
        # Check if from AWS Marketplace
        marketplace_verified = owner_id in ['amazon', 'aws-marketplace'] or ami_details.get('ProductCodes', [])
        
        # Check if from trusted account (this would be configurable)
        trusted_accounts = os.environ.get('TRUSTED_ACCOUNTS', '').split(',')
        trusted_account = owner_id in trusted_accounts
        
        # Get approval status from tags or Neptune
        approval_status = 'UNKNOWN'
        if ami_info and 'approval_status' in ami_info:
            approval_status = ami_info['approval_status'][0] if isinstance(ami_info['approval_status'], list) else ami_info['approval_status']
        
        return {
            'marketplace_verified': marketplace_verified,
            'trusted_account': trusted_account,
            'approval_status': approval_status,
            'owner_id': owner_id
        }
    
    except Exception as e:
        logger.error(f"Error validating AMI source: {str(e)}")
        return {'marketplace_verified': False, 'trusted_account': False, 'approval_status': 'ERROR'}

def get_ami_compliance_status(g, ami_id: str, ami_info: Dict) -> Dict:
    """
    Get detailed compliance status for an AMI
    """
    try:
        compliance_status = {
            'patch_level': 'UNKNOWN',
            'encryption_verified': False,
            'policy_violations': []
        }
        
        # Check required tags
        required_tags = ['Creator', 'Source', 'ApprovalStatus', 'SecurityScan', 'Environment']
        missing_tags = []
        
        for tag in required_tags:
            if tag.lower() not in ami_info or not ami_info[tag.lower()]:
                missing_tags.append(tag)
        
        if missing_tags:
            compliance_status['policy_violations'].append({
                'type': 'missing_required_tags',
                'details': missing_tags
            })
        
        # Check security scan status
        security_scan = ami_info.get('security_scan', ['PENDING'])
        if isinstance(security_scan, list):
            security_scan = security_scan[0] if security_scan else 'PENDING'
        
        if security_scan != 'PASSED':
            compliance_status['policy_violations'].append({
                'type': 'security_scan_not_passed',
                'details': f'Security scan status: {security_scan}'
            })
        
        # Check approval status
        approval_status = ami_info.get('approval_status', ['PENDING'])
        if isinstance(approval_status, list):
            approval_status = approval_status[0] if approval_status else 'PENDING'
        
        if approval_status != 'Approved':
            compliance_status['policy_violations'].append({
                'type': 'not_approved',
                'details': f'Approval status: {approval_status}'
            })
        
        return compliance_status
    
    except Exception as e:
        logger.error(f"Error getting AMI compliance status: {str(e)}")
        return {'patch_level': 'ERROR', 'encryption_verified': False, 'policy_violations': []}

def get_ami_vulnerability_status(ami_id: str) -> Dict:
    """
    Get vulnerability status for an AMI
    """
    try:
        # This would integrate with vulnerability scanning services
        # For now, return basic structure
        return {
            'cve_findings': [],
            'last_scan_date': None,
            'scan_status': 'PENDING'
        }
    
    except Exception as e:
        logger.error(f"Error getting AMI vulnerability status: {str(e)}")
        return {'cve_findings': [], 'last_scan_date': None, 'scan_status': 'ERROR'}

def get_basic_lineage_data(g, ami_id: str) -> Dict:
    """
    Get basic lineage information for an AMI
    """
    try:
        # Get parent AMIs (source AMIs)
        parents = g.V().has('ami', 'ami_id', ami_id).in_().hasLabel('ami').valueMap('ami_id', 'name', 'creation_date').toList()
        
        # Get child AMIs (derived AMIs)
        children = g.V().has('ami', 'ami_id', ami_id).out().hasLabel('ami').valueMap('ami_id', 'name', 'creation_date').toList()
        
        # Get instances using this AMI
        instances = g.V().has('ami', 'ami_id', ami_id).in_().hasLabel('instance').valueMap('instance_id', 'launch_time', 'state').toList()
        
        return {
            'parent_amis': parents,
            'child_amis': children,
            'instances': instances
        }
    
    except Exception as e:
        logger.error(f"Error getting basic lineage data: {str(e)}")
        return {'parent_amis': [], 'child_amis': [], 'instances': []}

def assess_security_impact(g, ami_id: str, finding_type: str, finding_id: str, severity: str) -> Dict:
    """
    Assess security impact of a finding on an AMI and its lineage
    """
    try:
        # Get all AMIs derived from the affected AMI
        affected_amis = g.V().has('ami', 'ami_id', ami_id).repeat(__.out().hasLabel('ami')).emit().valueMap('ami_id', 'account_id', 'region').toList()
        
        # Include the original AMI
        original_ami = g.V().has('ami', 'ami_id', ami_id).valueMap('ami_id', 'account_id', 'region').toList()
        affected_amis.extend(original_ami)
        
        # Get all instances using affected AMIs
        affected_instances = []
        for ami in affected_amis:
            ami_id_val = ami['ami_id'][0] if isinstance(ami['ami_id'], list) else ami['ami_id']
            instances = g.V().has('ami', 'ami_id', ami_id_val).in_().hasLabel('instance').valueMap('instance_id', 'account_id', 'region', 'state').toList()
            affected_instances.extend(instances)
        
        # Get Auto Scaling Groups and Launch Templates (would require additional data collection)
        # For now, return basic structure
        
        remediation_steps = generate_remediation_steps(finding_type, severity, len(affected_amis), len(affected_instances))
        
        return {
            'affected_resources': {
                'amis': affected_amis,
                'instances': affected_instances,
                'auto_scaling_groups': [],  # Would be populated with real data
                'launch_templates': []      # Would be populated with real data
            },
            'impact_summary': {
                'total_affected_amis': len(affected_amis),
                'total_affected_instances': len(affected_instances),
                'severity': severity,
                'finding_type': finding_type,
                'finding_id': finding_id
            },
            'remediation_steps': remediation_steps
        }
    
    except Exception as e:
        logger.warning(f"Error assessing security impact: {str(e)}")
        raise

def generate_remediation_steps(finding_type: str, severity: str, ami_count: int, instance_count: int) -> List[str]:
    """
    Generate remediation steps based on finding type and severity
    """
    steps = []
    
    if severity in ['CRITICAL', 'HIGH']:
        steps.append("Immediately stop affected instances if possible")
        steps.append("Block deployment of affected AMIs using SCPs")
    
    steps.extend([
        f"Update {ami_count} affected AMIs with security patches",
        "Create new AMI versions with fixes applied",
        "Update launch templates with new AMI IDs",
        f"Replace {instance_count} affected instances",
        "Update Auto Scaling Groups with new launch templates",
        "Verify remediation through security scanning"
    ])
    
    return steps

def perform_compliance_assessment(g, rules: List[str], scope: str) -> Dict:
    """
    Perform comprehensive compliance assessment
    """
    try:
        # Get all AMIs based on scope
        if scope == 'ORGANIZATION':
            amis = g.V().hasLabel('ami').valueMap().toList()
        else:
            # Default to current account
            current_account = os.environ.get('AWS_ACCOUNT_ID', '')
            amis = g.V().hasLabel('ami').has('account_id', current_account).valueMap().toList()
        
        total_amis = len(amis)
        rule_results = {}
        non_compliant_resources = []
        
        for rule in rules:
            compliant_count = 0
            
            for ami in amis:
                ami_id = ami['ami_id'][0] if isinstance(ami['ami_id'], list) else ami['ami_id']
                is_compliant = evaluate_compliance_rule(ami, rule)
                
                if is_compliant:
                    compliant_count += 1
                else:
                    # Add to non-compliant resources
                    account_id = ami.get('account_id', [''])[0] if isinstance(ami.get('account_id', ['']), list) else ami.get('account_id', '')
                    region = ami.get('region', [''])[0] if isinstance(ami.get('region', ['']), list) else ami.get('region', '')
                    
                    existing_resource = next((r for r in non_compliant_resources if r['ami_id'] == ami_id), None)
                    if existing_resource:
                        existing_resource['violations'].append(rule)
                    else:
                        non_compliant_resources.append({
                            'ami_id': ami_id,
                            'account_id': account_id,
                            'region': region,
                            'violations': [rule]
                        })
            
            rule_results[rule] = {
                'compliant': compliant_count,
                'non_compliant': total_amis - compliant_count
            }
        
        # Calculate overall compliance
        compliant_amis = len([ami for ami in amis if all(evaluate_compliance_rule(ami, rule) for rule in rules)])
        compliance_percentage = (compliant_amis / total_amis * 100) if total_amis > 0 else 0
        
        return {
            'compliance_summary': {
                'total_amis': total_amis,
                'compliant_amis': compliant_amis,
                'non_compliant_amis': total_amis - compliant_amis,
                'compliance_percentage': round(compliance_percentage, 2)
            },
            'rule_results': rule_results,
            'non_compliant_resources': non_compliant_resources
        }
    
    except Exception as e:
        logger.warning(f"Error performing compliance assessment: {str(e)}")
        raise

def evaluate_compliance_rule(ami: Dict, rule: str) -> bool:
    """
    Evaluate a specific compliance rule for an AMI
    """
    try:
        if rule == 'required_tags':
            required_tags = ['creator', 'source', 'approval_status', 'security_scan', 'environment']
            return all(tag in ami and ami[tag] for tag in required_tags)
        
        elif rule == 'approved_source_validation':
            approval_status = ami.get('approval_status', [''])[0] if isinstance(ami.get('approval_status', ['']), list) else ami.get('approval_status', '')
            return approval_status == 'Approved'
        
        elif rule == 'security_scan_status':
            security_scan = ami.get('security_scan', [''])[0] if isinstance(ami.get('security_scan', ['']), list) else ami.get('security_scan', '')
            return security_scan == 'PASSED'
        
        elif rule == 'naming_convention':
            name = ami.get('name', [''])[0] if isinstance(ami.get('name', ['']), list) else ami.get('name', '')
            # Example naming convention check
            return bool(name and len(name) > 5)
        
        elif rule == 'lineage_verification':
            # Check if AMI has proper lineage information
            return 'creation_method' in ami and ami['creation_method']
        
        else:
            logger.warning(f"Unknown compliance rule: {rule}")
            return False
    
    except Exception as e:
        logger.error(f"Error evaluating compliance rule {rule}: {str(e)}")
        return False

def get_ami_lineage(g, ami_id: str, direction: str, depth: int) -> Dict:
    """
    Get comprehensive AMI lineage information
    """
    try:
        lineage_data = {
            'ami_id': ami_id,
            'ancestors': [],
            'descendants': [],
            'lineage_graph': []
        }
        
        if direction in ['ancestors', 'both']:
            # Get ancestor AMIs
            ancestors = g.V().has('ami', 'ami_id', ami_id).repeat(__.in_().hasLabel('ami')).times(depth).emit().path().toList()
            lineage_data['ancestors'] = process_lineage_paths(ancestors)
        
        if direction in ['descendants', 'both']:
            # Get descendant AMIs
            descendants = g.V().has('ami', 'ami_id', ami_id).repeat(__.out().hasLabel('ami')).times(depth).emit().path().toList()
            lineage_data['descendants'] = process_lineage_paths(descendants)
        
        return lineage_data
    
    except Exception as e:
        logger.warning(f"Error getting AMI lineage: {str(e)}")
        raise

def process_lineage_paths(paths: List) -> List[Dict]:
    """
    Process lineage paths from Neptune query results
    """
    processed_paths = []
    
    for path in paths:
        path_data = []
        for vertex in path:
            if hasattr(vertex, 'valueMap'):
                vertex_data = vertex.valueMap()
                path_data.append({
                    'ami_id': vertex_data.get('ami_id', [''])[0],
                    'name': vertex_data.get('name', [''])[0],
                    'creation_date': vertex_data.get('creation_date', [''])[0]
                })
        
        if path_data:
            processed_paths.append(path_data)
    
    return processed_paths

def search_amis(g, filters: Dict, limit: int) -> Dict:
    """
    Search AMIs based on filters
    """
    try:
        # Start with all AMI vertices
        query = g.V().hasLabel('ami')
        
        # Apply filters
        for key, value in filters.items():
            if key == 'approval_status':
                query = query.has('approval_status', value)
            elif key == 'security_scan':
                query = query.has('security_scan', value)
            elif key == 'account_id':
                query = query.has('account_id', value)
            elif key == 'region':
                query = query.has('region', value)
            elif key == 'environment':
                query = query.has('environment', value)
            elif key == 'name_contains':
                query = query.has('name', P.containing(value))
        
        # Execute query with limit
        results = query.limit(limit).valueMap().toList()
        
        return {
            'total_results': len(results),
            'amis': results,
            'filters_applied': filters
        }
    
    except Exception as e:
        logger.warning(f"Error searching AMIs: {str(e)}")
        raise

def create_security_hub_finding(ami_id: str, finding_type: str, finding_id: str, severity: str, impact_assessment: Dict):
    """
    Create a Security Hub finding for the security impact
    """
    try:
        finding = {
            'SchemaVersion': '2018-10-08',
            'Id': f'ami-lineage/{ami_id}/{finding_id}',
            'ProductArn': f'arn:aws:securityhub:{os.environ.get("AWS_REGION")}:{os.environ.get("AWS_ACCOUNT_ID")}:product/{os.environ.get("AWS_ACCOUNT_ID")}/default',
            'GeneratorId': 'ami-lineage-governance',
            'AwsAccountId': os.environ.get('AWS_ACCOUNT_ID'),
            'Types': ['Sensitive Data Identifications/PII'],
            'FirstObservedAt': datetime.utcnow().isoformat() + 'Z',
            'LastObservedAt': datetime.utcnow().isoformat() + 'Z',
            'CreatedAt': datetime.utcnow().isoformat() + 'Z',
            'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
            'Severity': {
                'Label': severity
            },
            'Title': f'AMI Security Impact Assessment: {finding_id}',
            'Description': f'Security finding {finding_id} affects AMI {ami_id} and its lineage',
            'Resources': [
                {
                    'Type': 'AwsEc2Image',
                    'Id': f'arn:aws:ec2:{os.environ.get("AWS_REGION")}:{os.environ.get("AWS_ACCOUNT_ID")}:image/{ami_id}',
                    'Region': os.environ.get('AWS_REGION'),
                    'Details': {
                        'Other': {
                            'AffectedAMIs': str(impact_assessment['impact_summary']['total_affected_amis']),
                            'AffectedInstances': str(impact_assessment['impact_summary']['total_affected_instances'])
                        }
                    }
                }
            ]
        }
        
        securityhub_client.batch_import_findings(Findings=[finding])
        logger.info(f"Created Security Hub finding for AMI: {ami_id}")
    
    except Exception as e:
        logger.error(f"Error creating Security Hub finding: {str(e)}")

def create_response(status_code: int, body: Dict) -> Dict:
    """
    Create API Gateway response
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        },
        'body': json.dumps(body, default=str)
    }
