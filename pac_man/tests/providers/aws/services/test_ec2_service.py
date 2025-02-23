"""Unit tests for EC2Service."""

import pytest
from unittest.mock import MagicMock, patch
from providers.aws.services.ec2_service import EC2Service

@pytest.fixture
def ec2_service():
    """Create EC2Service instance with mocked session."""
    mock_session = MagicMock()
    return EC2Service(mock_session)

def test_revoke_security_group_ingress_success(ec2_service):
    ec2_service.client.revoke_security_group_ingress.return_value = {}
    result = ec2_service.revoke_security_group_ingress(GroupId='sg-12345678')
    assert result['success'] is True

def test_revoke_security_group_ingress_error(ec2_service):
    ec2_service.client.revoke_security_group_ingress.side_effect = Exception("Error")
    result = ec2_service.revoke_security_group_ingress(GroupId='sg-12345678')
    assert result['success'] is False
    assert 'error_message' in result

def test_revoke_security_group_egress_success(ec2_service):
    ec2_service.client.revoke_security_group_egress.return_value = {}
    result = ec2_service.revoke_security_group_egress(GroupId='sg-12345678')
    assert result['success'] is True

def test_revoke_security_group_egress_error(ec2_service):
    ec2_service.client.revoke_security_group_egress.side_effect = Exception("Error")
    result = ec2_service.revoke_security_group_egress(GroupId='sg-12345678')
    assert result['success'] is False
    assert 'error_message' in result

def test_authorize_security_group_ingress_success(ec2_service):
    ec2_service.client.authorize_security_group_ingress.return_value = {}
    result = ec2_service.authorize_security_group_ingress(GroupId='sg-12345678')
    assert result['success'] is True

def test_authorize_security_group_ingress_error(ec2_service):
    ec2_service.client.authorize_security_group_ingress.side_effect = Exception("Error")
    result = ec2_service.authorize_security_group_ingress(GroupId='sg-12345678')
    assert result['success'] is False
    assert 'error_message' in result

def test_authorize_security_group_egress_success(ec2_service):
    ec2_service.client.authorize_security_group_egress.return_value = {}
    result = ec2_service.authorize_security_group_egress(GroupId='sg-12345678')
    assert result['success'] is True

def test_authorize_security_group_egress_error(ec2_service):
    ec2_service.client.authorize_security_group_egress.side_effect = Exception("Error")
    result = ec2_service.authorize_security_group_egress(GroupId='sg-12345678')
    assert result['success'] is False
    assert 'error_message' in result
def test_list_active_regions_success(ec2_service):
    ec2_service.client.describe_regions.return_value = {
        'Regions': [
            {'RegionName': 'us-east-1', 'OptInStatus': 'opt-in-not-required'},
            {'RegionName': 'us-west-2', 'OptInStatus': 'opted-in'},
            {'RegionName': 'eu-west-1', 'OptInStatus': 'not-opted-in'}
        ]
    }
    result = ec2_service.list_active_regions()
    assert result['success'] is True
    assert result['regions'] == ['us-east-1', 'us-west-2']

def test_list_active_regions_error(ec2_service):
    ec2_service.client.describe_regions.side_effect = Exception("Error")
    result = ec2_service.list_active_regions()
    assert result['success'] is False
    assert 'error_message' in result

def test_describe_flow_logs_success(ec2_service):
    ec2_service.client.describe_flow_logs.return_value = {
        'FlowLogs': [{'FlowLogId': 'fl-12345'}]
    }
    result = ec2_service.describe_flow_logs()
    assert result['success'] is True
    assert result['FlowLogs'][0]['FlowLogId'] == 'fl-12345'

def test_describe_flow_logs_error(ec2_service):
    ec2_service.client.describe_flow_logs.side_effect = Exception("Error")
    result = ec2_service.describe_flow_logs()
    assert result['success'] is False
    assert 'error_message' in result

def test_describe_vpcs_success(ec2_service):
    ec2_service.client.describe_vpcs.return_value = {
        'Vpcs': [{'VpcId': 'vpc-12345'}]
    }
    result = ec2_service.describe_vpcs()
    assert result['success'] is True
    assert result['Vpcs'][0]['VpcId'] == 'vpc-12345'

def test_describe_vpcs_error(ec2_service):
    ec2_service.client.describe_vpcs.side_effect = Exception("Error")
    result = ec2_service.describe_vpcs()
    assert result['success'] is False
    assert 'error_message' in result

def test_create_flow_logs_success(ec2_service):
    ec2_service.client.create_flow_logs.return_value = {
        'FlowLogIds': ['fl-12345']
    }
    result = ec2_service.create_flow_logs(
        ResourceIds=['vpc-12345'],
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs',
        DeliverLogsPermissionArn='arn:aws:iam::123456789012:role/FlowLogRole',
        LogGroupName='VPCFlowLogs'
    )
    assert result['success'] is True
    assert result['FlowLogIds'][0] == 'fl-12345'

def test_create_flow_logs_error(ec2_service):
    ec2_service.client.create_flow_logs.side_effect = Exception("Error")
    result = ec2_service.create_flow_logs(
        ResourceIds=['vpc-12345'],
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs',
        DeliverLogsPermissionArn='arn:aws:iam::123456789012:role/FlowLogRole',
        LogGroupName='VPCFlowLogs'
    )
    assert result['success'] is False
    assert 'error_message' in result

def test_is_subnet_public_with_igw(ec2_service):
    ec2_service.session.client().describe_route_tables.return_value = {
        'RouteTables': [{
            'Routes': [{'GatewayId': 'igw-12345'}]
        }]
    }
    assert ec2_service.is_subnet_public('subnet-12345', 'vpc-12345') is True

def test_is_subnet_public_without_igw(ec2_service):
    ec2_service.session.client().describe_route_tables.return_value = {
        'RouteTables': [{
            'Routes': [{'GatewayId': 'local'}]
        }]
    }
    assert ec2_service.is_subnet_public('subnet-12345', 'vpc-12345') is False

def test_is_subnet_public_no_route_table(ec2_service):
    ec2_service.session.client().describe_route_tables.return_value = {
        'RouteTables': []
    }
    assert ec2_service.is_subnet_public('subnet-12345', 'vpc-12345') is False

def test_describe_security_groups_success(ec2_service):
    ec2_service.client.describe_security_groups.return_value = {
        'SecurityGroups': [{'GroupId': 'sg-12345'}]
    }
    result = ec2_service.describe_security_groups()
    assert result['success'] is True
    assert result['SecurityGroups'][0]['GroupId'] == 'sg-12345'

def test_describe_security_groups_error(ec2_service):
    ec2_service.client.describe_security_groups.side_effect = Exception("Error")
    result = ec2_service.describe_security_groups()
    assert result['success'] is False
    assert 'error_message' in result

def test_update_security_group_rules_ingress(ec2_service):
    ec2_service.client.revoke_security_group_ingress.return_value = {}
    ec2_service.client.authorize_security_group_ingress.return_value = {}
    ec2_service.update_security_group_rules('sg-12345', [], 'ingress')
    ec2_service.client.revoke_security_group_ingress.assert_called_once()
    ec2_service.client.authorize_security_group_ingress.assert_called_once()

def test_update_security_group_rules_egress(ec2_service):
    ec2_service.client.revoke_security_group_egress.return_value = {}
    ec2_service.client.authorize_security_group_egress.return_value = {}
    ec2_service.update_security_group_rules('sg-12345', [], 'egress')
    ec2_service.client.revoke_security_group_egress.assert_called_once()
    ec2_service.client.authorize_security_group_egress.assert_called_once()
