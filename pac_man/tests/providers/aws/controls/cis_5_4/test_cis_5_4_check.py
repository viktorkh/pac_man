import pytest
from unittest.mock import Mock, patch
from providers.aws.lib.check_result import CheckResult
from providers.aws.controls.cis_5_4.cis_5_4_check import execute, CHECK_ID, CHECK_DESCRIPTION

@pytest.fixture
def mock_ec2_service():
    return Mock()

@pytest.fixture
def mock_sts_service():
    return Mock()

@pytest.fixture
def mock_service_factory(mock_ec2_service, mock_sts_service):
    factory = Mock()
    factory.get_service.side_effect = lambda service: {
        'ec2': mock_ec2_service,
        'sts': mock_sts_service
    }[service]
    return factory

@pytest.fixture
def mock_session():
    session = Mock()
    session.region_name = 'us-west-2'
    return session

@pytest.fixture
def mock_logger():
    return Mock()

def test_execute_no_vpcs(mock_service_factory, mock_session, mock_logger):
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {'success': True, 'account_id': '123456789012'}
    
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {'success': True, 'Vpcs': []}
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[0].resource_id == "NoVPCs"
    assert "No VPCs found in the account" in results[0].status_extended

def test_execute_vpc_with_compliant_sg(mock_service_factory, mock_session, mock_logger):
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {'success': True, 'account_id': '123456789012'}
    
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {'success': True, 'Vpcs': [{'VpcId': 'vpc-12345'}]}
    mock_ec2_service.describe_security_groups.return_value = {
        'success': True,
        'SecurityGroups': [{'GroupId': 'sg-12345', 'IpPermissions': [], 'IpPermissionsEgress': []}]
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[0].resource_id == "sg-12345"
    assert "restricts all traffic" in results[0].status_extended

def test_execute_vpc_with_non_compliant_sg(mock_service_factory, mock_session, mock_logger):
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {'success': True, 'account_id': '123456789012'}
    
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {'success': True, 'Vpcs': [{'VpcId': 'vpc-12345'}]}
    mock_ec2_service.describe_security_groups.return_value = {
        'success': True,
        'SecurityGroups': [{'GroupId': 'sg-12345', 'IpPermissions': [{'IpProtocol': '-1'}], 'IpPermissionsEgress': []}]
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert results[0].resource_id == "sg-12345"
    assert "has inbound or outbound rules" in results[0].status_extended

def test_execute_multiple_vpcs(mock_service_factory, mock_session, mock_logger):
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {'success': True, 'account_id': '123456789012'}
    
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {'success': True, 'Vpcs': [{'VpcId': 'vpc-1'}, {'VpcId': 'vpc-2'}]}
    mock_ec2_service.describe_security_groups.side_effect = [
        {'success': True, 'SecurityGroups': [{'GroupId': 'sg-1', 'IpPermissions': [], 'IpPermissionsEgress': []}]},
        {'success': True, 'SecurityGroups': [{'GroupId': 'sg-2', 'IpPermissions': [{'IpProtocol': '-1'}], 'IpPermissionsEgress': []}]}
    ]
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 2
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[1].status == CheckResult.STATUS_FAIL

def test_execute_error_getting_vpcs(mock_service_factory, mock_session, mock_logger):
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {'success': True, 'account_id': '123456789012'}
    
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {'success': False, 'error_message': 'API error'}
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "Failed to describe VPCs" in results[0].status_extended

def test_execute_error_getting_security_groups(mock_service_factory, mock_session, mock_logger):
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {'success': True, 'account_id': '123456789012'}
    
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {'success': True, 'Vpcs': [{'VpcId': 'vpc-12345'}]}
    mock_ec2_service.describe_security_groups.return_value = {'success': False, 'error_message': 'API error'}
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "Failed to describe security groups" in results[0].status_extended

