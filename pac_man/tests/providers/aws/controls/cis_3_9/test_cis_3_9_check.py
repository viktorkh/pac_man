import pytest
from unittest.mock import Mock, patch
from providers.aws.lib.check_result import CheckResult
from providers.aws.controls.cis_3_9.cis_3_9_check import check_vpc_flow_logging, execute, CHECK_ID, CHECK_DESCRIPTION

@pytest.fixture
def mock_ec2_service():
    return Mock()

@pytest.fixture
def mock_service_factory(mock_ec2_service):
    factory = Mock()
    factory.get_service.return_value = mock_ec2_service
    return factory

@pytest.fixture
def mock_logger():
    return Mock()

def test_check_vpc_flow_logging_pass(mock_ec2_service, mock_logger):
    mock_ec2_service.describe_flow_logs.return_value = {'success': True, 'FlowLogs': [{}]}
    result = check_vpc_flow_logging(mock_ec2_service, 'vpc-12345678', mock_logger)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "VPC flow logging is enabled" in result.status_extended
    assert result.resource_id == 'vpc-12345678'

def test_check_vpc_flow_logging_fail(mock_ec2_service, mock_logger):
    mock_ec2_service.describe_flow_logs.return_value = {'success': True, 'FlowLogs': []}
    result = check_vpc_flow_logging(mock_ec2_service, 'vpc-12345678', mock_logger)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "VPC flow logging is not enabled" in result.status_extended

def test_check_vpc_flow_logging_error(mock_ec2_service, mock_logger):
    mock_ec2_service.describe_flow_logs.side_effect = Exception("Test error")
    result = check_vpc_flow_logging(mock_ec2_service, 'vpc-12345678', mock_logger)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "Error checking VPC flow logging" in result.status_extended
    mock_logger.error.assert_called_once()

def test_execute_success(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {
        'success': True,
        'Vpcs': [{'VpcId': 'vpc-12345678'}]
    }
    mock_ec2_service.describe_flow_logs.return_value = {'success': True, 'FlowLogs': [{}]}
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[0].resource_id == 'vpc-12345678'

def test_execute_no_vpcs(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {
        'success': True,
        'Vpcs': []
    }
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 0

def test_execute_multiple_vpcs(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.describe_vpcs.return_value = {
        'success': True,
        'Vpcs': [{'VpcId': 'vpc-1'}, {'VpcId': 'vpc-2'}]
    }
    mock_ec2_service.describe_flow_logs.side_effect = [
        {'success': True, 'FlowLogs': [{}]},
        {'success': True, 'FlowLogs': []}
    ]
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 2
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[1].status == CheckResult.STATUS_FAIL
