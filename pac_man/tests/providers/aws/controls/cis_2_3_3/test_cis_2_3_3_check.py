import pytest
from unittest.mock import Mock, patch
from providers.aws.lib.check_result import CheckResult
from providers.aws.controls.cis_2_3_3.cis_2_3_3_check import execute, CHECK_ID, CHECK_DESCRIPTION

@pytest.fixture
def mock_ec2_service():
    return Mock()

@pytest.fixture
def mock_rds_service():
    return Mock()

@pytest.fixture
def mock_service_factory(mock_ec2_service, mock_rds_service):
    factory = Mock()
    factory.get_service.side_effect = lambda service, region=None: {
        'ec2': mock_ec2_service,
        'rds': mock_rds_service
    }[service]
    return factory

@pytest.fixture
def mock_logger():
    return Mock()

def test_execute_no_instances(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.list_active_regions.return_value = {'success': True, 'regions': ['us-west-1']}
    
    mock_rds_service = mock_service_factory.get_service('rds')
    mock_rds_service.describe_db_instances.return_value = []
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[0].status_extended == "No RDS instances found in any region"
    assert results[0].check_id == CHECK_ID
    assert results[0].check_description == CHECK_DESCRIPTION

def test_execute_private_instance(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.list_active_regions.return_value = {'success': True, 'regions': ['us-west-1']}
    
    mock_rds_service = mock_service_factory.get_service('rds')
    mock_rds_service.describe_db_instances.return_value = [{
        'DBInstanceIdentifier': 'test-db',
        'DBInstanceArn': 'arn:aws:rds:us-west-1:123456789012:db:test-db',
        'PubliclyAccessible': False
    }]
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert "is not publicly accessible" in results[0].status_extended
    assert results[0].resource_id == 'test-db'
    assert results[0].resource_arn == 'arn:aws:rds:us-west-1:123456789012:db:test-db'
    assert results[0].region == 'us-west-1'

def test_execute_public_instance(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.list_active_regions.return_value = {'success': True, 'regions': ['us-west-1']}
    
    mock_rds_service = mock_service_factory.get_service('rds')
    mock_rds_service.describe_db_instances.return_value = [{
        'DBInstanceIdentifier': 'test-db',
        'DBInstanceArn': 'arn:aws:rds:us-west-1:123456789012:db:test-db',
        'PubliclyAccessible': True
    }]
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "is publicly accessible" in results[0].status_extended
    assert results[0].resource_id == 'test-db'
    assert results[0].resource_arn == 'arn:aws:rds:us-west-1:123456789012:db:test-db'
    assert results[0].region == 'us-west-1'

def test_execute_multiple_regions(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.list_active_regions.return_value = {'success': True, 'regions': ['us-west-1', 'us-east-1']}
    
    mock_rds_service = mock_service_factory.get_service('rds')
    mock_rds_service.describe_db_instances.side_effect = [
        [{
            'DBInstanceIdentifier': 'test-db-1',
            'DBInstanceArn': 'arn:aws:rds:us-west-1:123456789012:db:test-db-1',
            'PubliclyAccessible': False
        }],
        [{
            'DBInstanceIdentifier': 'test-db-2',
            'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:test-db-2',
            'PubliclyAccessible': True
        }]
    ]
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 2
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[1].status == CheckResult.STATUS_FAIL
    assert results[0].region == 'us-west-1'
    assert results[1].region == 'us-east-1'

def test_execute_error_listing_regions(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.list_active_regions.return_value = {'success': False, 'error_message': 'Test error'}
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "Error executing check" in results[0].status_extended
    assert "Test error" in results[0].status_extended

def test_execute_error_describing_instances(mock_service_factory, mock_logger):
    mock_ec2_service = mock_service_factory.get_service('ec2')
    mock_ec2_service.list_active_regions.return_value = {'success': True, 'regions': ['us-west-1']}
    
    mock_rds_service = mock_service_factory.get_service('rds')
    mock_rds_service.describe_db_instances.side_effect = Exception("Test error")
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "Error executing check" in results[0].status_extended
    assert "Test error" in results[0].status_extended
