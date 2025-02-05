"""Unit tests for CIS 3.5 check."""

import pytest
from unittest.mock import MagicMock, call
from providers.aws.controls.cis_3_5.cis_3_5_check import execute, create_error_result

@pytest.fixture
def mock_session():
    """Create mock session."""
    return MagicMock()

@pytest.fixture
def mock_logger():
    """Create mock logger."""
    return MagicMock()

@pytest.fixture
def mock_service_factory():
    """Create mock service factory with required services."""
    factory = MagicMock()
    return factory

@pytest.fixture
def mock_config_recorder():
    """Create mock config recorder response."""
    return {
        'name': 'default',
        'roleARN': 'arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig',
        'recordingGroup': {
            'allSupported': True,
            'includeGlobalResourceTypes': True
        }
    }

@pytest.fixture
def mock_recorder_status():
    """Create mock recorder status response."""
    return {
        'name': 'default',
        'recording': True,
        'lastStatus': 'SUCCESS'
    }

def test_execute_all_regions_compliant(mock_session, mock_logger, mock_service_factory, mock_config_recorder, mock_recorder_status):
    """Test when all regions have properly configured AWS Config."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1', 'us-west-2']
    }
    
    # Mock Config service response
    mock_config = MagicMock()
    mock_config.describe_configuration_recorders.return_value = {
        'success': True,
        'configuration_recorders': [mock_config_recorder]
    }
    mock_config.describe_configuration_recorder_status.return_value = {
        'success': True,
        'recorder_statuses': [mock_recorder_status]
    }
    
    # Configure service factory
    def get_service_side_effect(service_name, region=None):
        if service_name == 'ec2':
            return mock_ec2
        return mock_config
    
    mock_service_factory.get_service.side_effect = get_service_side_effect
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 2  # One result per region
    for result in results:
        assert result.status == "PASS"
        assert "properly configured" in result.status_extended
        assert result.check_id == "cis_3_5"
        assert "AWS Config Recorder" in result.resource_id

def test_execute_no_config_recorder(mock_session, mock_logger, mock_service_factory):
    """Test when regions have no config recorder."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Mock Config service response with no recorders
    mock_config = MagicMock()
    mock_config.describe_configuration_recorders.return_value = {
        'success': True,
        'configuration_recorders': []
    }
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_config]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert "not configured" in results[0].status_extended

def test_execute_improperly_configured(mock_session, mock_logger, mock_service_factory, mock_config_recorder):
    """Test when config recorder exists but is not properly configured."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Modify recorder for improper configuration
    improper_recorder = mock_config_recorder.copy()
    improper_recorder['recordingGroup']['allSupported'] = False
    
    # Mock Config service response
    mock_config = MagicMock()
    mock_config.describe_configuration_recorders.return_value = {
        'success': True,
        'configuration_recorders': [improper_recorder]
    }
    mock_config.describe_configuration_recorder_status.return_value = {
        'success': True,
        'recorder_statuses': [{
            'name': 'default',
            'recording': False,
            'lastStatus': 'FAILURE'
        }]
    }
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_config]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert "not properly configured" in results[0].status_extended

def test_execute_region_listing_error(mock_session, mock_logger, mock_service_factory):
    """Test handling of error when listing regions."""
    # Mock EC2 service error
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': False,
        'error_message': 'Failed to list regions'
    }
    
    # Configure service factory
    mock_service_factory.get_service.return_value = mock_ec2
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "ERROR"
    assert "Error listing active regions" in results[0].status_extended
    
    # Verify logger was called
    mock_logger.error.assert_called_once_with("Error listing active regions: Failed to list regions")

def test_execute_config_recorder_error(mock_session, mock_logger, mock_service_factory):
    """Test handling of error when checking config recorder."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Mock Config service error
    mock_config = MagicMock()
    mock_config.describe_configuration_recorders.return_value = {
        'success': False,
        'error_message': 'Failed to describe config recorders'
    }
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_config]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "ERROR"
    assert "Error checking AWS Config" in results[0].status_extended
    assert "Failed to describe config recorders" in results[0].status_extended

def test_execute_general_exception(mock_session, mock_logger, mock_service_factory):
    """Test handling of general exceptions during execution."""
    # Mock service factory to raise an exception
    mock_service_factory.get_service.side_effect = Exception("Unexpected error occurred")
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "ERROR"
    assert "Error executing check" in results[0].status_extended
    assert "Unexpected error occurred" in results[0].status_extended
    
    # Verify logger was called
    mock_logger.error.assert_called_once_with(
        "Error executing CIS 3.5 check: Unexpected error occurred"
    )

def test_create_error_result():
    """Test creation of error result."""
    error_message = "Test error message"
    result = create_error_result(error_message)
    
    assert result.check_id == "cis_3_5"
    assert result.status == "ERROR"
    assert result.status_extended == error_message
