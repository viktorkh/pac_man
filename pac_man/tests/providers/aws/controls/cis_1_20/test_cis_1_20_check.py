"""Unit tests for CIS 1.20 check."""

import pytest
from unittest.mock import MagicMock, call
from providers.aws.controls.cis_1_20.cis_1_20_check import execute, create_error_result

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
def mock_active_analyzer():
    """Create mock active analyzer response."""
    return {
        'arn': 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test',
        'name': 'test-analyzer',
        'status': 'ACTIVE',
        'tags': {'Environment': 'Production'}
    }

def test_execute_all_regions_compliant(mock_session, mock_logger, mock_service_factory, mock_active_analyzer):
    """Test when all regions have active analyzers."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1', 'us-west-2']
    }
    
    # Mock Access Analyzer service response
    mock_analyzer = MagicMock()
    mock_analyzer.list_analyzers.return_value = {
        'success': True,
        'analyzers': [mock_active_analyzer]
    }
    
    # Configure service factory to return appropriate mocks
    def get_service_side_effect(service_name, region=None):
        if service_name == 'ec2':
            return mock_ec2
        return mock_analyzer
    
    mock_service_factory.get_service.side_effect = get_service_side_effect
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 2  # One result per region
    for result in results:
        assert result.status == "PASS"
        assert "is enabled" in result.status_extended
        assert result.check_id == "cis_1_20"
        assert result.resource_id == mock_active_analyzer['name']
        assert result.resource_arn == mock_active_analyzer['arn']
        assert result.resource_tags == mock_active_analyzer['tags']
        assert result.resource_details == {"total_regions": 2}

    # Verify logger calls
    mock_logger.info.assert_has_calls([
        call("Found 2 active regions"),
        call(f"Active analyzer found in region us-east-1: {mock_active_analyzer['name']}"),
        call(f"Active analyzer found in region us-west-2: {mock_active_analyzer['name']}")
    ])

def test_execute_partial_compliance(mock_session, mock_logger, mock_service_factory, mock_active_analyzer):
    """Test when some regions are compliant and others are not."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1', 'us-west-2']
    }
    
    # Mock Access Analyzer service responses
    mock_analyzer_east = MagicMock()
    mock_analyzer_east.list_analyzers.return_value = {
        'success': True,
        'analyzers': [mock_active_analyzer]
    }
    
    mock_analyzer_west = MagicMock()
    mock_analyzer_west.list_analyzers.return_value = {
        'success': True,
        'analyzers': []
    }
    
    # Configure service factory
    def get_service_side_effect(service_name, region=None):
        if service_name == 'ec2':
            return mock_ec2
        if region == 'us-east-1':
            return mock_analyzer_east
        return mock_analyzer_west
    
    mock_service_factory.get_service.side_effect = get_service_side_effect
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 2
    assert results[0].status == "PASS"
    assert results[1].status == "FAIL"
    assert "No ACTIVE IAM Access Analyzer found" in results[1].status_extended

def test_execute_inactive_analyzer(mock_session, mock_logger, mock_service_factory):
    """Test when analyzer exists but is not active."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Mock Access Analyzer service with inactive analyzer
    mock_analyzer = MagicMock()
    mock_analyzer.list_analyzers.return_value = {
        'success': True,
        'analyzers': [{
            'arn': 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test',
            'name': 'test-analyzer',
            'status': 'CREATING',
            'tags': {'Environment': 'Production'}
        }]
    }
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_analyzer]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert "No ACTIVE IAM Access Analyzer found" in results[0].status_extended

def test_execute_no_active_analyzers(mock_session, mock_logger, mock_service_factory):
    """Test when regions have no active analyzers."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Mock Access Analyzer service response with no analyzers
    mock_analyzer = MagicMock()
    mock_analyzer.list_analyzers.return_value = {
        'success': True,
        'analyzers': []
    }
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_analyzer]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert "No ACTIVE IAM Access Analyzer found" in results[0].status_extended
    assert results[0].resource_details == {"total_regions": 1}

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

def test_execute_analyzer_listing_error(mock_session, mock_logger, mock_service_factory):
    """Test handling of error when listing analyzers."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Mock Access Analyzer service error
    mock_analyzer = MagicMock()
    mock_analyzer.list_analyzers.return_value = {
        'success': False,
        'error_message': 'Failed to list analyzers'
    }
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_analyzer]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "ERROR"
    assert "Error checking analyzers" in results[0].status_extended
    
    # Verify logger was called
    mock_logger.error.assert_called_once_with(
        "Error checking analyzers in region us-east-1: Failed to list analyzers"
    )

def test_execute_region_processing_error(mock_session, mock_logger, mock_service_factory):
    """Test handling of error when processing a specific region."""
    # Mock EC2 service response
    mock_ec2 = MagicMock()
    mock_ec2.list_active_regions.return_value = {
        'success': True,
        'regions': ['us-east-1']
    }
    
    # Mock Access Analyzer service to raise an exception
    mock_analyzer = MagicMock()
    mock_analyzer.list_analyzers.side_effect = Exception("Region processing failed")
    
    # Configure service factory
    mock_service_factory.get_service.side_effect = [mock_ec2, mock_analyzer]
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify results
    assert len(results) == 1
    assert results[0].status == "ERROR"
    assert "Error processing region us-east-1" in results[0].status_extended
    assert results[0].resource_details == {"total_regions": 1}
    
    # Verify logger was called
    mock_logger.error.assert_called_once_with(
        "Error processing region us-east-1: Region processing failed"
    )

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
        "Error executing CIS 1.20 check: Unexpected error occurred"
    )

def test_create_error_result():
    """Test creation of error result."""
    error_message = "Test error message"
    result = create_error_result(error_message)
    
    assert result.check_id == "cis_1_20"
    assert result.status == "ERROR"
    assert result.status_extended == error_message
