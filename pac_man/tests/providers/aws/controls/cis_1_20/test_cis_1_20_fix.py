"""Tests for CIS 1.20 fix implementation."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError

from pac_man.providers.aws.lib.check_result import CheckResult
from pac_man.providers.aws.controls.cis_1_20.cis_1_20_fix import execute
from pac_man.providers.aws.services.access_analyzer_service import AccessAnalyzerService

@pytest.fixture
def mock_logger():
    """Create a mock logger fixture."""
    return Mock()

@pytest.fixture
def mock_session():
    """Create a mock boto3 session fixture."""
    return Mock()

@pytest.fixture
def mock_finding():
    """Create a mock finding fixture with realistic test data."""
    finding = CheckResult()
    finding.check_id = "CIS_1_20"
    finding.check_description = "Ensure IAM Access Analyzer is enabled"
    finding.region = "us-east-1"
    finding.status = "FAIL"
    finding.status_extended = "IAM Access Analyzer is not enabled"
    finding.resource_id = "ACCOUNT"
    finding.resource_arn = "arn:aws:iam::123456789012:root"
    finding.resource_details = ""
    finding.resource_tags = []
    return finding

@pytest.fixture
def mock_service_factory():
    """Create a mock service factory fixture."""
    factory = Mock()
    service_instance = Mock(spec=AccessAnalyzerService)
    factory.get_service.return_value = service_instance
    return factory, service_instance

def test_execute_success(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test successful execution of the fix."""
    factory, service = mock_service_factory
    analyzer_arn = 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/DefaultAnalyzer-us-east-1'
    
    # Setup mock service response
    service.create_analyzer.return_value = {
        'success': True,
        'arn': analyzer_arn
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, factory)

    # Verify service was called correctly
    factory.get_service.assert_called_once_with('access_analyzer', mock_finding.region)
    service.create_analyzer.assert_called_once_with('DefaultAnalyzer-us-east-1')

    # Verify finding was updated correctly
    assert result.status == "PASS"
    assert analyzer_arn in result.status_extended
    assert mock_logger.info.call_count == 2

    # Verify remediation result was updated correctly
    assert result.remediation_result is not None
    assert result.remediation_result.status == "SUCCESS"
    assert analyzer_arn in result.remediation_result.details
    assert result.remediation_result.provider == "aws"
    assert result.remediation_result.region == mock_finding.region
    assert result.remediation_result.current_state == {
        "status": "PASS",
        "analyzer_arn": analyzer_arn,
        "analyzer_name": f'DefaultAnalyzer-{mock_finding.region}'
    }

def test_execute_service_failure(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test fix execution when service creation fails."""
    factory, service = mock_service_factory
    error_msg = 'Service error occurred'
    
    # Setup mock service response
    service.create_analyzer.return_value = {
        'success': False,
        'error_message': error_msg
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, factory)

    # Verify service was called correctly
    factory.get_service.assert_called_once_with('access_analyzer', mock_finding.region)
    service.create_analyzer.assert_called_once_with('DefaultAnalyzer-us-east-1')

    # Verify finding was updated correctly
    assert "Fix attempt failed" in result.status_extended
    assert error_msg in result.status_extended
    assert mock_logger.error.call_count == 1

    # Verify remediation result was updated correctly
    assert result.remediation_result is not None
    assert result.remediation_result.status == "FAILED"
    assert error_msg in result.remediation_result.error_message
    assert result.remediation_result.provider == "aws"
    assert result.remediation_result.region == mock_finding.region

def test_execute_analyzer_exists(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test fix execution when analyzer already exists."""
    factory, service = mock_service_factory
    # Setup mock service to raise ClientError for existing analyzer
    error_response = {
        'Error': {
            'Code': 'ResourceAlreadyExistsException',
            'Message': 'Analyzer already exists'
        }
    }
    service.create_analyzer.side_effect = ClientError(error_response, 'CreateAnalyzer')

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, factory)

    # Verify service was called correctly
    factory.get_service.assert_called_once_with('access_analyzer', mock_finding.region)
    service.create_analyzer.assert_called_once_with('DefaultAnalyzer-us-east-1')

    # Verify finding was updated correctly
    assert "Fix attempt failed: An error occurred (ResourceAlreadyExistsException)" in result.status_extended
    assert mock_logger.error.call_count == 1

    # Verify remediation result was updated correctly
    assert result.remediation_result is not None
    assert result.remediation_result.status == "FAILED"
    assert "ResourceAlreadyExistsException" in result.remediation_result.error_message
    assert result.remediation_result.provider == "aws"
    assert result.remediation_result.region == mock_finding.region

def test_execute_invalid_region(mock_session, mock_logger, mock_service_factory):
    """Test fix execution with invalid region."""
    factory, service = mock_service_factory
    # Create finding with invalid region
    finding = CheckResult()
    finding.check_id = "CIS_1_20"
    finding.check_description = "Ensure IAM Access Analyzer is enabled"
    finding.region = "invalid-region"
    finding.status = "FAIL"
    finding.status_extended = "IAM Access Analyzer is not enabled"
    finding.resource_id = "ACCOUNT"
    finding.resource_arn = "arn:aws:iam::123456789012:root"
    finding.resource_details = ""
    finding.resource_tags = []

    # Setup mock service to raise ClientError for invalid region
    error_response = {
        'Error': {
            'Code': 'InvalidRegionException',
            'Message': 'Region invalid-region is not valid'
        }
    }
    service.create_analyzer.side_effect = ClientError(error_response, 'CreateAnalyzer')

    # Execute fix
    result = execute(mock_session, finding, mock_logger, factory)

    # Verify service was called correctly
    factory.get_service.assert_called_once_with('access_analyzer', finding.region)
    service.create_analyzer.assert_called_once_with('DefaultAnalyzer-invalid-region')

    # Verify finding was updated correctly
    assert "Fix attempt failed: An error occurred (InvalidRegionException)" in result.status_extended
    assert mock_logger.error.call_count == 1

    # Verify remediation result was updated correctly
    assert result.remediation_result is not None
    assert result.remediation_result.status == "FAILED"
    assert "InvalidRegionException" in result.remediation_result.error_message
    assert result.remediation_result.provider == "aws"
    assert result.remediation_result.region == finding.region

def test_execute_unexpected_error(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test fix execution when an unexpected error occurs."""
    factory, service = mock_service_factory
    error_msg = "Unexpected internal error"
    # Setup mock service to raise an unexpected exception
    service.create_analyzer.side_effect = Exception(error_msg)

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, factory)

    # Verify service was called correctly
    factory.get_service.assert_called_once_with('access_analyzer', mock_finding.region)
    service.create_analyzer.assert_called_once_with('DefaultAnalyzer-us-east-1')

    # Verify finding was updated correctly
    assert f"Fix attempt failed: {error_msg}" in result.status_extended
    assert mock_logger.error.call_count == 1

    # Verify remediation result was updated correctly
    assert result.remediation_result is not None
    assert result.remediation_result.status == "FAILED"
    assert error_msg in result.remediation_result.error_message
    assert result.remediation_result.provider == "aws"
    assert result.remediation_result.region == mock_finding.region

def test_execute_access_denied(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test fix execution when access is denied."""
    factory, service = mock_service_factory
    # Setup mock service to raise ClientError for access denied
    error_response = {
        'Error': {
            'Code': 'AccessDeniedException',
            'Message': 'User is not authorized to perform operation'
        }
    }
    service.create_analyzer.side_effect = ClientError(error_response, 'CreateAnalyzer')

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, factory)

    # Verify service was called correctly
    factory.get_service.assert_called_once_with('access_analyzer', mock_finding.region)
    service.create_analyzer.assert_called_once_with('DefaultAnalyzer-us-east-1')

    # Verify finding was updated correctly
    assert "Fix attempt failed: An error occurred (AccessDeniedException)" in result.status_extended
    assert mock_logger.error.call_count == 1

    # Verify remediation result was updated correctly
    assert result.remediation_result is not None
    assert result.remediation_result.status == "FAILED"
    assert "AccessDeniedException" in result.remediation_result.error_message
    assert result.remediation_result.provider == "aws"
    assert result.remediation_result.region == mock_finding.region
