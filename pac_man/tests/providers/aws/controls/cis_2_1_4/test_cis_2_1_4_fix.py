import pytest
from unittest.mock import Mock, MagicMock
from providers.aws.controls.cis_2_1_4.cis_2_1_4_fix import execute

@pytest.fixture
def mock_session():
    return Mock()

@pytest.fixture
def mock_logger():
    return Mock()

@pytest.fixture
def mock_service_factory():
    factory = MagicMock()
    factory.get_service = MagicMock()
    return factory

def test_execute_already_compliant(mock_session, mock_logger, mock_service_factory):
    """Should return early if public access block settings are already applied."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.get_public_access_block.return_value = {
        'success': True,
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    }
    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    mock_s3_service.get_public_access_block.assert_called_once_with('test-bucket')
    mock_s3_service.put_public_access_block.assert_not_called()
    assert result.status == "PASS"

def test_execute_success_with_verification(mock_session, mock_logger, mock_service_factory):
    """Should successfully apply public access block settings and verify them."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.get_public_access_block.side_effect = [
        {'success': True, 'PublicAccessBlockConfiguration': {}},  # Initial fetch
        {'success': True, 'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }}  # Verification fetch
    ]
    mock_s3_service.put_public_access_block.return_value = {'success': True}
    
    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    mock_s3_service.get_public_access_block.assert_called()
    mock_s3_service.put_public_access_block.assert_called_once()
    assert result.status == "PASS"

def test_execute_failed_verification(mock_session, mock_logger, mock_service_factory):
    """Should mark as failed if verification does not confirm changes."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.get_public_access_block.side_effect = [
        {'success': True, 'PublicAccessBlockConfiguration': {}},  # Initial fetch
        {'success': True, 'PublicAccessBlockConfiguration': {  # Incomplete verification response
            'BlockPublicAcls': True,
            'IgnorePublicAcls': False,  # Not fully enforced
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }}
    ]
    mock_s3_service.put_public_access_block.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_s3_service.put_public_access_block.assert_called_once()
    assert result.status == "FAIL"  # Ensure failure is detected


def test_execute_failed_application(mock_session, mock_logger, mock_service_factory):
    """Should mark remediation as failed when S3 service returns an error on applying settings."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.get_public_access_block.return_value = {'success': True, 'PublicAccessBlockConfiguration': {}}
    mock_s3_service.put_public_access_block.return_value = {'success': False, 'error_message': 'Access denied'}
    
    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    mock_s3_service.put_public_access_block.assert_called_once()
    assert result.status == "FAIL"

def test_execute_exception_handling(mock_session, mock_logger, mock_service_factory):
    """Should handle and log unexpected exceptions during execution."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.get_public_access_block.side_effect = Exception("Unexpected error")
    
    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    mock_logger.error.assert_called_once()
    assert result.status == "FAIL"
