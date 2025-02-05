
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

def test_execute_success(mock_session, mock_logger, mock_service_factory):
    """Should successfully enable all public access block settings for a valid bucket."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_service_factory.get_service.assert_called_once_with('S3')
    mock_s3_service.put_public_access_block.assert_called_once_with(
        'test-bucket',
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_success.assert_called_once()
    assert result.remediation_result.message == "Successfully enabled all public access block settings for bucket test-bucket"

def test_execute_failed_response(mock_session, mock_logger, mock_service_factory):
    """Should mark remediation as failed when S3 service returns an unsuccessful response."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.return_value = {
        'success': False,
        'error_message': 'Access denied'
    }

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_service_factory.get_service.assert_called_once_with('S3')
    mock_s3_service.put_public_access_block.assert_called_once_with(
        'test-bucket',
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_failed.assert_called_once()
    assert result.remediation_result.message == "Failed to enable public access block settings for bucket test-bucket: Access denied"

def test_execute_unexpected_exception(mock_session, mock_logger, mock_service_factory):
    """Should handle and log unexpected exceptions during execution."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.side_effect = Exception("Unexpected error")

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_service_factory.get_service.assert_called_once_with('S3')
    mock_s3_service.put_public_access_block.assert_called_once_with(
        'test-bucket',
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
    mock_logger.error.assert_called_once_with(
        "Unexpected error occurred while fixing CIS 2.1.4 for bucket test-bucket: Unexpected error"
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_failed.assert_called_once()
    assert result.remediation_result.message == "Unexpected error occurred: Unexpected error"


def test_execute_init_remediation(mock_session, mock_logger, mock_service_factory):
    """Should correctly initialize remediation before marking as success or failure."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    assert mock_finding.init_remediation.call_count == 1
    assert mock_finding.init_remediation.call_args_list[0] == ()
    assert mock_finding.mark_as_success.call_count == 1
    assert mock_finding.mark_as_success.call_args_list[0] == ()

    mock_s3_service.put_public_access_block.side_effect = Exception("Test error")
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    assert mock_finding.init_remediation.call_count == 2
    assert mock_finding.init_remediation.call_args_list[1] == ()
    assert mock_finding.mark_as_failed.call_count == 1
    assert mock_finding.mark_as_failed.call_args_list[0] == ()

def test_execute_uses_correct_bucket_name(mock_session, mock_logger, mock_service_factory):
    """Should use the correct bucket name from the finding's resource_id."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket-123'
    mock_finding.init_remediation.return_value = mock_finding

    execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_service_factory.get_service.assert_called_once_with('S3')
    mock_s3_service.put_public_access_block.assert_called_once_with(
        'test-bucket-123',
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_success.assert_called_once()
    assert mock_finding.remediation_result.message == "Successfully enabled all public access block settings for bucket test-bucket-123"
def test_execute_failed_public_access_block(mock_session, mock_logger, mock_service_factory):
    """Should set appropriate error message when public access block operation fails."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.return_value = {
        'success': False,
        'error_message': 'Access denied'
    }

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_service_factory.get_service.assert_called_once_with('S3')
    mock_s3_service.put_public_access_block.assert_called_once_with(
        'test-bucket',
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_failed.assert_called_once()
    assert result.remediation_result.message == "Failed to enable public access block settings for bucket test-bucket: Access denied"

def test_execute_verifies_all_public_access_block_settings(mock_session, mock_logger, mock_service_factory):
    """Should verify all four public access block settings are set to True."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_s3_service.put_public_access_block.assert_called_once_with(
        'test-bucket',
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
    mock_finding.mark_as_success.assert_called_once()
    assert mock_finding.remediation_result.message == "Successfully enabled all public access block settings for bucket test-bucket"

def test_execute_logs_error_on_exception(mock_session, mock_logger, mock_service_factory):
    """Should properly use the logger to record errors in case of exceptions."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    mock_s3_service.put_public_access_block.side_effect = Exception("Test error")

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_logger.error.assert_called_once_with(
        "Unexpected error occurred while fixing CIS 2.1.4 for bucket test-bucket: Test error"
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_failed.assert_called_once()
    assert mock_finding.remediation_result.message == "Unexpected error occurred: Test error"

def test_execute_returns_updated_finding(mock_session, mock_logger, mock_service_factory):
    """Should return the updated finding object regardless of success or failure."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    # Test success case
    mock_s3_service.put_public_access_block.return_value = {'success': True}
    result_success = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    assert result_success == mock_finding

    # Test failure case
    mock_s3_service.put_public_access_block.return_value = {'success': False, 'error_message': 'Access denied'}
    result_failure = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    assert result_failure == mock_finding

    # Test exception case
    mock_s3_service.put_public_access_block.side_effect = Exception("Unexpected error")
    result_exception = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    assert result_exception == mock_finding