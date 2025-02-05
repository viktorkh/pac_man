import pytest
from unittest.mock import Mock

from pac_man.providers.aws.controls.cis_2_1_4.cis_2_1_4_check import check_s3_public_access_block, execute
from pac_man.providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_s3_service():
    return Mock()

@pytest.fixture
def mock_logger():
    return Mock()

def test_check_s3_public_access_block_all_settings_enabled(mock_s3_service, mock_logger):
    """Should return STATUS_PASS when all public access block settings are enabled."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.return_value = {
        'success': True,
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    }

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    mock_s3_service.get_public_access_block.assert_called_once_with(bucket_name)
    assert result.status == CheckResult.STATUS_PASS
    assert result.status_extended == f"S3 bucket '{bucket_name}' has all public access block settings enabled"

def test_check_s3_public_access_block_no_configuration(mock_s3_service, mock_logger):
    """Should return STATUS_FAIL when no public access block configuration is present."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.return_value = {
        'success': False,
        'error_message': 'NoSuchPublicAccessBlockConfiguration'
    }

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    mock_s3_service.get_public_access_block.assert_called_once_with(bucket_name)
    assert result.status == CheckResult.STATUS_FAIL
    assert result.status_extended == f"S3 bucket '{bucket_name}' does not have a public access block configuration"

def test_check_s3_public_access_block_some_settings_disabled(mock_s3_service, mock_logger):
    """Should return STATUS_FAIL when some public access block settings are disabled."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.return_value = {
        'success': True,
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': False,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': False
        }
    }

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    mock_s3_service.get_public_access_block.assert_called_once_with(bucket_name)
    assert result.status == CheckResult.STATUS_FAIL
    assert result.status_extended == (
        f"S3 bucket '{bucket_name}' has the following public access block settings disabled: "
        "IgnorePublicAcls, RestrictPublicBuckets"
    )

def test_check_s3_public_access_block_error_retrieving_configuration(mock_s3_service, mock_logger):
    """Should return STATUS_ERROR when there is an error retrieving public access block configuration."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.side_effect = Exception("Service unavailable")

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    mock_logger.error.assert_called_once_with(
        f"Error checking public access block for bucket {bucket_name}: Service unavailable"
    )
    assert result.status == CheckResult.STATUS_ERROR
    assert result.status_extended == "Error checking public access block settings: Service unavailable"

def test_check_s3_public_access_block_exception_handling(mock_s3_service, mock_logger):
    """Should handle and log exceptions during public access block check gracefully."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.side_effect = Exception("Unexpected error")

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    mock_logger.error.assert_called_once_with(
        f"Error checking public access block for bucket {bucket_name}: Unexpected error"
    )
    assert result.status == CheckResult.STATUS_ERROR
    assert result.status_extended == "Error checking public access block settings: Unexpected error"

def test_check_s3_public_access_block_unexpected_error(mock_s3_service, mock_logger):
    """Should return STATUS_ERROR with appropriate message when an unexpected error occurs."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.side_effect = Exception("Unexpected service error")

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    mock_logger.error.assert_called_once_with(
        f"Error checking public access block for bucket {bucket_name}: Unexpected service error"
    )
    assert result.status == CheckResult.STATUS_ERROR
    assert result.status_extended == "Error checking public access block settings: Unexpected service error"


def test_check_s3_public_access_block_sets_correct_resource_arn(mock_s3_service, mock_logger):
    """Should correctly set resource ARN for each S3 bucket checked."""
    bucket_name = "test-bucket"
    mock_s3_service.get_public_access_block.return_value = {
        'success': True,
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    }

    result = check_s3_public_access_block(mock_s3_service, bucket_name, mock_logger)

    expected_arn = f"arn:aws:s3:::{bucket_name}"
    assert result.resource_arn == expected_arn

def test_execute_logs_start_message(mock_s3_service, mock_logger):
    """Should log a message when starting the CIS 2.1.4 check execution."""
    mock_s3_service.list_buckets.return_value = {
        'success': True,
        'buckets': []
    }
    
    execute(None, mock_logger, Mock(get_service=Mock(return_value=mock_s3_service)))
    
    mock_logger.info.assert_called_once_with("Executing CIS 2.1.4 check for S3 bucket public access block configuration")
