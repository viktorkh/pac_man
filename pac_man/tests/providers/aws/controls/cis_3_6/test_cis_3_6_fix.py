import pytest
from unittest.mock import MagicMock, patch
from pac_man.providers.aws.controls.cis_3_6.cis_3_6_fix import execute
from pac_man.providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_s3_service():
    return MagicMock()

@pytest.fixture
def mock_service_factory(mock_s3_service):
    factory = MagicMock()
    factory.get_service.return_value = mock_s3_service
    return factory

@pytest.fixture
def mock_logger():
    return MagicMock()

@pytest.fixture
def mock_finding():
    finding = MagicMock()
    finding.resource_id = "test-bucket"
    finding.remediation_result = MagicMock()
    return finding

def test_logging_already_enabled(mock_s3_service, mock_service_factory, mock_logger, mock_finding):
    mock_s3_service.get_bucket_logging.return_value = {
        'success': True,
        'LoggingEnabled': {'TargetBucket': 'test-bucket', 'TargetPrefix': 'logs/'}
    }

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "PASS"
    assert "Logging is already enabled" in result.remediation_result.mark_as_success.call_args[1]['details']

def test_enable_logging_success(mock_s3_service, mock_service_factory, mock_logger, mock_finding):
    mock_s3_service.get_bucket_logging.side_effect = [
        {'success': True},  # Initial check
        {'success': True, 'LoggingEnabled': {'TargetBucket': 'test-bucket', 'TargetPrefix': 'logs/'}}  # Verification
    ]
    mock_s3_service.put_bucket_logging.return_value = {'success': True}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "PASS"
    assert "Successfully enabled logging" in result.remediation_result.mark_as_success.call_args[1]['details']

def test_enable_logging_failure(mock_s3_service, mock_service_factory, mock_logger, mock_finding):
    mock_s3_service.get_bucket_logging.return_value = {'success': True}
    mock_s3_service.put_bucket_logging.return_value = {'success': False, 'error_message': 'Access denied'}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Failed to enable logging" in result.remediation_result.mark_as_failed.call_args[1]['error_message']

def test_verification_failure(mock_s3_service, mock_service_factory, mock_logger, mock_finding):
    mock_s3_service.get_bucket_logging.side_effect = [
        {'success': True},  # Initial check
        {'success': True}  # Verification (no LoggingEnabled)
    ]
    mock_s3_service.put_bucket_logging.return_value = {'success': True}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Logging configuration not found after enabling" in result.remediation_result.mark_as_failed.call_args[1]['error_message']

def test_unexpected_error(mock_s3_service, mock_service_factory, mock_logger, mock_finding):
    mock_s3_service.get_bucket_logging.side_effect = Exception("Unexpected error")

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Unexpected error occurred" in result.remediation_result.mark_as_failed.call_args[1]['error_message']
