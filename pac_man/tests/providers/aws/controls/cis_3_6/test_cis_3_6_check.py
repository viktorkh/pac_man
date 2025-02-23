import pytest
from unittest.mock import Mock, patch
from providers.aws.lib.check_result import CheckResult
from providers.aws.controls.cis_3_6.cis_3_6_check import check_s3_bucket_logging, execute, CHECK_ID, CHECK_DESCRIPTION

@pytest.fixture
def mock_s3_service():
    return Mock()

@pytest.fixture
def mock_cloudtrail_service():
    return Mock()

@pytest.fixture
def mock_service_factory(mock_s3_service, mock_cloudtrail_service):
    factory = Mock()
    factory.get_service.side_effect = lambda service: {
        's3': mock_s3_service,
        'cloudtrail': mock_cloudtrail_service
    }[service]
    return factory

@pytest.fixture
def mock_logger():
    return Mock()

def test_check_s3_bucket_logging_pass(mock_s3_service, mock_logger):
    mock_s3_service.get_bucket_logging.return_value = {'success': True, 'LoggingEnabled': True}
    result = check_s3_bucket_logging(mock_s3_service, 'test-bucket', mock_logger)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "S3 bucket access logging is enabled" in result.status_extended
    assert result.resource_id == 'test-bucket'
    assert result.resource_arn == 'arn:aws:s3:::test-bucket'

def test_check_s3_bucket_logging_fail(mock_s3_service, mock_logger):
    mock_s3_service.get_bucket_logging.return_value = {'success': True, 'LoggingEnabled': False}
    result = check_s3_bucket_logging(mock_s3_service, 'test-bucket', mock_logger)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "S3 bucket access logging is not enabled" in result.status_extended

def test_check_s3_bucket_logging_error(mock_s3_service, mock_logger):
    mock_s3_service.get_bucket_logging.side_effect = Exception("Test error")
    result = check_s3_bucket_logging(mock_s3_service, 'test-bucket', mock_logger)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "Error checking S3 bucket access logging" in result.status_extended
    mock_logger.error.assert_called_once()

def test_execute_success(mock_service_factory, mock_logger):
    mock_cloudtrail_service = mock_service_factory.get_service('cloudtrail')
    mock_cloudtrail_service.describe_trails.return_value = {
        'success': True,
        'trails': [{'S3BucketName': 'test-bucket'}]
    }
    
    mock_s3_service = mock_service_factory.get_service('s3')
    mock_s3_service.get_bucket_logging.return_value = {'success': True, 'LoggingEnabled': True}
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[0].resource_id == 'test-bucket'

def test_execute_no_buckets(mock_service_factory, mock_logger):
    mock_cloudtrail_service = mock_service_factory.get_service('cloudtrail')
    mock_cloudtrail_service.describe_trails.return_value = {
        'success': True,
        'trails': []
    }
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 0

def test_execute_multiple_buckets(mock_service_factory, mock_logger):
    mock_cloudtrail_service = mock_service_factory.get_service('cloudtrail')
    mock_cloudtrail_service.describe_trails.return_value = {
        'success': True,
        'trails': [{'S3BucketName': 'bucket1'}, {'S3BucketName': 'bucket2'}]
    }
    
    mock_s3_service = mock_service_factory.get_service('s3')
    mock_s3_service.get_bucket_logging.side_effect = [
        {'success': True, 'LoggingEnabled': True},
        {'success': True, 'LoggingEnabled': False}
    ]
    
    results = execute(None, mock_logger, mock_service_factory)
    
    assert len(results) == 2
    assert results[0].status == CheckResult.STATUS_PASS
    assert results[1].status == CheckResult.STATUS_FAIL