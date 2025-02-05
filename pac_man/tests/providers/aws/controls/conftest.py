"""Common test fixtures for AWS controls."""

import pytest
from unittest.mock import Mock
from providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    return Mock()

@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return Mock()

@pytest.fixture
def mock_service_factory():
    """Create a mock service factory with common AWS services."""
    mock_factory = Mock()
    
    # Create mock services
    mock_iam = Mock(name='iam_service')
    mock_s3 = Mock(name='s3_service')
    mock_cloudtrail = Mock(name='cloudtrail_service')
    mock_config = Mock(name='config_service')
    mock_sts = Mock(name='sts_service')
    
    # Configure service factory to return appropriate service
    def get_service(service_type, region=None):
        services = {
            'iam': mock_iam,
            's3': mock_s3,
            'cloudtrail': mock_cloudtrail,
            'config': mock_config,
            'sts': mock_sts
        }
        return services.get(service_type, Mock())
    
    mock_factory.get_service = get_service
    
    return mock_factory

@pytest.fixture
def base_check_result():
    """Create a base CheckResult instance with common fields."""
    result = CheckResult()
    result.resource_tags = []
    result.region = 'global'
    result.status = ''
    result.status_extended = ''
    return result

@pytest.fixture
def mock_aws_account_context():
    """Create a mock AWS account context."""
    return {
        'account_id': '123456789012',
        'account_name': 'test-account',
        'region': 'us-east-1'
    }

@pytest.fixture
def mock_credentials():
    """Create mock AWS credentials."""
    return {
        'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
        'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'SessionToken': 'FwoGZXIvYXdzELj...'
    }

@pytest.fixture
def mock_sts_response():
    """Create a mock STS get_caller_identity response."""
    return {
        'success': True,
        'account_id': '123456789012',
        'arn': 'arn:aws:iam::123456789012:user/test-user',
        'user_id': 'AIDACKCEVSQ6C2EXAMPLE'
    }

@pytest.fixture
def mock_error_response():
    """Create a mock error response."""
    return {
        'success': False,
        'error_message': 'Test error message',
        'error_code': 'TestError',
        'request_id': '1234567890ABCDEF'
    }

@pytest.fixture
def mock_success_response():
    """Create a mock success response."""
    return {
        'success': True,
        'message': 'Operation completed successfully',
        'request_id': '1234567890ABCDEF'
    }

@pytest.fixture
def mock_finding():
    """Create a mock finding for testing fixes."""
    finding = CheckResult()
    finding.check_id = 'test_check'
    finding.check_description = 'Test check description'
    finding.resource_id = 'test-resource'
    finding.region = 'global'
    finding.resource_tags = []
    finding.resource_details = 'Test resource details'
    finding.status = CheckResult.STATUS_FAIL
    finding.status_extended = 'Test failure message'
    return finding
