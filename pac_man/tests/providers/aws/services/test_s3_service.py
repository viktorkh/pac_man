"""Unit tests for S3 service."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from providers.aws.services.s3_service import S3Service

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
    return session

@pytest.fixture
def s3_service(mock_session):
    """Create an S3Service instance with a mock session."""
    return S3Service(mock_session)

@pytest.fixture
def mock_client(s3_service):
    """Get the mock S3 client from the service."""
    return s3_service.client

def test_init(mock_session):
    """Test S3Service initialization."""
    service = S3Service(mock_session)
    mock_session.client.assert_called_once_with('s3', region_name=None)
    assert service.client == mock_session.client.return_value

class TestListBuckets:
    """Tests for list_buckets method."""
    
    def test_success(self, s3_service, mock_client):
        """Test successful bucket listing."""
        mock_response = {
            'Buckets': [
                {
                    'Name': 'test-bucket',
                    'CreationDate': '2023-01-01T00:00:00Z'
                }
            ],
            'Owner': {
                'ID': 'test-owner-id',
                'DisplayName': 'test-owner'
            }
        }
        mock_client.list_buckets.return_value = mock_response
        
        result = s3_service.list_buckets()
        
        mock_client.list_buckets.assert_called_once()
        assert result['success'] is True
        assert len(result['buckets']) == 1
        assert result['buckets'][0]['Name'] == 'test-bucket'
        assert result['owner']['DisplayName'] == 'test-owner'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket listing."""
        error_response = {
            'Error': {
                'Code': 'InternalError',
                'Message': 'Internal service error'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 500
            }
        }
        mock_client.list_buckets.side_effect = ClientError(
            error_response, 'ListBuckets'
        )
        
        result = s3_service.list_buckets()
        
        assert result['success'] is False
        assert result['error_code'] == 'InternalError'
        assert result['operation'] == 'list_buckets'

class TestGetBucketLocation:
    """Tests for get_bucket_location method."""
    
    def test_success_with_location(self, s3_service, mock_client):
        """Test successful bucket location retrieval with specific location."""
        mock_response = {
            'LocationConstraint': 'us-west-2'
        }
        mock_client.get_bucket_location.return_value = mock_response
        
        result = s3_service.get_bucket_location('test-bucket')
        
        mock_client.get_bucket_location.assert_called_once_with(Bucket='test-bucket')
        assert result['success'] is True
        assert result['location'] == 'us-west-2'
    
    def test_success_us_east_1(self, s3_service, mock_client):
        """Test successful bucket location retrieval for us-east-1."""
        mock_response = {
            'LocationConstraint': None
        }
        mock_client.get_bucket_location.return_value = mock_response
        
        result = s3_service.get_bucket_location('test-bucket')
        
        assert result['success'] is True
        assert result['location'] == 'us-east-1'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket location retrieval."""
        error_response = {
            'Error': {
                'Code': 'NoSuchBucket',
                'Message': 'The specified bucket does not exist'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_bucket_location.side_effect = ClientError(
            error_response, 'GetBucketLocation'
        )
        
        result = s3_service.get_bucket_location('test-bucket')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchBucket'
        assert result['operation'] == 'get_bucket_location for bucket test-bucket'

class TestGetBucketEncryption:
    """Tests for get_bucket_encryption method."""
    
    def test_success(self, s3_service, mock_client):
        """Test successful bucket encryption retrieval."""
        mock_response = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        }
        mock_client.get_bucket_encryption.return_value = mock_response
        
        result = s3_service.get_bucket_encryption('test-bucket')
        
        mock_client.get_bucket_encryption.assert_called_once_with(Bucket='test-bucket')
        assert result['success'] is True
        assert result['encryption']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket encryption retrieval."""
        error_response = {
            'Error': {
                'Code': 'ServerSideEncryptionConfigurationNotFoundError',
                'Message': 'The server side encryption configuration was not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_bucket_encryption.side_effect = ClientError(
            error_response, 'GetBucketEncryption'
        )
        
        result = s3_service.get_bucket_encryption('test-bucket')
        
        assert result['success'] is False
        assert result['error_code'] == 'ServerSideEncryptionConfigurationNotFoundError'
        assert result['operation'] == 'get_bucket_encryption for bucket test-bucket'

class TestGetBucketVersioning:
    """Tests for get_bucket_versioning method."""
    
    def test_success_enabled(self, s3_service, mock_client):
        """Test successful bucket versioning retrieval when enabled."""
        mock_response = {
            'Status': 'Enabled',
            'MFADelete': 'Enabled'
        }
        mock_client.get_bucket_versioning.return_value = mock_response
        
        result = s3_service.get_bucket_versioning('test-bucket')
        
        mock_client.get_bucket_versioning.assert_called_once_with(Bucket='test-bucket')
        assert result['success'] is True
        assert result['versioning'] == 'Enabled'
        assert result['mfa_delete'] == 'Enabled'
    
    def test_success_disabled(self, s3_service, mock_client):
        """Test successful bucket versioning retrieval when disabled."""
        mock_response = {}
        mock_client.get_bucket_versioning.return_value = mock_response
        
        result = s3_service.get_bucket_versioning('test-bucket')
        
        assert result['success'] is True
        assert result['versioning'] == 'Disabled'
        assert result['mfa_delete'] == 'Disabled'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket versioning retrieval."""
        error_response = {
            'Error': {
                'Code': 'NoSuchBucket',
                'Message': 'The specified bucket does not exist'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_bucket_versioning.side_effect = ClientError(
            error_response, 'GetBucketVersioning'
        )
        
        result = s3_service.get_bucket_versioning('test-bucket')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchBucket'
        assert result['operation'] == 'get_bucket_versioning for bucket test-bucket'

class TestPutBucketEncryption:
    """Tests for put_bucket_encryption method."""
    
    def test_success(self, s3_service, mock_client):
        """Test successful bucket encryption configuration."""
        encryption_config = {
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }
            ]
        }
        
        result = s3_service.put_bucket_encryption('test-bucket', encryption_config)
        
        mock_client.put_bucket_encryption.assert_called_once_with(
            Bucket='test-bucket',
            ServerSideEncryptionConfiguration=encryption_config
        )
        assert result['success'] is True
        assert result['message'] == 'Encryption configured successfully for bucket test-bucket'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket encryption configuration."""
        error_response = {
            'Error': {
                'Code': 'InvalidArgument',
                'Message': 'Invalid encryption configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.put_bucket_encryption.side_effect = ClientError(
            error_response, 'PutBucketEncryption'
        )
        
        result = s3_service.put_bucket_encryption('test-bucket', {})
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidArgument'
        assert result['operation'] == 'put_bucket_encryption for bucket test-bucket'

class TestPutBucketVersioning:
    """Tests for put_bucket_versioning method."""
    
    def test_success_basic(self, s3_service, mock_client):
        """Test successful basic bucket versioning configuration."""
        result = s3_service.put_bucket_versioning('test-bucket', 'Enabled')
        
        mock_client.put_bucket_versioning.assert_called_once_with(
            Bucket='test-bucket',
            VersioningConfiguration={'Status': 'Enabled'}
        )
        assert result['success'] is True
        assert result['message'] == 'Versioning configured successfully for bucket test-bucket'
    
    def test_success_with_mfa(self, s3_service, mock_client):
        """Test successful bucket versioning configuration with MFA."""
        result = s3_service.put_bucket_versioning(
            'test-bucket',
            'Enabled',
            mfa_delete='Enabled',
            mfa='123456 123456'
        )
        
        mock_client.put_bucket_versioning.assert_called_once_with(
            Bucket='test-bucket',
            VersioningConfiguration={
                'Status': 'Enabled',
                'MFADelete': 'Enabled'
            },
            MFA='123456 123456'
        )
        assert result['success'] is True
        assert result['message'] == 'Versioning configured successfully for bucket test-bucket'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket versioning configuration."""
        error_response = {
            'Error': {
                'Code': 'InvalidArgument',
                'Message': 'Invalid versioning configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.put_bucket_versioning.side_effect = ClientError(
            error_response, 'PutBucketVersioning'
        )
        
        result = s3_service.put_bucket_versioning('test-bucket', 'Invalid')
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidArgument'
        assert result['operation'] == 'put_bucket_versioning for bucket test-bucket'

class TestGetBucketPolicy:
    """Tests for get_bucket_policy method."""
    
    def test_success(self, s3_service, mock_client):
        """Test successful bucket policy retrieval."""
        mock_response = {
            'Policy': '{"Version":"2012-10-17","Statement":[]}'
        }
        mock_client.get_bucket_policy.return_value = mock_response
        
        result = s3_service.get_bucket_policy('test-bucket')
        
        mock_client.get_bucket_policy.assert_called_once_with(Bucket='test-bucket')
        assert result['success'] is True
        assert result['policy'] == '{"Version":"2012-10-17","Statement":[]}'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in bucket policy retrieval."""
        error_response = {
            'Error': {
                'Code': 'NoSuchBucketPolicy',
                'Message': 'The bucket policy does not exist'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_bucket_policy.side_effect = ClientError(
            error_response, 'GetBucketPolicy'
        )
        
        result = s3_service.get_bucket_policy('test-bucket')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchBucketPolicy'
        assert result['operation'] == 'get_bucket_policy for bucket test-bucket'

class TestGetBucketLogging:
    """Tests for get_bucket_logging method."""
    
    def test_success(self, s3_service, mock_client):
        """Test successful retrieval of bucket logging settings."""
        mock_response = {
            'LoggingEnabled': {
                'TargetBucket': 'log-bucket',
                'TargetPrefix': 'logs/'
            }
        }
        mock_client.get_bucket_logging.return_value = mock_response
        
        result = s3_service.get_bucket_logging('test-bucket')
        
        mock_client.get_bucket_logging.assert_called_once_with(Bucket='test-bucket')
        assert result['success'] is True
        assert result['LoggingEnabled']['TargetBucket'] == 'log-bucket'
        assert result['LoggingEnabled']['TargetPrefix'] == 'logs/'
    
    def test_no_logging_enabled(self, s3_service, mock_client):
        """Test when logging is not enabled for a bucket."""
        mock_client.get_bucket_logging.return_value = {}
        
        result = s3_service.get_bucket_logging('test-bucket')
        
        assert result['success'] is True
        assert result['LoggingEnabled'] == {}
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in get_bucket_logging."""
        error_response = {
            'Error': {
                'Code': 'NoSuchBucket',
                'Message': 'The specified bucket does not exist'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_bucket_logging.side_effect = ClientError(
            error_response, 'GetBucketLogging'
        )
        
        result = s3_service.get_bucket_logging('test-bucket')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchBucket'
        assert result['operation'] == 'get_bucket_logging for bucket test-bucket'

class TestPutBucketLogging:
    """Tests for put_bucket_logging method."""
    
    def test_success(self, s3_service, mock_client):
        """Test successful enabling of bucket logging."""
        logging_config = {
            'TargetBucket': 'log-bucket',
            'TargetPrefix': 'logs/'
        }
        
        result = s3_service.put_bucket_logging('test-bucket', logging_config)
        
        mock_client.put_bucket_logging.assert_called_once_with(
            Bucket='test-bucket',
            BucketLoggingStatus={'LoggingEnabled': logging_config}
        )
        assert result['success'] is True
        assert result['message'] == 'Logging enabled successfully for bucket test-bucket'
    
    def test_error(self, s3_service, mock_client):
        """Test error handling in put_bucket_logging."""
        error_response = {
            'Error': {
                'Code': 'InvalidTargetBucketForLogging',
                'Message': 'Target bucket for logging does not exist'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.put_bucket_logging.side_effect = ClientError(
            error_response, 'PutBucketLogging'
        )
        
        result = s3_service.put_bucket_logging('test-bucket', {'TargetBucket': 'nonexistent-bucket'})
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidTargetBucketForLogging'
        assert result['operation'] == 'put_bucket_logging for bucket test-bucket'