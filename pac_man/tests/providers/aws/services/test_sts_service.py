"""Unit tests for STS service."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from providers.aws.services.sts_service import STSService

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
    return session

@pytest.fixture
def sts_service(mock_session):
    """Create an STSService instance with a mock session."""
    return STSService(mock_session)

@pytest.fixture
def mock_client(sts_service):
    """Get the mock STS client from the service."""
    return sts_service.client

def test_init(mock_session):
    """Test STSService initialization."""
    service = STSService(mock_session)
    mock_session.client.assert_called_once_with('sts', region_name=None)
    assert service.client == mock_session.client.return_value

class TestGetCallerIdentity:
    """Tests for get_caller_identity method."""
    
    def test_success(self, sts_service, mock_client):
        """Test successful caller identity retrieval."""
        mock_response = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/test-user',
            'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
        }
        mock_client.get_caller_identity.return_value = mock_response
        
        result = sts_service.get_caller_identity()
        
        mock_client.get_caller_identity.assert_called_once()
        assert result['success'] is True
        assert result['account_id'] == '123456789012'
        assert result['arn'] == 'arn:aws:iam::123456789012:user/test-user'
        assert result['user_id'] == 'AIDACKCEVSQ6C2EXAMPLE'
    
    def test_error(self, sts_service, mock_client):
        """Test error handling in caller identity retrieval."""
        error_response = {
            'Error': {
                'Code': 'InvalidClientTokenId',
                'Message': 'The security token included in the request is invalid'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 403
            }
        }
        mock_client.get_caller_identity.side_effect = ClientError(
            error_response, 'GetCallerIdentity'
        )
        
        result = sts_service.get_caller_identity()
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidClientTokenId'
        assert result['operation'] == 'get_caller_identity'
