"""Unit tests for AWS service base class."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from providers.aws.services.base import AWSServiceBase

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
    return session

@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    with patch('logging.getLogger') as mock:
        yield mock.return_value

@pytest.fixture
def base_service(mock_session, mock_logger):
    """Create an AWSServiceBase instance with mocked dependencies."""
    return AWSServiceBase(mock_session)

class TestInit:
    """Tests for AWSServiceBase initialization."""
    
    def test_init_without_region(self, mock_session):
        """Test initialization without region name."""
        service = AWSServiceBase(mock_session)
        assert service.session == mock_session
        assert service.region_name is None
    
    def test_init_with_region(self, mock_session):
        """Test initialization with region name."""
        service = AWSServiceBase(mock_session, region_name='us-west-2')
        assert service.session == mock_session
        assert service.region_name == 'us-west-2'

class TestGetClient:
    """Tests for _get_client method."""
    
    def test_success(self, base_service, mock_session):
        """Test successful client creation."""
        client = base_service._get_client('s3')
        mock_session.client.assert_called_once_with('s3', region_name=None)
        assert client == mock_session.client.return_value
    
    def test_success_with_region(self, mock_session):
        """Test successful client creation with region."""
        service = AWSServiceBase(mock_session, region_name='us-west-2')
        client = service._get_client('s3')
        mock_session.client.assert_called_once_with('s3', region_name='us-west-2')
        assert client == mock_session.client.return_value
    
    def test_error(self, base_service, mock_session, mock_logger):
        """Test error handling in client creation."""
        error = Exception('Test error')
        mock_session.client.side_effect = error
        
        with pytest.raises(Exception) as exc_info:
            base_service._get_client('s3')
        
        assert str(exc_info.value) == 'Test error'
        mock_logger.error.assert_called_once_with('Error creating s3 client: Test error')

class TestHandleError:
    """Tests for _handle_error method."""
    
    def test_client_error(self, base_service, mock_logger):
        """Test handling of ClientError."""
        error_response = {
            'Error': {
                'Code': 'TestError',
                'Message': 'Test error message'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        error = ClientError(error_response, 'TestOperation')
        
        result = base_service._handle_error(error, 'test_operation')
        
        assert result['success'] is False
        assert result['operation'] == 'test_operation'
        assert result['error_type'] == 'ClientError'
        assert result['error_message'] == "An error occurred (TestError) when calling the TestOperation operation: Test error message"
        assert result['error_code'] == 'TestError'
        assert result['request_id'] == '1234567890'
        assert result['http_status'] == 400
        mock_logger.error.assert_called_once()
    
    def test_general_exception(self, base_service, mock_logger):
        """Test handling of general Exception."""
        error = ValueError('Test error')
        
        result = base_service._handle_error(error, 'test_operation')
        
        assert result['success'] is False
        assert result['operation'] == 'test_operation'
        assert result['error_type'] == 'ValueError'
        assert result['error_message'] == 'Test error'
        assert 'error_code' not in result
        assert 'request_id' not in result
        assert 'http_status' not in result
        mock_logger.error.assert_called_once()
    
    def test_error_with_missing_metadata(self, base_service, mock_logger):
        """Test handling of ClientError with missing metadata fields."""
        error_response = {
            'Error': {
                'Code': 'TestError',
                'Message': 'Test error message'
            },
            'ResponseMetadata': {}
        }
        error = ClientError(error_response, 'TestOperation')
        
        result = base_service._handle_error(error, 'test_operation')
        
        assert result['success'] is False
        assert result['operation'] == 'test_operation'
        assert result['error_code'] == 'TestError'
        assert result['request_id'] is None
        assert result['http_status'] is None
        mock_logger.error.assert_called_once()
