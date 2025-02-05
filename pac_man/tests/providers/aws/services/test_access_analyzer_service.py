"""Unit tests for AccessAnalyzerService."""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from providers.aws.services.access_analyzer_service import AccessAnalyzerService

@pytest.fixture
def access_analyzer_service():
    """Create AccessAnalyzerService instance with mocked session."""
    mock_session = MagicMock()
    return AccessAnalyzerService(mock_session)

def test_list_analyzers_success(access_analyzer_service):
    """Test successful listing of analyzers."""
    # Mock response from AWS
    mock_response = {
        'analyzers': [
            {
                'arn': 'arn:aws:access-analyzer:us-west-2:123456789012:analyzer/test-analyzer',
                'name': 'test-analyzer',
                'status': 'ACTIVE',
                'tags': {'Environment': 'Production'}
            }
        ]
    }
    access_analyzer_service.client.list_analyzers = MagicMock(return_value=mock_response)
    
    # Execute test
    result = access_analyzer_service.list_analyzers()
    
    # Verify results
    assert result['success'] is True
    assert len(result['analyzers']) == 1
    analyzer = result['analyzers'][0]
    assert analyzer['name'] == 'test-analyzer'
    assert analyzer['status'] == 'ACTIVE'
    assert analyzer['tags'] == {'Environment': 'Production'}
    
    # Verify AWS was called correctly
    access_analyzer_service.client.list_analyzers.assert_called_once()

def test_list_analyzers_empty_response(access_analyzer_service):
    """Test successful listing of analyzers when no analyzers exist."""
    # Mock empty response from AWS
    mock_response = {'analyzers': []}
    access_analyzer_service.client.list_analyzers = MagicMock(return_value=mock_response)
    
    # Execute test
    result = access_analyzer_service.list_analyzers()
    
    # Verify results
    assert result['success'] is True
    assert len(result['analyzers']) == 0
    
    # Verify AWS was called correctly
    access_analyzer_service.client.list_analyzers.assert_called_once()

def test_list_analyzers_client_error(access_analyzer_service):
    """Test handling of ClientError when listing analyzers."""
    # Mock error response
    error_response = {
        'Error': {
            'Code': 'AccessDeniedException',
            'Message': 'User is not authorized to perform access-analyzer:ListAnalyzers'
        },
        'ResponseMetadata': {
            'RequestId': '1234567890',
            'HTTPStatusCode': 403
        }
    }
    access_analyzer_service.client.list_analyzers = MagicMock(
        side_effect=ClientError(error_response, 'ListAnalyzers')
    )
    
    # Execute test
    result = access_analyzer_service.list_analyzers()
    
    # Verify error handling
    assert result['success'] is False
    assert result['error_type'] == 'ClientError'
    assert result['error_code'] == 'AccessDeniedException'
    assert result['operation'] == 'list_analyzers'
    assert 'not authorized' in result['error_message'].lower()

def test_list_analyzers_general_error(access_analyzer_service):
    """Test handling of general exceptions when listing analyzers."""
    # Mock general error
    access_analyzer_service.client.list_analyzers = MagicMock(
        side_effect=Exception('Unexpected error')
    )
    
    # Execute test
    result = access_analyzer_service.list_analyzers()
    
    # Verify error handling
    assert result['success'] is False
    assert result['error_type'] == 'Exception'
    assert result['operation'] == 'list_analyzers'
    assert 'unexpected error' in result['error_message'].lower()

def test_create_analyzer_success(access_analyzer_service):
    """Test successful creation of an analyzer."""
    analyzer_name = "test-analyzer"
    mock_response = {
        'arn': f'arn:aws:access-analyzer:us-west-2:123456789012:analyzer/{analyzer_name}'
    }
    access_analyzer_service.client.create_analyzer = MagicMock(return_value=mock_response)
    
    # Execute test
    result = access_analyzer_service.create_analyzer(analyzer_name)
    
    # Verify results
    assert result['success'] is True
    assert 'arn' in result
    assert analyzer_name in result['arn']
    
    # Verify AWS was called correctly
    access_analyzer_service.client.create_analyzer.assert_called_once_with(
        analyzerName=analyzer_name,
        type='ACCOUNT'
    )

def test_create_analyzer_client_error(access_analyzer_service):
    """Test handling of ClientError when creating an analyzer."""
    # Mock error response
    error_response = {
        'Error': {
            'Code': 'ValidationException',
            'Message': 'Invalid analyzer name'
        },
        'ResponseMetadata': {
            'RequestId': '1234567890',
            'HTTPStatusCode': 400
        }
    }
    access_analyzer_service.client.create_analyzer = MagicMock(
        side_effect=ClientError(error_response, 'CreateAnalyzer')
    )
    
    # Execute test
    result = access_analyzer_service.create_analyzer("invalid-name")
    
    # Verify error handling
    assert result['success'] is False
    assert result['error_type'] == 'ClientError'
    assert result['error_code'] == 'ValidationException'
    assert result['operation'] == 'create_analyzer'
    assert 'invalid analyzer name' in result['error_message'].lower()

def test_create_analyzer_general_error(access_analyzer_service):
    """Test handling of general exceptions when creating an analyzer."""
    # Mock general error
    access_analyzer_service.client.create_analyzer = MagicMock(
        side_effect=Exception('Unexpected error')
    )
    
    # Execute test
    result = access_analyzer_service.create_analyzer("test-analyzer")
    
    # Verify error handling
    assert result['success'] is False
    assert result['error_type'] == 'Exception'
    assert result['operation'] == 'create_analyzer'
    assert 'unexpected error' in result['error_message'].lower()
