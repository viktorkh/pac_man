"""Unit tests for EC2Service."""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from providers.aws.services.ec2_service import EC2Service

@pytest.fixture
def ec2_service():
    """Create EC2Service instance with mocked session."""
    mock_session = MagicMock()
    return EC2Service(mock_session)

def test_list_active_regions_success(ec2_service):
    """Test successful listing of active regions."""
    # Mock response from AWS
    mock_response = {
        'Regions': [
            {'RegionName': 'us-east-1', 'OptInStatus': 'opt-in-not-required'},
            {'RegionName': 'us-west-2', 'OptInStatus': 'opted-in'},
            {'RegionName': 'ap-east-1', 'OptInStatus': 'not-opted-in'}  # Should be excluded
        ]
    }
    ec2_service.client.describe_regions = MagicMock(return_value=mock_response)
    
    # Execute test
    result = ec2_service.list_active_regions()
    
    # Verify results
    assert result['success'] is True
    assert len(result['regions']) == 2
    assert 'us-east-1' in result['regions']
    assert 'us-west-2' in result['regions']
    assert 'ap-east-1' not in result['regions']
    
    # Verify AWS was called correctly
    ec2_service.client.describe_regions.assert_called_once_with(AllRegions=False)

def test_list_active_regions_client_error(ec2_service):
    """Test handling of ClientError when listing regions."""
    # Mock error response
    error_response = {
        'Error': {
            'Code': 'UnauthorizedOperation',
            'Message': 'You are not authorized to perform this operation.'
        },
        'ResponseMetadata': {
            'RequestId': '1234567890',
            'HTTPStatusCode': 403
        }
    }
    ec2_service.client.describe_regions = MagicMock(
        side_effect=ClientError(error_response, 'DescribeRegions')
    )
    
    # Execute test
    result = ec2_service.list_active_regions()
    
    # Verify error handling
    assert result['success'] is False
    assert result['error_type'] == 'ClientError'
    assert result['error_code'] == 'UnauthorizedOperation'
    assert result['operation'] == 'list_active_regions'
    assert 'not authorized' in result['error_message'].lower()

def test_list_active_regions_general_error(ec2_service):
    """Test handling of general exceptions when listing regions."""
    # Mock general error
    ec2_service.client.describe_regions = MagicMock(
        side_effect=Exception('Unexpected error')
    )
    
    # Execute test
    result = ec2_service.list_active_regions()
    
    # Verify error handling
    assert result['success'] is False
    assert result['error_type'] == 'Exception'
    assert result['operation'] == 'list_active_regions'
    assert 'unexpected error' in result['error_message'].lower()
