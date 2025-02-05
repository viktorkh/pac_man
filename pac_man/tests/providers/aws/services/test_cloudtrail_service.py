"""Unit tests for CloudTrail service."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from providers.aws.services.cloudtrail_service import CloudTrailService

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
    return session

@pytest.fixture
def cloudtrail_service(mock_session):
    """Create a CloudTrailService instance with a mock session."""
    return CloudTrailService(mock_session)

@pytest.fixture
def mock_client(cloudtrail_service):
    """Get the mock CloudTrail client from the service."""
    return cloudtrail_service.client

def test_init(mock_session):
    """Test CloudTrailService initialization."""
    service = CloudTrailService(mock_session)
    mock_session.client.assert_called_once_with('cloudtrail', region_name=None)
    assert service.client == mock_session.client.return_value

class TestDescribeTrails:
    """Tests for describe_trails method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful trail description."""
        mock_response = {
            'trailList': [
                {
                    'Name': 'test-trail',
                    'S3BucketName': 'test-bucket',
                    'IsMultiRegionTrail': True
                }
            ]
        }
        mock_client.describe_trails.return_value = mock_response
        
        result = cloudtrail_service.describe_trails(include_shadow_trails=True)
        
        mock_client.describe_trails.assert_called_once_with(includeShadowTrails=True)
        assert result['success'] is True
        assert len(result['trails']) == 1
        assert result['trails'][0]['Name'] == 'test-trail'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in trail description."""
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
        mock_client.describe_trails.side_effect = ClientError(
            error_response, 'DescribeTrails'
        )
        
        result = cloudtrail_service.describe_trails()
        
        assert result['success'] is False
        assert result['error_code'] == 'InternalError'
        assert result['operation'] == 'describe_trails'

class TestGetTrailStatus:
    """Tests for get_trail_status method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful trail status retrieval."""
        mock_response = {
            'IsLogging': True,
            'LatestDeliveryTime': '2023-01-01T00:00:00Z',
            'StartLoggingTime': '2023-01-01T00:00:00Z'
        }
        mock_client.get_trail_status.return_value = mock_response
        
        result = cloudtrail_service.get_trail_status('test-trail')
        
        mock_client.get_trail_status.assert_called_once_with(Name='test-trail')
        assert result['success'] is True
        assert result['status']['is_logging'] is True
        assert result['status']['latest_delivery_time'] == '2023-01-01T00:00:00Z'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in trail status retrieval."""
        error_response = {
            'Error': {
                'Code': 'TrailNotFoundException',
                'Message': 'Trail not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_trail_status.side_effect = ClientError(
            error_response, 'GetTrailStatus'
        )
        
        result = cloudtrail_service.get_trail_status('test-trail')
        
        assert result['success'] is False
        assert result['error_code'] == 'TrailNotFoundException'
        assert result['operation'] == 'get_trail_status for trail test-trail'

class TestGetEventSelectors:
    """Tests for get_event_selectors method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful event selectors retrieval."""
        mock_response = {
            'EventSelectors': [
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': True
                }
            ],
            'AdvancedEventSelectors': []
        }
        mock_client.get_event_selectors.return_value = mock_response
        
        result = cloudtrail_service.get_event_selectors('test-trail')
        
        mock_client.get_event_selectors.assert_called_once_with(TrailName='test-trail')
        assert result['success'] is True
        assert len(result['event_selectors']) == 1
        assert result['event_selectors'][0]['ReadWriteType'] == 'All'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in event selectors retrieval."""
        error_response = {
            'Error': {
                'Code': 'TrailNotFoundException',
                'Message': 'Trail not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_event_selectors.side_effect = ClientError(
            error_response, 'GetEventSelectors'
        )
        
        result = cloudtrail_service.get_event_selectors('test-trail')
        
        assert result['success'] is False
        assert result['error_code'] == 'TrailNotFoundException'
        assert result['operation'] == 'get_event_selectors for trail test-trail'

class TestCreateTrail:
    """Tests for create_trail method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful trail creation."""
        trail_config = {
            'Name': 'test-trail',
            'S3BucketName': 'test-bucket',
            'IsMultiRegionTrail': True
        }
        mock_response = {
            'Name': 'test-trail',
            'S3BucketName': 'test-bucket',
            'IsMultiRegionTrail': True
        }
        mock_client.create_trail.return_value = mock_response
        
        result = cloudtrail_service.create_trail(trail_config)
        
        mock_client.create_trail.assert_called_once_with(**trail_config)
        assert result['success'] is True
        assert result['trail']['Name'] == 'test-trail'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in trail creation."""
        error_response = {
            'Error': {
                'Code': 'InvalidParameterException',
                'Message': 'Invalid trail configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.create_trail.side_effect = ClientError(
            error_response, 'CreateTrail'
        )
        
        result = cloudtrail_service.create_trail({})
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidParameterException'
        assert result['operation'] == 'create_trail'

class TestUpdateTrail:
    """Tests for update_trail method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful trail update."""
        trail_config = {
            'Name': 'test-trail',
            'S3BucketName': 'new-bucket'
        }
        mock_response = {
            'Name': 'test-trail',
            'S3BucketName': 'new-bucket'
        }
        mock_client.update_trail.return_value = mock_response
        
        result = cloudtrail_service.update_trail(trail_config)
        
        mock_client.update_trail.assert_called_once_with(**trail_config)
        assert result['success'] is True
        assert result['trail']['S3BucketName'] == 'new-bucket'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in trail update."""
        error_response = {
            'Error': {
                'Code': 'TrailNotFoundException',
                'Message': 'Trail not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.update_trail.side_effect = ClientError(
            error_response, 'UpdateTrail'
        )
        
        result = cloudtrail_service.update_trail({'Name': 'test-trail'})
        
        assert result['success'] is False
        assert result['error_code'] == 'TrailNotFoundException'
        assert result['operation'] == 'update_trail for trail test-trail'

class TestStartLogging:
    """Tests for start_logging method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful logging start."""
        result = cloudtrail_service.start_logging('test-trail')
        
        mock_client.start_logging.assert_called_once_with(Name='test-trail')
        assert result['success'] is True
        assert result['message'] == 'Logging started for trail test-trail'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in logging start."""
        error_response = {
            'Error': {
                'Code': 'TrailNotFoundException',
                'Message': 'Trail not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.start_logging.side_effect = ClientError(
            error_response, 'StartLogging'
        )
        
        result = cloudtrail_service.start_logging('test-trail')
        
        assert result['success'] is False
        assert result['error_code'] == 'TrailNotFoundException'
        assert result['operation'] == 'start_logging for trail test-trail'

class TestStopLogging:
    """Tests for stop_logging method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful logging stop."""
        result = cloudtrail_service.stop_logging('test-trail')
        
        mock_client.stop_logging.assert_called_once_with(Name='test-trail')
        assert result['success'] is True
        assert result['message'] == 'Logging stopped for trail test-trail'
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in logging stop."""
        error_response = {
            'Error': {
                'Code': 'TrailNotFoundException',
                'Message': 'Trail not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.stop_logging.side_effect = ClientError(
            error_response, 'StopLogging'
        )
        
        result = cloudtrail_service.stop_logging('test-trail')
        
        assert result['success'] is False
        assert result['error_code'] == 'TrailNotFoundException'
        assert result['operation'] == 'stop_logging for trail test-trail'

class TestPutEventSelectors:
    """Tests for put_event_selectors method."""
    
    def test_success(self, cloudtrail_service, mock_client):
        """Test successful event selectors update."""
        event_selectors = [
            {
                'ReadWriteType': 'All',
                'IncludeManagementEvents': True
            }
        ]
        mock_response = {
            'EventSelectors': event_selectors
        }
        mock_client.put_event_selectors.return_value = mock_response
        
        result = cloudtrail_service.put_event_selectors('test-trail', event_selectors)
        
        mock_client.put_event_selectors.assert_called_once_with(
            TrailName='test-trail',
            EventSelectors=event_selectors
        )
        assert result['success'] is True
        assert result['event_selectors'] == event_selectors
    
    def test_error(self, cloudtrail_service, mock_client):
        """Test error handling in event selectors update."""
        error_response = {
            'Error': {
                'Code': 'TrailNotFoundException',
                'Message': 'Trail not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.put_event_selectors.side_effect = ClientError(
            error_response, 'PutEventSelectors'
        )
        
        result = cloudtrail_service.put_event_selectors('test-trail', [])
        
        assert result['success'] is False
        assert result['error_code'] == 'TrailNotFoundException'
        assert result['operation'] == 'put_event_selectors for trail test-trail'
