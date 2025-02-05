"""Unit tests for Config service."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from providers.aws.services.config_service import ConfigService

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
    return session

@pytest.fixture
def config_service(mock_session):
    """Create a ConfigService instance with a mock session."""
    return ConfigService(mock_session)

@pytest.fixture
def mock_client(config_service):
    """Get the mock Config client from the service."""
    return config_service.client

def test_init(mock_session):
    """Test ConfigService initialization."""
    service = ConfigService(mock_session)
    mock_session.client.assert_called_once_with('config', region_name=None)
    assert service.client == mock_session.client.return_value

class TestDescribeConfigurationRecorders:
    """Tests for describe_configuration_recorders method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful configuration recorders description."""
        mock_response = {
            'ConfigurationRecorders': [
                {
                    'name': 'test-recorder',
                    'roleARN': 'arn:aws:iam::123456789012:role/test-role',
                    'recordingGroup': {
                        'allSupported': True,
                        'includeGlobalResources': True
                    }
                }
            ]
        }
        mock_client.describe_configuration_recorders.return_value = mock_response
        
        result = config_service.describe_configuration_recorders()
        
        mock_client.describe_configuration_recorders.assert_called_once()
        assert result['success'] is True
        assert len(result['configuration_recorders']) == 1
        assert result['configuration_recorders'][0]['name'] == 'test-recorder'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in configuration recorders description."""
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
        mock_client.describe_configuration_recorders.side_effect = ClientError(
            error_response, 'DescribeConfigurationRecorders'
        )
        
        result = config_service.describe_configuration_recorders()
        
        assert result['success'] is False
        assert result['error_code'] == 'InternalError'
        assert result['operation'] == 'describe_configuration_recorders'

class TestDescribeConfigurationRecorderStatus:
    """Tests for describe_configuration_recorder_status method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful configuration recorder status retrieval."""
        mock_response = {
            'ConfigurationRecordersStatus': [
                {
                    'name': 'test-recorder',
                    'recording': True,
                    'lastStatus': 'SUCCESS'
                }
            ]
        }
        mock_client.describe_configuration_recorder_status.return_value = mock_response
        
        result = config_service.describe_configuration_recorder_status()
        
        mock_client.describe_configuration_recorder_status.assert_called_once()
        assert result['success'] is True
        assert len(result['recorder_statuses']) == 1
        assert result['recorder_statuses'][0]['name'] == 'test-recorder'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in configuration recorder status retrieval."""
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
        mock_client.describe_configuration_recorder_status.side_effect = ClientError(
            error_response, 'DescribeConfigurationRecorderStatus'
        )
        
        result = config_service.describe_configuration_recorder_status()
        
        assert result['success'] is False
        assert result['error_code'] == 'InternalError'
        assert result['operation'] == 'describe_configuration_recorder_status'

class TestPutConfigurationRecorder:
    """Tests for put_configuration_recorder method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful configuration recorder creation/update."""
        recorder_config = {
            'name': 'test-recorder',
            'roleARN': 'arn:aws:iam::123456789012:role/test-role',
            'recordingGroup': {
                'allSupported': True,
                'includeGlobalResources': True
            }
        }
        
        result = config_service.put_configuration_recorder(recorder_config)
        
        mock_client.put_configuration_recorder.assert_called_once_with(
            ConfigurationRecorder=recorder_config
        )
        assert result['success'] is True
        assert result['message'] == 'Configuration recorder test-recorder created/updated successfully'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in configuration recorder creation/update."""
        error_response = {
            'Error': {
                'Code': 'InvalidParameterValue',
                'Message': 'Invalid configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.put_configuration_recorder.side_effect = ClientError(
            error_response, 'PutConfigurationRecorder'
        )
        
        result = config_service.put_configuration_recorder({})
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidParameterValue'
        assert result['operation'] == 'put_configuration_recorder'

class TestStartConfigurationRecorder:
    """Tests for start_configuration_recorder method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful configuration recorder start."""
        result = config_service.start_configuration_recorder('test-recorder')
        
        mock_client.start_configuration_recorder.assert_called_once_with(
            ConfigurationRecorderName='test-recorder'
        )
        assert result['success'] is True
        assert result['message'] == 'Configuration recorder test-recorder started successfully'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in configuration recorder start."""
        error_response = {
            'Error': {
                'Code': 'NoSuchConfigurationRecorderException',
                'Message': 'Recorder not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.start_configuration_recorder.side_effect = ClientError(
            error_response, 'StartConfigurationRecorder'
        )
        
        result = config_service.start_configuration_recorder('test-recorder')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchConfigurationRecorderException'
        assert result['operation'] == 'start_configuration_recorder for recorder test-recorder'

class TestStopConfigurationRecorder:
    """Tests for stop_configuration_recorder method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful configuration recorder stop."""
        result = config_service.stop_configuration_recorder('test-recorder')
        
        mock_client.stop_configuration_recorder.assert_called_once_with(
            ConfigurationRecorderName='test-recorder'
        )
        assert result['success'] is True
        assert result['message'] == 'Configuration recorder test-recorder stopped successfully'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in configuration recorder stop."""
        error_response = {
            'Error': {
                'Code': 'NoSuchConfigurationRecorderException',
                'Message': 'Recorder not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.stop_configuration_recorder.side_effect = ClientError(
            error_response, 'StopConfigurationRecorder'
        )
        
        result = config_service.stop_configuration_recorder('test-recorder')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchConfigurationRecorderException'
        assert result['operation'] == 'stop_configuration_recorder for recorder test-recorder'

class TestPutDeliveryChannel:
    """Tests for put_delivery_channel method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful delivery channel creation/update."""
        channel_config = {
            'name': 'test-channel',
            's3BucketName': 'test-bucket',
            'snsTopicARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'
        }
        
        result = config_service.put_delivery_channel(channel_config)
        
        mock_client.put_delivery_channel.assert_called_once_with(
            DeliveryChannel=channel_config
        )
        assert result['success'] is True
        assert result['message'] == 'Delivery channel test-channel created/updated successfully'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in delivery channel creation/update."""
        error_response = {
            'Error': {
                'Code': 'InvalidParameterValue',
                'Message': 'Invalid configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.put_delivery_channel.side_effect = ClientError(
            error_response, 'PutDeliveryChannel'
        )
        
        result = config_service.put_delivery_channel({})
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidParameterValue'
        assert result['operation'] == 'put_delivery_channel'

class TestDescribeDeliveryChannels:
    """Tests for describe_delivery_channels method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful delivery channels description."""
        mock_response = {
            'DeliveryChannels': [
                {
                    'name': 'test-channel',
                    's3BucketName': 'test-bucket',
                    'snsTopicARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'
                }
            ]
        }
        mock_client.describe_delivery_channels.return_value = mock_response
        
        result = config_service.describe_delivery_channels()
        
        mock_client.describe_delivery_channels.assert_called_once()
        assert result['success'] is True
        assert len(result['delivery_channels']) == 1
        assert result['delivery_channels'][0]['name'] == 'test-channel'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in delivery channels description."""
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
        mock_client.describe_delivery_channels.side_effect = ClientError(
            error_response, 'DescribeDeliveryChannels'
        )
        
        result = config_service.describe_delivery_channels()
        
        assert result['success'] is False
        assert result['error_code'] == 'InternalError'
        assert result['operation'] == 'describe_delivery_channels'

class TestDescribeDeliveryChannelStatus:
    """Tests for describe_delivery_channel_status method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful delivery channel status retrieval."""
        mock_response = {
            'DeliveryChannelsStatus': [
                {
                    'name': 'test-channel',
                    'configHistoryDeliveryInfo': {
                        'lastStatus': 'SUCCESS',
                        'lastAttemptTime': '2023-01-01T00:00:00Z'
                    }
                }
            ]
        }
        mock_client.describe_delivery_channel_status.return_value = mock_response
        
        result = config_service.describe_delivery_channel_status()
        
        mock_client.describe_delivery_channel_status.assert_called_once()
        assert result['success'] is True
        assert len(result['delivery_channel_status']) == 1
        assert result['delivery_channel_status'][0]['name'] == 'test-channel'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in delivery channel status retrieval."""
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
        mock_client.describe_delivery_channel_status.side_effect = ClientError(
            error_response, 'DescribeDeliveryChannelStatus'
        )
        
        result = config_service.describe_delivery_channel_status()
        
        assert result['success'] is False
        assert result['error_code'] == 'InternalError'
        assert result['operation'] == 'describe_delivery_channel_status'

class TestPutConfigRule:
    """Tests for put_config_rule method."""
    
    def test_success(self, config_service, mock_client):
        """Test successful Config rule creation/update."""
        rule_config = {
            'ConfigRuleName': 'test-rule',
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': 'REQUIRED_TAGS'
            }
        }
        
        result = config_service.put_config_rule(rule_config)
        
        mock_client.put_config_rule.assert_called_once_with(
            ConfigRule=rule_config
        )
        assert result['success'] is True
        assert result['message'] == 'Config rule test-rule created/updated successfully'
    
    def test_error(self, config_service, mock_client):
        """Test error handling in Config rule creation/update."""
        error_response = {
            'Error': {
                'Code': 'InvalidParameterValue',
                'Message': 'Invalid configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.put_config_rule.side_effect = ClientError(
            error_response, 'PutConfigRule'
        )
        
        result = config_service.put_config_rule({})
        
        assert result['success'] is False
        assert result['error_code'] == 'InvalidParameterValue'
        assert result['operation'] == 'put_config_rule'
