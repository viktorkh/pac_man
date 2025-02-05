"""Tests for CIS 3.5 fix implementation."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from providers.aws.lib.check_result import CheckResult
from providers.aws.controls.cis_3_5.cis_3_5_fix import execute

@pytest.fixture
def mock_logger():
    """Create a mock logger fixture."""
    return Mock()

@pytest.fixture
def mock_session():
    """Create a mock boto3 session fixture."""
    session = Mock()
    # Mock SNS client
    mock_sns = Mock()
    mock_sns.create_topic.return_value = {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:config-topic'}
    session.client.return_value = mock_sns
    return session

@pytest.fixture
def mock_finding():
    """Create a mock finding fixture with realistic test data."""
    finding = CheckResult()
    finding.check_id = "cis_3_5"
    finding.check_description = "Ensure AWS Config is enabled"
    finding.region = "us-east-1"
    finding.status = "FAIL"
    finding.status_extended = "AWS Config is not enabled"
    finding.resource_id = "AWS Config Recorder - us-east-1"
    finding.resource_arn = "arn:aws:config:us-east-1:123456789012:config-recorder"
    finding.resource_details = ""
    finding.resource_tags = []
    # Mock init_remediation method
    finding.init_remediation = Mock()
    finding.init_remediation.return_value = Mock()
    return finding

@pytest.fixture
def mock_service_factory():
    """Create a mock service factory."""
    factory = Mock()
    # Mock session for SNS client
    mock_sns = Mock()
    mock_sns.create_topic.return_value = {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:config-topic'}
    mock_session = Mock()
    mock_session.client.return_value = mock_sns
    factory.session = mock_session
    return factory

@pytest.fixture
def mock_services(mock_service_factory):
    """Create mock services with default successful responses."""
    # Mock S3 service
    mock_s3 = Mock()
    mock_s3.create_bucket.return_value = {
        'success': True,
        'message': 'Bucket created successfully'
    }

    # Mock IAM service
    mock_iam = Mock()
    mock_iam.create_role.return_value = {
        'success': True,
        'role': {'Arn': 'arn:aws:iam::123456789012:role/AWSConfigRole'}
    }
    mock_iam.attach_role_policy.return_value = {
        'success': True,
        'message': 'Policy attached successfully'
    }
    mock_iam.get_role.return_value = {
        'success': True,
        'role': {'Arn': 'arn:aws:iam::123456789012:role/AWSConfigRole'}
    }

    # Mock Config service
    mock_config = Mock()
    mock_config.describe_configuration_recorders.return_value = {
        'success': True,
        'configuration_recorders': []
    }
    mock_config.describe_configuration_recorder_status.return_value = {
        'success': True,
        'recorder_statuses': []
    }
    mock_config.put_configuration_recorder.return_value = {
        'success': True,
        'message': 'Recorder created successfully'
    }
    mock_config.put_delivery_channel.return_value = {
        'success': True,
        'message': 'Delivery channel created successfully'
    }
    mock_config.start_configuration_recorder.return_value = {
        'success': True,
        'message': 'Recorder started successfully'
    }

    # Mock STS service
    mock_sts = Mock()
    mock_sts.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }

    def get_service_side_effect(service_name, region=None):
        services = {
            's3': mock_s3,
            'iam': mock_iam,
            'config': mock_config,
            'sts': mock_sts
        }
        return services.get(service_name)

    mock_service_factory.get_service.side_effect = get_service_side_effect

    return {
        's3': mock_s3,
        'iam': mock_iam,
        'config': mock_config,
        'sts': mock_sts
    }

def test_execute_success(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test successful execution of the fix."""
    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert result.status == "PASS"
    assert "Successfully configured AWS Config" in result.status_extended
    assert mock_logger.info.call_count >= 4  # Multiple info logs for each step
    mock_finding.init_remediation().mark_as_success.assert_called_once()

def test_execute_config_already_enabled(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test when AWS Config is already properly configured."""
    # Mock Config service to show Config is already enabled
    mock_services['config'].describe_configuration_recorders.return_value = {
        'success': True,
        'configuration_recorders': [{
            'name': 'default',
            'recordingGroup': {
                'allSupported': True,
                'includeGlobalResourceTypes': True
            }
        }]
    }
    mock_services['config'].describe_configuration_recorder_status.return_value = {
        'success': True,
        'recorder_statuses': [{
            'name': 'default',
            'recording': True,
            'lastStatus': 'SUCCESS'
        }]
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert result.status == "PASS"
    assert "AWS Config is already properly configured" in result.status_extended
    mock_finding.init_remediation().mark_as_success.assert_called_once()

def test_execute_s3_creation_failure(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test handling of S3 bucket creation failure."""
    # Mock S3 service to fail
    mock_services['s3'].create_bucket.return_value = {
        'success': False,
        'error_message': 'Failed to create bucket'
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Failed to create bucket" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()

def test_execute_iam_role_creation_failure(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test handling of IAM role creation failure."""
    # Mock IAM service to fail
    mock_services['iam'].create_role.return_value = {
        'success': False,
        'error_message': 'Failed to create IAM role'
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Failed to create IAM role" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()

def test_execute_config_recorder_creation_failure(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test handling of Config recorder creation failure."""
    # Mock Config service to fail
    mock_services['config'].put_configuration_recorder.return_value = {
        'success': False,
        'error_message': 'Failed to create configuration recorder'
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Failed to create configuration recorder" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()

def test_execute_delivery_channel_creation_failure(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test handling of delivery channel creation failure."""
    # Mock Config service to fail at delivery channel creation
    mock_services['config'].put_delivery_channel.return_value = {
        'success': False,
        'error_message': 'Failed to create delivery channel'
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Failed to create delivery channel" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()

def test_execute_start_recorder_failure(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test handling of starting recorder failure."""
    # Mock Config service to fail at starting recorder
    mock_services['config'].start_configuration_recorder.return_value = {
        'success': False,
        'error_message': 'Failed to start configuration recorder'
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Failed to start configuration recorder" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()

def test_execute_unexpected_error(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test handling of unexpected errors."""
    # Mock service factory to raise an unexpected exception
    mock_service_factory.get_service.side_effect = Exception("Unexpected internal error")

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Fix attempt failed: Unexpected internal error" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()

def test_execute_invalid_region(mock_session, mock_finding, mock_logger, mock_service_factory, mock_services):
    """Test fix execution with invalid region."""
    # Update finding with invalid region
    mock_finding.region = "invalid-region"

    # Mock S3 service to fail for invalid region
    mock_services['s3'].create_bucket.return_value = {
        'success': False,
        'error_message': 'Invalid region specified'
    }

    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    # Verify result
    assert "Invalid region specified" in result.status_extended
    assert mock_logger.error.call_count >= 1
    mock_finding.init_remediation().mark_as_failed.assert_called_once()
