"""Unit tests for CIS 1.14 fix implementation."""

import pytest
from unittest.mock import MagicMock
import io
from datetime import datetime, timezone, timedelta
from providers.aws.controls.cis_1_14.cis_1_14_fix import execute, rotate_access_key, get_users_with_old_keys
from providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_session():
    return MagicMock()

@pytest.fixture
def mock_logger():
    return MagicMock()

@pytest.fixture
def mock_service_factory():
    mock_factory = MagicMock()
    
    # Mock IAM service
    mock_iam = MagicMock()
    mock_factory.get_service.return_value = mock_iam
    
    return mock_factory

@pytest.fixture
def mock_finding():
    finding = CheckResult()
    finding.check_id = "cis_1_14"
    finding.status = CheckResult.STATUS_FAIL
    finding.status_extended = "Multiple users have access keys older than 90 days"
    finding.resource_id = "test-user"
    finding.resource_arn = "arn:aws:iam::123456789012:user/test-user"
    finding.region = "global"
    return finding

def test_no_old_access_keys(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test when no access keys are older than 90 days."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Create credential report with recent keys
    current_time = datetime.now(timezone.utc)
    recent_time = (current_time - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    csv_content = f"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service\ntest-user,arn:aws:iam::123456789012:user/test-user,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,not_supported,true,true,{recent_time},2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A"
    
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "No access keys older than 90 days found" in result.status_extended

def test_rotate_keys_success(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test successful rotation of old access keys."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Create credential report with old keys
    current_time = datetime.now(timezone.utc)
    old_time = (current_time - timedelta(days=100)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    csv_content = f"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service\ntest-user,arn:aws:iam::123456789012:user/test-user,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,not_supported,true,true,{old_time},2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A"
    
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    # Mock successful key creation and deactivation
    mock_iam.create_access_key.return_value = {
        'success': True,
        'access_key': {
            'AccessKeyId': 'AKIANEW',
            'SecretAccessKey': 'secret'
        }
    }
    
    mock_iam.update_access_key.return_value = {
        'success': True,
        'message': 'Access key status updated successfully'
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "Successfully rotated all old access keys" in result.status_extended
    mock_iam.create_access_key.assert_called_once()
    mock_iam.update_access_key.assert_called_once()

def test_rotate_keys_partial_failure(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test partial failure when rotating access keys."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Create credential report with old keys for multiple users
    current_time = datetime.now(timezone.utc)
    old_time = (current_time - timedelta(days=100)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    csv_content = f"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service
user1,arn:aws:iam::123456789012:user/user1,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,not_supported,true,true,{old_time},2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A
user2,arn:aws:iam::123456789012:user/user2,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,not_supported,true,true,{old_time},2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A"""
    
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    # Mock create_access_key to succeed for user1 and fail for user2
    def mock_create_key(user_name):
        if user_name == 'user1':
            return {
                'success': True,
                'access_key': {
                    'AccessKeyId': f'AKIANEW_{user_name}',
                    'SecretAccessKey': 'secret'
                }
            }
        else:
            return {
                'success': False,
                'error_message': 'Failed to create key'
            }
    
    mock_iam.create_access_key.side_effect = mock_create_key
    
    # Mock update_access_key to always succeed
    mock_iam.update_access_key.return_value = {
        'success': True,
        'message': 'Access key status updated successfully'
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "Failed to rotate some access keys" in result.status_extended
    assert "Successfully rotated: 1" in result.status_extended

def test_credential_report_error(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test when getting credential report fails."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    mock_iam.get_credential_report.return_value = {
        'success': False,
        'error_message': 'Failed to generate credential report'
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "Failed to get credential report" in result.status_extended

def test_rotate_access_key_helper():
    """Test the rotate_access_key helper function."""
    mock_iam = MagicMock()
    mock_logger = MagicMock()
    
    # Mock successful key rotation
    mock_iam.create_access_key.return_value = {
        'success': True,
        'access_key': {
            'AccessKeyId': 'AKIANEW',
            'SecretAccessKey': 'secret'
        }
    }
    
    mock_iam.update_access_key.return_value = {
        'success': True,
        'message': 'Success'
    }
    
    result = rotate_access_key(mock_iam, 'test-user', 'AKIAOLD', mock_logger)
    
    assert result['success']
    assert 'new_key' in result
    assert result['new_key']['AccessKeyId'] == 'AKIANEW'
    mock_iam.create_access_key.assert_called_once_with('test-user')
    mock_iam.update_access_key.assert_called_once_with('test-user', 'AKIAOLD', 'Inactive')

def test_rotate_access_key_update_failure():
    """Test when update_access_key fails after creating a new key."""
    mock_iam = MagicMock()
    mock_logger = MagicMock()
    
    # Mock successful key creation but failed update
    mock_iam.create_access_key.return_value = {
        'success': True,
        'access_key': {
            'AccessKeyId': 'AKIANEW',
            'SecretAccessKey': 'secret'
        }
    }
    
    mock_iam.update_access_key.return_value = {
        'success': False,
        'error_message': 'Failed to update key status'
    }
    
    result = rotate_access_key(mock_iam, 'test-user', 'AKIAOLD', mock_logger)
    
    assert not result['success']
    assert "Failed to deactivate old access key" in result['error_message']
    mock_iam.create_access_key.assert_called_once_with('test-user')
    mock_iam.update_access_key.assert_called_once_with('test-user', 'AKIAOLD', 'Inactive')

def test_rotate_access_key_unexpected_error():
    """Test when an unexpected exception occurs during key rotation."""
    mock_iam = MagicMock()
    mock_logger = MagicMock()
    
    # Mock an unexpected exception
    mock_iam.create_access_key.side_effect = Exception("Unexpected error")
    
    result = rotate_access_key(mock_iam, 'test-user', 'AKIAOLD', mock_logger)
    
    assert not result['success']
    assert "Unexpected error" in result['error_message']
    mock_iam.create_access_key.assert_called_once_with('test-user')
    mock_iam.update_access_key.assert_not_called()

def test_get_users_with_old_keys_helper():
    """Test the get_users_with_old_keys helper function."""
    current_time = datetime.now(timezone.utc)
    old_time = (current_time - timedelta(days=100)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    recent_time = (current_time - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    cred_report = [
        {
            'user': 'user1',
            'access_key_1_last_rotated': old_time,
            'access_key_1_active': 'AKIA1',
            'access_key_2_last_rotated': 'N/A',
            'access_key_2_active': 'N/A'
        },
        {
            'user': 'user2',
            'access_key_1_last_rotated': recent_time,
            'access_key_1_active': 'AKIA2',
            'access_key_2_last_rotated': 'N/A',
            'access_key_2_active': 'N/A'
        }
    ]
    
    result = get_users_with_old_keys(cred_report)
    
    assert len(result) == 1
    assert result[0][0] == 'user1'  # user name
    assert result[0][1] == 'AKIA1'  # key id
    assert result[0][2] > 90  # age in days
