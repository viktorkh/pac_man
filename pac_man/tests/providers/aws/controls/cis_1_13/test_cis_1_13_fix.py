"""Unit tests for CIS 1.13 fix implementation."""

import pytest
from unittest.mock import MagicMock
from providers.aws.controls.cis_1_13.cis_1_13_fix import execute
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
    finding.check_id = "cis_1_13"
    finding.status = CheckResult.STATUS_FAIL
    finding.status_extended = "Multiple users have more than one active access key"
    finding.resource_id = "test-user"
    finding.resource_arn = "arn:aws:iam::123456789012:user/test-user"
    finding.region = "global"
    return finding

def test_no_users_with_multiple_keys(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test when no users have multiple active access keys."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Mock list_users response
    mock_iam.list_users.return_value = {
        'success': True,
        'users': [
            {'UserName': 'user1', 'Arn': 'arn:aws:iam::123456789012:user/user1'},
            {'UserName': 'user2', 'Arn': 'arn:aws:iam::123456789012:user/user2'}
        ]
    }
    
    # Mock list_access_keys responses - each user has one active key
    mock_iam.list_access_keys.return_value = {
        'success': True,
        'access_keys': [{'AccessKeyId': 'AKIA123', 'Status': 'Active'}]
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "No users with multiple active access keys found" in result.status_extended

def test_fix_multiple_keys_success(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test successful fix for users with multiple active access keys."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Mock list_users response
    mock_iam.list_users.return_value = {
        'success': True,
        'users': [{'UserName': 'user1', 'Arn': 'arn:aws:iam::123456789012:user/user1'}]
    }
    
    # Mock list_access_keys response - user has multiple active keys
    mock_iam.list_access_keys.return_value = {
        'success': True,
        'access_keys': [
            {'AccessKeyId': 'AKIA123', 'Status': 'Active'},
            {'AccessKeyId': 'AKIA456', 'Status': 'Active'}
        ]
    }
    
    # Mock update_access_key response
    mock_iam.update_access_key.return_value = {
        'success': True,
        'message': 'Access key status updated successfully'
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "Successfully deactivated extra access keys for all affected users" in result.status_extended
    assert "user1" in result.status_extended
    mock_iam.update_access_key.assert_called_once()

def test_fix_multiple_keys_partial_failure(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test partial failure when fixing users with multiple active access keys."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Mock list_users response
    mock_iam.list_users.return_value = {
        'success': True,
        'users': [
            {'UserName': 'user1', 'Arn': 'arn:aws:iam::123456789012:user/user1'},
            {'UserName': 'user2', 'Arn': 'arn:aws:iam::123456789012:user/user2'}
        ]
    }
    
    # Mock list_access_keys responses
    def mock_list_access_keys(user_name):
        return {
            'success': True,
            'access_keys': [
                {'AccessKeyId': f'AKIA123_{user_name}', 'Status': 'Active'},
                {'AccessKeyId': f'AKIA456_{user_name}', 'Status': 'Active'}
            ]
        }
    
    mock_iam.list_access_keys.side_effect = mock_list_access_keys
    
    # Mock update_access_key to succeed for user1 and fail for user2
    def mock_update_access_key(user_name, access_key_id, status):
        if user_name == 'user1':
            return {'success': True, 'message': 'Success'}
        else:
            return {'success': False, 'error_message': 'Failed to update key'}
    
    mock_iam.update_access_key.side_effect = mock_update_access_key
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "Failed to deactivate extra access keys for users: user2" in result.status_extended
    assert "Successfully fixed for users: user1" in result.status_extended

def test_list_users_error(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test when listing IAM users fails."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Mock list_users to fail
    mock_iam.list_users.return_value = {
        'success': False,
        'error_message': 'Failed to list users'
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "Failed to list IAM users" in result.status_extended

def test_list_access_keys_error(mock_session, mock_finding, mock_logger, mock_service_factory):
    """Test when listing access keys fails."""
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    # Mock list_users response
    mock_iam.list_users.return_value = {
        'success': True,
        'users': [{'UserName': 'user1', 'Arn': 'arn:aws:iam::123456789012:user/user1'}]
    }
    
    # Mock list_access_keys to fail
    mock_iam.list_access_keys.return_value = {
        'success': False,
        'error_message': 'Failed to list access keys'
    }
    
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "Could not verify access key status for users: user1" in result.status_extended
    mock_logger.error.assert_called_with(
        "Failed to list access keys for user user1: Failed to list access keys"
    )
