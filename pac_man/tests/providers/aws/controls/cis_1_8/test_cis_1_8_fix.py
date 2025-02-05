"""Unit tests for CIS 1.8 fix implementation."""

import pytest
from providers.aws.controls.cis_1_8.cis_1_8_fix import execute
from providers.aws.lib.check_result import CheckResult

def test_update_existing_policy(mock_service_factory, mock_session, mock_logger):
    """Test updating an existing non-compliant password policy."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock current policy with non-compliant length
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'MinimumPasswordLength': 8,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'AllowUsersToChangePassword': True
        }
    }
    
    # Mock successful policy update
    mock_iam.update_account_password_policy.return_value = {
        'success': True,
        'message': 'Password policy updated successfully'
    }
    
    finding = CheckResult()
    result = execute(mock_session, finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "updated successfully" in result.status_extended.lower()
    
    # Verify update called with correct parameters
    mock_iam.update_account_password_policy.assert_called_once()
    call_args = mock_iam.update_account_password_policy.call_args[0][0]
    assert call_args['MinimumPasswordLength'] == 14
    assert call_args['RequireSymbols'] == True
    assert call_args['RequireNumbers'] == True
    assert call_args['RequireUppercaseCharacters'] == True
    assert call_args['RequireLowercaseCharacters'] == True
    assert call_args['AllowUsersToChangePassword'] == True

def test_create_new_policy(mock_service_factory, mock_session, mock_logger):
    """Test creating a new password policy when none exists."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock no existing policy
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'NoSuchEntity'
    }
    
    # Mock successful policy creation
    mock_iam.update_account_password_policy.return_value = {
        'success': True,
        'message': 'Password policy created successfully'
    }
    
    finding = CheckResult()
    result = execute(mock_session, finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "updated successfully" in result.status_extended.lower()
    
    # Verify update called with correct parameters for new policy
    mock_iam.update_account_password_policy.assert_called_once()
    call_args = mock_iam.update_account_password_policy.call_args[0][0]
    assert call_args['MinimumPasswordLength'] == 14
    assert call_args['RequireSymbols'] == True
    assert call_args['RequireNumbers'] == True
    assert call_args['RequireUppercaseCharacters'] == True
    assert call_args['RequireLowercaseCharacters'] == True
    assert call_args['AllowUsersToChangePassword'] == True

def test_already_compliant_policy(mock_service_factory, mock_session, mock_logger):
    """Test when password policy is already compliant."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock current policy with compliant length
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'MinimumPasswordLength': 16,  # Already greater than required 14
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'AllowUsersToChangePassword': True
        }
    }
    
    finding = CheckResult()
    result = execute(mock_session, finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "already compliant" in result.status_extended.lower()
    
    # Verify no update was attempted
    mock_iam.update_account_password_policy.assert_not_called()

def test_error_getting_policy(mock_service_factory, mock_session, mock_logger):
    """Test handling of error getting password policy."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock error response for get_account_password_policy
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'Internal Server Error'
    }
    
    finding = CheckResult()
    result = execute(mock_session, finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to retrieve password policy" in result.status_extended.lower()
    
    # Verify no update was attempted
    mock_iam.update_account_password_policy.assert_not_called()

def test_error_updating_policy(mock_service_factory, mock_session, mock_logger):
    """Test handling of error updating password policy."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock current non-compliant policy
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'MinimumPasswordLength': 8,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'AllowUsersToChangePassword': True
        }
    }
    
    # Mock error response for update_account_password_policy
    mock_iam.update_account_password_policy.return_value = {
        'success': False,
        'error_message': 'Failed to update policy'
    }
    
    finding = CheckResult()
    result = execute(mock_session, finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to update password policy" in result.status_extended.lower()

def test_unexpected_error(mock_service_factory, mock_session, mock_logger):
    """Test handling of unexpected errors."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock unexpected exception
    mock_iam.get_account_password_policy.side_effect = Exception("Unexpected error")
    
    finding = CheckResult()
    result = execute(mock_session, finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "error executing fix" in result.status_extended.lower()
