"""Unit tests for CIS 1.9 fix implementation."""

import pytest
from unittest.mock import MagicMock, patch
from providers.aws.controls.cis_1_9.cis_1_9_fix import execute
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
    finding.check_id = "cis_1_9"
    finding.status = CheckResult.STATUS_FAIL
    finding.status_extended = "Initial finding status"
    return finding

def test_already_compliant(mock_session, mock_logger, mock_service_factory, mock_finding):
    """Test when password policy is already compliant."""
    # Mock IAM service response
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'PasswordReusePrevention': 24
        }
    }
    
    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "already prevents reuse" in result.status_extended
    mock_iam.update_account_password_policy.assert_not_called()

def test_successful_fix(mock_session, mock_logger, mock_service_factory, mock_finding):
    """Test successful password policy update."""
    # Mock IAM service responses
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'PasswordReusePrevention': 5
        }
    }
    
    mock_iam.update_account_password_policy.return_value = {
        'success': True
    }
    
    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "updated to prevent reuse" in result.status_extended
    mock_iam.update_account_password_policy.assert_called_once_with({
        'PasswordReusePrevention': 24
    })

def test_no_existing_policy(mock_session, mock_logger, mock_service_factory, mock_finding):
    """Test when no password policy exists."""
    # Mock IAM service responses
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'NoSuchEntity: The request was rejected because no password policy exists.'
    }
    
    mock_iam.update_account_password_policy.return_value = {
        'success': True
    }
    
    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "updated to prevent reuse" in result.status_extended
    mock_iam.update_account_password_policy.assert_called_once_with({
        'PasswordReusePrevention': 24
    })

def test_update_failure(mock_session, mock_logger, mock_service_factory, mock_finding):
    """Test when password policy update fails."""
    # Mock IAM service responses
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'PasswordReusePrevention': 5
        }
    }
    
    mock_iam.update_account_password_policy.return_value = {
        'success': False,
        'error_message': 'Failed to update policy'
    }
    
    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "Failed to update IAM password policy" in result.status_extended
    mock_iam.update_account_password_policy.assert_called_once_with({
        'PasswordReusePrevention': 24
    })

def test_get_policy_error(mock_session, mock_logger, mock_service_factory, mock_finding):
    """Test when getting password policy fails with non-NoSuchEntity error."""
    # Mock IAM service responses
    mock_iam = MagicMock()
    mock_service_factory.get_service.return_value = mock_iam
    
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'AWS API Error'
    }
    
    # Execute fix
    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "Error checking password policy" in result.status_extended
    mock_iam.update_account_password_policy.assert_not_called()
