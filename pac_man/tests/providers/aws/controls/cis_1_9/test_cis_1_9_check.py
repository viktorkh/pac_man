"""Unit tests for CIS 1.9 check implementation."""

import pytest
from unittest.mock import MagicMock, patch
from providers.aws.controls.cis_1_9.cis_1_9_check import execute
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
    
    # Mock STS service (same mock since we're using return_value)
    # Individual tests can override if needed
    
    return mock_factory

def test_password_policy_compliant(mock_session, mock_logger, mock_service_factory):
    """Test when password policy is compliant (prevents reuse of 24 passwords)."""
    # Mock service responses
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    mock_sts.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }
    
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'PasswordReusePrevention': 24
        }
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_PASS
    assert "prevents password reuse for 24 passwords" in result.status_extended
    assert result.resource_id == "PasswordPolicy-123456789012"

def test_password_policy_non_compliant(mock_session, mock_logger, mock_service_factory):
    """Test when password policy is non-compliant (prevents reuse of less than 24 passwords)."""
    # Mock service responses
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    mock_sts.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }
    
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'PasswordReusePrevention': 5
        }
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_FAIL
    assert "prevents password reuse for 5 passwords" in result.status_extended
    assert result.resource_id == "PasswordPolicy-123456789012"

def test_no_password_policy(mock_session, mock_logger, mock_service_factory):
    """Test when no password policy exists."""
    # Mock service responses
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    mock_sts.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }
    
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'NoSuchEntity: The request was rejected because no password policy exists.'
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_FAIL
    assert "No IAM password policy is set" in result.status_extended
    assert result.resource_id == "PasswordPolicy-123456789012"

def test_api_error(mock_session, mock_logger, mock_service_factory):
    """Test when AWS API call fails."""
    # Mock service responses
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    mock_sts.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }
    
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'AWS API Error'
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "Error executing check" in result.status_extended
    assert result.resource_id == "PasswordPolicy-123456789012"

def test_sts_error(mock_session, mock_logger, mock_service_factory):
    """Test when STS get_caller_identity fails."""
    # Mock service responses
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    mock_sts.get_caller_identity.return_value = {
        'success': False,
        'error_message': 'Failed to get identity'
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "Failed to get AWS Account ID" in result.status_extended

def test_unexpected_exception(mock_session, mock_logger, mock_service_factory):
    """Test when an unexpected exception occurs."""
    # Mock service responses
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    # Make get_account_password_policy raise an unexpected exception
    mock_iam.get_account_password_policy.side_effect = Exception("Unexpected error")
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "Error executing check" in result.status_extended
    mock_logger.error.assert_called_with("Error executing CIS 1.9 check: Unexpected error")
