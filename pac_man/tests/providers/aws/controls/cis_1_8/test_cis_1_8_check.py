"""Unit tests for CIS 1.8 check implementation."""

import pytest
import json
from providers.aws.controls.cis_1_8.cis_1_8_check import execute
from providers.aws.lib.check_result import CheckResult

def test_compliant_password_policy(mock_service_factory, mock_session, mock_logger, mock_sts_response):
    """Test when password policy meets minimum length requirement."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_sts = mock_service_factory.get_service('sts')
    
    # Mock password policy response
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'MinimumPasswordLength': 14,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'AllowUsersToChangePassword': True,
            'ExpirePasswords': True,
            'MaxPasswordAge': 90,
            'PasswordReusePrevention': 24,
            'HardExpiry': False
        }
    }
    
    # Mock STS response
    mock_sts.get_caller_identity.return_value = mock_sts_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_PASS
    assert "minimum password length is 14" in result.status_extended.lower()
    assert result.resource_id == f"PasswordPolicy-{mock_sts_response['account_id']}"
    assert result.resource_arn == f"arn:aws:iam::{mock_sts_response['account_id']}:account-password-policy"
    assert result.region == 'global'

def test_non_compliant_password_policy(mock_service_factory, mock_session, mock_logger, mock_sts_response):
    """Test when password policy does not meet minimum length requirement."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_sts = mock_service_factory.get_service('sts')
    
    # Mock password policy response with length < 14
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'MinimumPasswordLength': 8,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True
        }
    }
    
    mock_sts.get_caller_identity.return_value = mock_sts_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_FAIL
    assert "current minimum password length is 8" in result.status_extended.lower()
    assert "should be at least 14 characters" in result.status_extended.lower()

def test_no_password_policy(mock_service_factory, mock_session, mock_logger, mock_sts_response):
    """Test when no password policy is set."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_sts = mock_service_factory.get_service('sts')
    
    # Mock no password policy response
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'NoSuchEntity'
    }
    
    mock_sts.get_caller_identity.return_value = mock_sts_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_FAIL
    assert "no password policy is set" in result.status_extended.lower()
    assert result.resource_details == '{}'

def test_error_getting_password_policy(mock_service_factory, mock_session, mock_logger, mock_sts_response):
    """Test handling of error getting password policy."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_sts = mock_service_factory.get_service('sts')
    
    # Mock error response
    mock_iam.get_account_password_policy.return_value = {
        'success': False,
        'error_message': 'Internal Server Error'
    }
    
    mock_sts.get_caller_identity.return_value = mock_sts_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "failed to get password policy" in result.status_extended.lower()

def test_error_getting_account_id(mock_service_factory, mock_session, mock_logger):
    """Test handling of error getting AWS account ID."""
    mock_sts = mock_service_factory.get_service('sts')
    
    # Mock error response for get_caller_identity
    mock_sts.get_caller_identity.return_value = {
        'success': False,
        'error_message': 'Failed to get caller identity'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "failed to get aws account id" in result.status_extended.lower()

def test_check_result_initialization(mock_service_factory, mock_session, mock_logger, mock_sts_response):
    """Test proper initialization of CheckResult."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_sts = mock_service_factory.get_service('sts')
    
    # Mock successful responses
    mock_iam.get_account_password_policy.return_value = {
        'success': True,
        'policy': {
            'MinimumPasswordLength': 14
        }
    }
    mock_sts.get_caller_identity.return_value = mock_sts_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    
    assert result.check_id == 'cis_1_8'
    assert result.check_description == 'Ensure IAM password policy requires minimum length of 14 or greater'
    assert result.resource_id == f"PasswordPolicy-{mock_sts_response['account_id']}"
    assert result.resource_arn == f"arn:aws:iam::{mock_sts_response['account_id']}:account-password-policy"
    assert result.region == 'global'
    assert isinstance(result.resource_tags, list)
    assert len(result.resource_tags) == 0  # Password policies don't have tags
    assert json.loads(result.resource_details) == {'MinimumPasswordLength': 14}
