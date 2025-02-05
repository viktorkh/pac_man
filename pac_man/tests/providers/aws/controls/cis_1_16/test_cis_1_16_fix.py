"""Unit tests for CIS 1.16 fix implementation."""

import pytest
from unittest.mock import patch
from providers.aws.controls.cis_1_16.cis_1_16_fix import execute
from providers.aws.lib.check_result import CheckResult

@pytest.fixture
def cis_1_16_finding(mock_finding):
    """Create a CIS 1.16 specific finding."""
    mock_finding.check_id = 'cis_1_16'
    mock_finding.check_description = 'Ensure IAM policies that allow full "*:*" administrative privileges are not attached'
    mock_finding.resource_id = 'FullAdminPolicy'
    mock_finding.resource_arn = 'arn:aws:iam::123456789012:policy/FullAdminPolicy'
    mock_finding.status = CheckResult.STATUS_FAIL
    return mock_finding

def test_successful_fix(mock_service_factory, mock_session, mock_logger, cis_1_16_finding, mock_success_response):
    """Test successful policy detachment from all entities."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock get_policy response
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    
    # Mock get_policy_version response with full admin privileges
    mock_iam.get_policy_version.return_value = {
        'success': True,
        'policy_version': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            }
        }
    }
    
    # Mock list_entities_for_policy response
    mock_iam.list_entities_for_policy.return_value = {
        'success': True,
        'policy_roles': [{'RoleName': 'Role1'}],
        'policy_users': [{'UserName': 'User1'}],
        'policy_groups': [{'GroupName': 'Group1'}]
    }
    
    # Mock successful detachment operations
    mock_iam.detach_role_policy.return_value = mock_success_response
    mock_iam.detach_user_policy.return_value = mock_success_response
    mock_iam.detach_group_policy.return_value = mock_success_response
    
    with patch('providers.aws.lib.whitelist.whitelist.is_whitelisted', return_value=None):
        result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
        
        assert result.status == CheckResult.STATUS_PASS
        assert "successfully detached" in result.status_extended.lower()
        mock_iam.detach_role_policy.assert_called_once()
        mock_iam.detach_user_policy.assert_called_once()
        mock_iam.detach_group_policy.assert_called_once()

def test_whitelisted_role_skip(mock_service_factory, mock_session, mock_logger, cis_1_16_finding, mock_success_response):
    """Test when policy is attached to a whitelisted role."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock get_policy response
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    
    # Mock get_policy_version response with full admin privileges
    mock_iam.get_policy_version.return_value = {
        'success': True,
        'policy_version': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            }
        }
    }
    
    # Mock list_entities_for_policy response with whitelisted role
    mock_iam.list_entities_for_policy.return_value = {
        'success': True,
        'policy_roles': [{'RoleName': 'WhitelistedRole'}],
        'policy_users': [],
        'policy_groups': []
    }
    
    with patch('providers.aws.lib.whitelist.whitelist.is_whitelisted', return_value="Whitelisted for testing"):
        result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
        
        assert result.status == CheckResult.STATUS_FAIL
        assert "whitelisted" in result.status_extended.lower()
        mock_iam.detach_role_policy.assert_not_called()

def test_muted_finding(mock_service_factory, mock_session, mock_logger, cis_1_16_finding):
    """Test when finding is muted."""
    cis_1_16_finding.status = "MUTED"
    cis_1_16_finding.mute_reason = "Muted for testing"
    
    result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
    
    assert result.status == "MUTED"
    assert "fix skipped" in result.status_extended.lower()

def test_get_policy_error(mock_service_factory, mock_session, mock_logger, cis_1_16_finding, mock_error_response):
    """Test handling of get_policy error."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_policy.return_value = mock_error_response
    
    result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to get policy details" in result.status_extended.lower()

def test_get_policy_version_error(mock_service_factory, mock_session, mock_logger, cis_1_16_finding, mock_error_response):
    """Test handling of get_policy_version error."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock get_policy success
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    
    # Mock get_policy_version error
    mock_iam.get_policy_version.return_value = mock_error_response
    
    result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to get policy version details" in result.status_extended.lower()

def test_list_entities_error(mock_service_factory, mock_session, mock_logger, cis_1_16_finding, mock_error_response):
    """Test handling of list_entities_for_policy error."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock get_policy and get_policy_version success
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    mock_iam.get_policy_version.return_value = {
        'success': True,
        'policy_version': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            }
        }
    }
    
    # Mock list_entities_for_policy error
    mock_iam.list_entities_for_policy.return_value = mock_error_response
    
    result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to list entities for policy" in result.status_extended.lower()

def test_detachment_error(mock_service_factory, mock_session, mock_logger, cis_1_16_finding, mock_error_response):
    """Test handling of policy detachment error."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock get_policy and get_policy_version success
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    mock_iam.get_policy_version.return_value = {
        'success': True,
        'policy_version': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            }
        }
    }
    
    # Mock list_entities_for_policy success
    mock_iam.list_entities_for_policy.return_value = {
        'success': True,
        'policy_roles': [{'RoleName': 'Role1'}],
        'policy_users': [{'UserName': 'User1'}],
        'policy_groups': [{'GroupName': 'Group1'}]
    }
    
    # Mock detachment errors
    mock_iam.detach_role_policy.return_value = mock_error_response
    mock_iam.detach_user_policy.return_value = mock_error_response
    mock_iam.detach_group_policy.return_value = mock_error_response
    
    with patch('providers.aws.lib.whitelist.whitelist.is_whitelisted', return_value=None):
        result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
        
        assert result.status == CheckResult.STATUS_FAIL
        assert "failed to detach policy" in result.status_extended.lower()

def test_unexpected_error(mock_service_factory, mock_session, mock_logger, cis_1_16_finding):
    """Test handling of unexpected errors."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_policy.side_effect = Exception("Unexpected error")
    
    result = execute(mock_session, cis_1_16_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "error executing fix" in result.status_extended.lower()
