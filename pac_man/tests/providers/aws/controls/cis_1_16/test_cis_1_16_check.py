"""Unit tests for CIS 1.16 check implementation."""

import pytest
from unittest.mock import Mock
from providers.aws.controls.cis_1_16.cis_1_16_check import execute
from providers.aws.lib.check_result import CheckResult
from providers.aws.lib.whitelist import Whitelist

@pytest.fixture
def mock_whitelist():
    """Create a mock whitelist instance."""
    mock = Mock(spec=Whitelist)
    mock.is_whitelisted.return_value = None
    return mock

@pytest.fixture
def mock_policy_with_full_admin():
    """Mock policy with full administrative privileges."""
    return {
        'PolicyVersion': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            }
        }
    }

@pytest.fixture
def mock_policy_without_full_admin():
    """Mock policy without full administrative privileges."""
    return {
        'PolicyVersion': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': ['s3:*'],
                    'Resource': '*'
                }]
            }
        }
    }

def test_policy_with_full_admin(mock_service_factory, mock_session, mock_logger, mock_success_response, mock_whitelist):
    """Test when policy has full administrative privileges."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock list_policies response
    mock_iam.list_policies.return_value = {
        'success': True,
        'policies': [{
            'PolicyName': 'FullAdminPolicy',
            'Arn': 'arn:aws:iam::123456789012:policy/FullAdminPolicy'
        }]
    }
    
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
        'policy_roles': [],
        'policy_users': [],
        'policy_groups': []
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "allows full administrative privileges" in results[0].status_extended.lower()
    assert results[0].resource_id == 'FullAdminPolicy'

def test_policy_without_full_admin(mock_service_factory, mock_session, mock_logger, mock_success_response, mock_whitelist):
    """Test when policy does not have full administrative privileges."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock list_policies response
    mock_iam.list_policies.return_value = {
        'success': True,
        'policies': [{
            'PolicyName': 'LimitedPolicy',
            'Arn': 'arn:aws:iam::123456789012:policy/LimitedPolicy'
        }]
    }
    
    # Mock get_policy response
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    
    # Mock get_policy_version response without full admin privileges
    mock_iam.get_policy_version.return_value = {
        'success': True,
        'policy_version': {
            'Document': {
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': ['s3:*'],
                    'Resource': '*'
                }]
            }
        }
    }
    
    # Mock list_entities_for_policy response
    mock_iam.list_entities_for_policy.return_value = {
        'success': True,
        'policy_roles': [],
        'policy_users': [],
        'policy_groups': []
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert "does not allow full administrative privileges" in results[0].status_extended.lower()
    assert results[0].resource_id == 'LimitedPolicy'

def test_policy_with_whitelisted_role(mock_service_factory, mock_session, mock_logger, mock_success_response, mock_whitelist):
    """Test when policy is attached to a whitelisted role."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock list_policies response
    mock_iam.list_policies.return_value = {
        'success': True,
        'policies': [{
            'PolicyName': 'FullAdminPolicy',
            'Arn': 'arn:aws:iam::123456789012:policy/FullAdminPolicy'
        }]
    }
    
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
    
    # Configure whitelist mock to return a whitelisting reason for the test role
    mock_whitelist.is_whitelisted.return_value = "Whitelisted for testing"
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == "MUTED"
    assert "whitelisted roles" in results[0].status_extended.lower()
    assert results[0].resource_id == 'FullAdminPolicy'

def test_policy_with_no_whitelist(mock_service_factory, mock_session, mock_logger, mock_success_response):
    """Test when no whitelist is provided."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock list_policies response
    mock_iam.list_policies.return_value = {
        'success': True,
        'policies': [{
            'PolicyName': 'FullAdminPolicy',
            'Arn': 'arn:aws:iam::123456789012:policy/FullAdminPolicy'
        }]
    }
    
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
    
    # Mock list_entities_for_policy response with a role
    mock_iam.list_entities_for_policy.return_value = {
        'success': True,
        'policy_roles': [{'RoleName': 'SomeRole'}],
        'policy_users': [],
        'policy_groups': []
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory, None)
    
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert "allows full administrative privileges" in results[0].status_extended.lower()
    assert results[0].resource_id == 'FullAdminPolicy'

def test_get_policy_version_error(mock_service_factory, mock_session, mock_logger, mock_error_response, mock_whitelist):
    """Test handling of get_policy_version error."""
    mock_iam = mock_service_factory.get_service('iam')
    policy_name = 'TestPolicy'
    error_message = "Failed to get policy version"
    expected_error = f"Error getting policy version for {policy_name}: {error_message}"
    
    # Mock list_policies success
    mock_iam.list_policies.return_value = {
        'success': True,
        'policies': [{
            'PolicyName': policy_name,
            'Arn': 'arn:aws:iam::123456789012:policy/TestPolicy'
        }]
    }
    
    # Mock get_policy success
    mock_iam.get_policy.return_value = {
        'success': True,
        'policy': {'DefaultVersionId': 'v1'}
    }
    
    # Mock get_policy_version error with specific error message
    mock_iam.get_policy_version.return_value = {
        'success': False,
        'error_message': error_message
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert results[0].status_extended == expected_error
    mock_logger.error.assert_called_with(expected_error)

def test_list_policies_error(mock_service_factory, mock_session, mock_logger, mock_error_response, mock_whitelist):
    """Test handling of list_policies error."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.list_policies.return_value = mock_error_response
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "error listing iam policies" in results[0].status_extended.lower()

def test_get_policy_error(mock_service_factory, mock_session, mock_logger, mock_error_response, mock_whitelist):
    """Test handling of get_policy error."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock list_policies success
    mock_iam.list_policies.return_value = {
        'success': True,
        'policies': [{
            'PolicyName': 'TestPolicy',
            'Arn': 'arn:aws:iam::123456789012:policy/TestPolicy'
        }]
    }
    
    # Mock get_policy error
    mock_iam.get_policy.return_value = mock_error_response
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "error getting policy" in results[0].status_extended.lower()

def test_unexpected_error(mock_service_factory, mock_session, mock_logger, mock_whitelist):
    """Test handling of unexpected errors."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.list_policies.side_effect = Exception("Unexpected error")
    
    results = execute(mock_session, mock_logger, mock_service_factory, mock_whitelist)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "error executing check" in results[0].status_extended.lower()
