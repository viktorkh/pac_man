"""Unit tests for CIS 1.13 check implementation."""

import pytest
from unittest.mock import MagicMock
import io
from providers.aws.controls.cis_1_13.cis_1_13_check import execute
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

def test_root_no_active_keys(mock_session, mock_logger, mock_service_factory):
    """Test when root account has no active access keys."""
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
    
    # Create credential report CSV content
    csv_content = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    # Mock empty list of users since we're only testing root
    mock_iam.list_users.return_value = {
        'success': True,
        'users': []
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    # Verify root account result
    root_result = next(r for r in results if ':root' in r.resource_id)
    assert root_result.status == CheckResult.STATUS_PASS
    assert "Root account has 0 active access keys" in root_result.status_extended

def test_root_with_active_keys(mock_session, mock_logger, mock_service_factory):
    """Test when root account has active access keys."""
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
    
    # Create credential report with active keys for root
    csv_content = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,not_supported,not_supported,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    mock_iam.list_users.return_value = {
        'success': True,
        'users': []
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    root_result = next(r for r in results if ':root' in r.resource_id)
    assert root_result.status == CheckResult.STATUS_FAIL
    assert "Root account has 1 active access key(s)" in root_result.status_extended

def test_user_single_active_key(mock_session, mock_logger, mock_service_factory):
    """Test when IAM user has one active access key."""
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
    
    # Root with no keys
    csv_content = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    # User with one active key
    mock_iam.list_users.return_value = {
        'success': True,
        'users': [{
            'UserName': 'test-user',
            'Arn': 'arn:aws:iam::123456789012:user/test-user'
        }]
    }
    
    mock_iam.list_access_keys.return_value = {
        'success': True,
        'access_keys': [{
            'AccessKeyId': 'AKIA1234567890',
            'Status': 'Active'
        }]
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    user_result = next(r for r in results if r.resource_id == 'test-user')
    assert user_result.status == CheckResult.STATUS_PASS
    assert "has 1 active access key" in user_result.status_extended

def test_user_multiple_active_keys(mock_session, mock_logger, mock_service_factory):
    """Test when IAM user has multiple active access keys."""
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
    
    # Root with no keys
    csv_content = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    # User with multiple active keys
    mock_iam.list_users.return_value = {
        'success': True,
        'users': [{
            'UserName': 'test-user',
            'Arn': 'arn:aws:iam::123456789012:user/test-user'
        }]
    }
    
    mock_iam.list_access_keys.return_value = {
        'success': True,
        'access_keys': [
            {
                'AccessKeyId': 'AKIA1234567890',
                'Status': 'Active'
            },
            {
                'AccessKeyId': 'AKIA0987654321',
                'Status': 'Active'
            }
        ]
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    user_result = next(r for r in results if r.resource_id == 'test-user')
    assert user_result.status == CheckResult.STATUS_FAIL
    assert "has 2 active access keys" in user_result.status_extended

def test_credential_report_error(mock_session, mock_logger, mock_service_factory):
    """Test when getting credential report fails."""
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
    
    mock_iam.get_credential_report.return_value = {
        'success': False,
        'error_message': 'Failed to generate credential report'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "Failed to get credential report" in results[0].status_extended

def test_list_users_error(mock_session, mock_logger, mock_service_factory):
    """Test when listing IAM users fails."""
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
    
    # Root with no keys
    csv_content = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    mock_iam.list_users.return_value = {
        'success': False,
        'error_message': 'Failed to list IAM users'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 2  # Root result + error result
    root_result = next(r for r in results if ':root' in r.resource_id)
    assert root_result.status == CheckResult.STATUS_PASS
    assert "Root account has 0 active access keys" in root_result.status_extended
    
    error_result = next(r for r in results if ':users' in r.resource_id)
    assert error_result.status == CheckResult.STATUS_ERROR
    assert "Failed to list IAM users" in error_result.status_extended
