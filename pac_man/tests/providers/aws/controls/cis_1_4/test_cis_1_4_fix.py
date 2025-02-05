"""Unit tests for CIS 1.4 fix implementation."""

import pytest
from providers.aws.controls.cis_1_4.cis_1_4_fix import execute
from providers.aws.lib.check_result import CheckResult

@pytest.fixture
def cis_1_4_finding(mock_finding):
    """Create a CIS 1.4 specific finding."""
    mock_finding.check_id = 'cis_1_4'
    mock_finding.check_description = 'Ensure no root account access key exists'
    mock_finding.resource_id = 'Root Account'
    mock_finding.resource_details = 'AWS root account'
    return mock_finding

def test_successful_fix_key1(mock_service_factory, mock_session, mock_logger, cis_1_4_finding, mock_success_response):
    """Test successful remediation of access key 1."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report showing key 1 active
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    # Mock successful key deletion
    mock_iam.delete_access_key.return_value = mock_success_response
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "successfully deleted" in result.status_extended.lower()
    assert "key 1" in result.status_extended.lower()
    mock_iam.delete_access_key.assert_called_once()

def test_successful_fix_key2(mock_service_factory, mock_session, mock_logger, cis_1_4_finding, mock_success_response):
    """Test successful remediation of access key 2."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report showing key 2 active
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    # Mock successful key deletion
    mock_iam.delete_access_key.return_value = mock_success_response
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "successfully deleted" in result.status_extended.lower()
    assert "key 2" in result.status_extended.lower()
    mock_iam.delete_access_key.assert_called_once()

def test_successful_fix_both_keys(mock_service_factory, mock_session, mock_logger, cis_1_4_finding, mock_success_response):
    """Test successful remediation of both access keys."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report showing both keys active
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    # Mock successful key deletions
    mock_iam.delete_access_key.return_value = mock_success_response
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "successfully deleted" in result.status_extended.lower()
    assert "key 1" in result.status_extended.lower()
    assert "key 2" in result.status_extended.lower()
    assert mock_iam.delete_access_key.call_count == 2

def test_no_keys_to_fix(mock_service_factory, mock_session, mock_logger, cis_1_4_finding):
    """Test when no keys need to be fixed."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report showing no active keys
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_PASS
    assert "no root account access keys found" in result.status_extended.lower()
    mock_iam.delete_access_key.assert_not_called()

def test_credential_report_error(mock_service_factory, mock_session, mock_logger, cis_1_4_finding, mock_error_response):
    """Test handling of credential report error."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_credential_report.return_value = mock_error_response
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "error getting credential report" in result.status_extended.lower()
    mock_iam.delete_access_key.assert_not_called()

def test_key_deletion_error(mock_service_factory, mock_session, mock_logger, cis_1_4_finding, mock_error_response):
    """Test handling of key deletion error."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report showing key 1 active
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    # Mock failed key deletion
    mock_iam.delete_access_key.return_value = mock_error_response
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to delete root access key" in result.status_extended.lower()

def test_unexpected_error(mock_service_factory, mock_session, mock_logger, cis_1_4_finding):
    """Test handling of unexpected errors."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_credential_report.side_effect = Exception("Unexpected error")
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "error executing fix" in result.status_extended.lower()
    mock_iam.delete_access_key.assert_not_called()

def test_malformed_credential_report(mock_service_factory, mock_session, mock_logger, cis_1_4_finding):
    """Test handling of malformed credential report."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock malformed credential report
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'invalid,csv,format'
    }
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_ERROR
    assert "error parsing credential report" in result.status_extended.lower()
    mock_iam.delete_access_key.assert_not_called()

def test_partial_fix_success(mock_service_factory, mock_session, mock_logger, cis_1_4_finding, mock_success_response, mock_error_response):
    """Test when one key deletion succeeds but the other fails."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report showing both keys active
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    # Mock first deletion success, second deletion failure
    mock_iam.delete_access_key.side_effect = [mock_success_response, mock_error_response]
    
    result = execute(mock_session, cis_1_4_finding, mock_logger, mock_service_factory)
    
    assert result.status == CheckResult.STATUS_FAIL
    assert "failed to delete root access key" in result.status_extended.lower()
    assert mock_iam.delete_access_key.call_count == 2
