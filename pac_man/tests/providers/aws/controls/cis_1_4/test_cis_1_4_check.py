"""Unit tests for CIS 1.4 check implementation."""

import pytest
from providers.aws.controls.cis_1_4.cis_1_4_check import execute
from providers.aws.lib.check_result import CheckResult

def test_root_account_no_access_keys(mock_service_factory, mock_session, mock_logger):
    """Test when root account has no access keys."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report response with all required columns
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    # Execute check
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert "no active access keys" in results[0].status_extended.lower()

def test_root_account_with_access_key_1(mock_service_factory, mock_session, mock_logger):
    """Test when root account has access key 1 active."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report response with all required columns
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "key 1" in results[0].status_extended.lower()

def test_root_account_with_access_key_2(mock_service_factory, mock_session, mock_logger):
    """Test when root account has access key 2 active."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report response with all required columns
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "key 2" in results[0].status_extended.lower()

def test_root_account_with_both_access_keys(mock_service_factory, mock_session, mock_logger):
    """Test when root account has both access keys active."""
    mock_iam = mock_service_factory.get_service('iam')
    
    # Mock credential report response with all required columns
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "key 1" in results[0].status_extended.lower()
    assert "key 2" in results[0].status_extended.lower()

def test_credential_report_error(mock_service_factory, mock_session, mock_logger, mock_error_response):
    """Test handling of credential report error."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_credential_report.return_value = mock_error_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "error getting credential report" in results[0].status_extended.lower()

def test_unexpected_error(mock_service_factory, mock_session, mock_logger):
    """Test handling of unexpected errors."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_credential_report.side_effect = Exception("Unexpected error")
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "error executing check" in results[0].status_extended.lower()

def test_check_result_initialization(mock_service_factory, mock_session, mock_logger, mock_sts_response):
    """Test proper initialization of CheckResult."""
    mock_iam = mock_service_factory.get_service('iam')
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': b'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,true,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00,false,2023-01-01T00:00:00+00:00'
    }
    
    mock_sts = mock_service_factory.get_service('sts')
    mock_sts.get_caller_identity.return_value = mock_sts_response
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    result = results[0]
    
    assert result.check_id == 'cis_1_4'
    assert result.check_description == 'Ensure no root account access key exists'
    assert result.resource_id == 'Root Account'
    assert result.region == 'global'
    assert isinstance(result.resource_tags, list)
    assert result.resource_details == 'AWS root account'
    assert result.resource_arn == f"arn:aws:iam::{mock_sts_response['account_id']}:root"
