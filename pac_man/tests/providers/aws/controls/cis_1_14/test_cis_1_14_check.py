"""Unit tests for CIS 1.14 check implementation."""

import pytest
from unittest.mock import MagicMock
import io
from datetime import datetime, timezone, timedelta
from providers.aws.controls.cis_1_14.cis_1_14_check import execute, check_access_key_rotation
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

def test_no_old_access_keys(mock_session, mock_logger, mock_service_factory):
    """Test when no access keys are older than 90 days."""
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
    
    # Create credential report with recently rotated keys
    current_time = datetime.now(timezone.utc)
    recent_time = (current_time - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    csv_content = f"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service\ntest-user,arn:aws:iam::123456789012:user/test-user,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,not_supported,true,true,{recent_time},2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A"
    
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_PASS
    assert "All access keys have been rotated within the last 90 days" in results[0].status_extended

def test_old_access_keys(mock_session, mock_logger, mock_service_factory):
    """Test when access keys are older than 90 days."""
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
    
    # Create credential report with old keys
    current_time = datetime.now(timezone.utc)
    old_time = (current_time - timedelta(days=100)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    csv_content = f"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service\ntest-user,arn:aws:iam::123456789012:user/test-user,2023-01-01T00:00:00+00:00,true,2023-01-01T00:00:00+00:00,2023-01-01T00:00:00+00:00,not_supported,true,true,{old_time},2023-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A"
    
    mock_iam.get_credential_report.return_value = {
        'success': True,
        'content': io.StringIO(csv_content).getvalue().encode('utf-8')
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_FAIL
    assert "has not been rotated in" in results[0].status_extended

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

def test_check_access_key_rotation():
    """Test the check_access_key_rotation helper function."""
    current_time = datetime.now(timezone.utc)
    old_time = (current_time - timedelta(days=100)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    recent_time = (current_time - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    
    report = [
        {
            'user': 'user1',
            'arn': 'arn:aws:iam::123456789012:user/user1',
            'access_key_1_last_rotated': old_time,
            'access_key_1_active': 'AKIA1234567890',
            'access_key_2_last_rotated': 'N/A',
            'access_key_2_active': 'N/A'
        },
        {
            'user': 'user2',
            'arn': 'arn:aws:iam::123456789012:user/user2',
            'access_key_1_last_rotated': recent_time,
            'access_key_1_active': 'AKIA0987654321',
            'access_key_2_last_rotated': 'N/A',
            'access_key_2_active': 'N/A'
        }
    ]
    
    issues = check_access_key_rotation(report)
    
    assert len(issues) == 1
    assert issues[0]['user'] == 'user1'
    assert issues[0]['key_id'] == 'AKIA1234567890'
    assert issues[0]['age'] > 90

def test_sts_error(mock_session, mock_logger, mock_service_factory):
    """Test when getting AWS account ID fails."""
    mock_iam = MagicMock()
    mock_sts = MagicMock()
    
    mock_service_factory.get_service.side_effect = lambda service: {
        'iam': mock_iam,
        'sts': mock_sts
    }[service]
    
    mock_sts.get_caller_identity.return_value = {
        'success': False,
        'error_message': 'Failed to get caller identity'
    }
    
    results = execute(mock_session, mock_logger, mock_service_factory)
    
    assert len(results) == 1
    assert results[0].status == CheckResult.STATUS_ERROR
    assert "Failed to get AWS Account ID" in results[0].status_extended
