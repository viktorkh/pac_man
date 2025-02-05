import pytest
from unittest.mock import Mock
from datetime import datetime, timezone, timedelta

from pac_man.providers.aws.controls.cis_1_12.cis_1_12_check import execute, check_inactive_credentials
from providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_iam_service():
    return Mock()

@pytest.fixture
def mock_sts_service():
    return Mock()

@pytest.fixture
def mock_logger():
    return Mock()

def test_execute_no_inactive_users(mock_iam_service, mock_sts_service, mock_logger):
    """Should return STATUS_PASS when no inactive users are found."""
    mock_sts_service.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b"user,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\nuser1,false,N/A,false,N/A,false,N/A"
    }

    service_factory = Mock(get_service=Mock(side_effect=[mock_iam_service, mock_sts_service]))

    results = execute(None, mock_logger, service_factory)

    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_PASS
    assert "No users found" in result.status_extended

def test_execute_with_inactive_users(mock_iam_service, mock_sts_service, mock_logger):
    """Should return STATUS_FAIL when inactive users are found."""
    mock_sts_service.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b"user,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\nuser1,true,2023-01-01T00:00:00+00:00,false,N/A,false,N/A"
    }

    service_factory = Mock(get_service=Mock(side_effect=[mock_iam_service, mock_sts_service]))

    results = execute(None, mock_logger, service_factory)

    print("Results:", results)  # Debugging output
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_FAIL  # Expected behavior
    assert "Found 1 user" in result.status_extended


def test_execute_error_handling(mock_iam_service, mock_sts_service, mock_logger):
    """Should return STATUS_ERROR when an exception occurs."""
    mock_sts_service.get_caller_identity.side_effect = Exception("Unexpected error")

    service_factory = Mock(get_service=Mock(side_effect=[mock_iam_service, mock_sts_service]))

    results = execute(None, mock_logger, service_factory)

    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "Error executing check" in result.status_extended
    mock_logger.error.assert_called_once()

def test_check_inactive_credentials():
    """Should correctly identify users with inactive credentials."""
    now = datetime.now(timezone.utc)
    users = [
        {
            'user': 'user1',
            'password_enabled': 'true',
            'password_last_used': (now - timedelta(days=50)).strftime('%Y-%m-%dT%H:%M:%S+00:00'),
            'access_key_1_active': 'false',
            'access_key_1_last_used_date': 'N/A',
            'access_key_2_active': 'false',
            'access_key_2_last_used_date': 'N/A',
            'arn': 'arn:aws:iam::123456789012:user/user1'
        },
        {
            'user': 'user2',
            'password_enabled': 'false',
            'password_last_used': 'N/A',
            'access_key_1_active': 'true',
            'access_key_1_last_used_date': (now - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S+00:00'),
            'access_key_2_active': 'false',
            'access_key_2_last_used_date': 'N/A',
            'arn': 'arn:aws:iam::123456789012:user/user2'
        }
    ]

    inactive_users = check_inactive_credentials(users)

    assert len(inactive_users) == 1
    assert inactive_users[0]['user'] == 'user1'
