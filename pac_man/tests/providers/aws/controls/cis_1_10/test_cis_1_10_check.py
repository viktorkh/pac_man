import pytest
from unittest.mock import Mock
from providers.aws.controls.cis_1_10.cis_1_10_check import execute, check_users_without_mfa
from providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_iam_service():
    return Mock()

@pytest.fixture
def mock_sts_service():
    return Mock()

@pytest.fixture
def mock_service_factory(mock_iam_service, mock_sts_service):
    return Mock(get_service=Mock(side_effect=lambda service: {
        'iam': mock_iam_service,
        'sts': mock_sts_service
    }[service]))

@pytest.fixture
def mock_logger():
    return Mock()

def test_execute_all_users_have_mfa(mock_service_factory, mock_logger):
    """Should return STATUS_PASS when all users have MFA enabled."""
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }

    mock_iam_service = mock_service_factory.get_service('iam')
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b'user,password_enabled,mfa_active\nuser1,true,true\nuser2,false,false\n'
    }

    results = execute(None, mock_logger, mock_service_factory)
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_PASS
    assert result.status_extended == "All IAM users with a console password have MFA enabled."

def test_execute_some_users_without_mfa(mock_service_factory, mock_logger):
    """Should return STATUS_FAIL when some users lack MFA."""
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }

    mock_iam_service = mock_service_factory.get_service('iam')
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b'user,password_enabled,mfa_active\nuser1,true,false\nuser2,false,false\n'
    }

    results = execute(None, mock_logger, mock_service_factory)
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_FAIL
    assert "Found 1 IAM user(s) with a console password but without MFA enabled." in result.status_extended

def test_execute_error_in_sts(mock_service_factory, mock_logger):
    """Should return STATUS_ERROR when STS call fails."""
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {
        'success': False,
        'error_message': 'Access denied'
    }

    results = execute(None, mock_logger, mock_service_factory)
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "Failed to get AWS Account ID: Access denied" in result.status_extended

def test_execute_error_in_iam(mock_service_factory, mock_logger):
    """Should return STATUS_ERROR when IAM call fails."""
    mock_sts_service = mock_service_factory.get_service('sts')
    mock_sts_service.get_caller_identity.return_value = {
        'success': True,
        'account_id': '123456789012'
    }

    mock_iam_service = mock_service_factory.get_service('iam')
    mock_iam_service.get_credential_report.return_value = {
        'success': False,
        'error_message': 'Service unavailable'
    }

    results = execute(None, mock_logger, mock_service_factory)
    assert len(results) == 1
    result = results[0]
    assert result.status == CheckResult.STATUS_ERROR
    assert "Failed to get credential report: Service unavailable" in result.status_extended

def test_check_users_without_mfa():
    """Should return a list of users without MFA."""
    users = [
        {'user': 'user1', 'password_enabled': 'true', 'mfa_active': 'false'},
        {'user': 'user2', 'password_enabled': 'false', 'mfa_active': 'false'},
        {'user': 'user3', 'password_enabled': 'true', 'mfa_active': 'true'}
    ]

    result = check_users_without_mfa(users)
    assert len(result) == 1
    assert result[0]['user'] == 'user1'
    assert result[0]['password_last_used'] == 'N/A'
