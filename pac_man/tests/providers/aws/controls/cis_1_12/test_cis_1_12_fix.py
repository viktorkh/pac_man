import pytest
from unittest.mock import Mock, MagicMock
from pac_man.providers.aws.controls.cis_1_12.cis_1_12_fix import execute

@pytest.fixture
def mock_session():
    return Mock()

@pytest.fixture
def mock_logger():
    return Mock()

@pytest.fixture
def mock_service_factory():
    factory = MagicMock()
    factory.get_service = MagicMock()
    return factory

def test_execute_no_inactive_users(mock_session, mock_logger, mock_service_factory):
    """Should mark remediation as success when no inactive users are found."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b"user,password_enabled,password_last_used,access_key_1_active,access_key_1_id,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\nuser1,false,N/A,false,N/A,false,N/A"
    }

    mock_finding = Mock()
    mock_finding.init_remediation.return_value = mock_finding
    mock_finding.to_dict.return_value = {'remediation_result': {'status': 'SUCCESS'}}

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_iam_service.get_credential_report.assert_called_once()
    mock_finding.mark_as_success.assert_called_once_with(
        "No users found with credentials unused for 45 days or greater. No action needed."
    )
    assert result['remediation_result']['status'] == 'SUCCESS'

def test_execute_inactive_users_fixed(mock_session, mock_logger, mock_service_factory):
    """Should successfully disable credentials for inactive users."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b"user,password_enabled,password_last_used,access_key_1_active,access_key_1_id,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\nuser1,true,2023-01-01T00:00:00+00:00,true,key1,2023-01-01T00:00:00+00:00,false,N/A"
    }

    mock_finding = Mock()
    mock_finding.init_remediation.return_value = mock_finding
    mock_finding.to_dict.return_value = {'remediation_result': {'status': 'SUCCESS'}}

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_iam_service.get_credential_report.assert_called_once()
    mock_iam_service.delete_login_profile.assert_called_once_with('user1')
    mock_iam_service.update_access_key.assert_called_once_with('user1', 'key1', 'Inactive')
    mock_finding.mark_as_success.assert_called_once_with(
        "Successfully disabled credentials for users: user1"
    )
    assert result['remediation_result']['status'] == 'SUCCESS'

def test_execute_inactive_users_failed(mock_session, mock_logger, mock_service_factory):
    """Should mark remediation as failed if unable to disable credentials for some users."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service
    mock_iam_service.get_credential_report.return_value = {
        'success': True,
        'content': b"user,password_enabled,password_last_used,access_key_1_active,access_key_1_id,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\nuser1,true,2023-01-01T00:00:00+00:00,true,key1,2023-01-01T00:00:00+00:00,false,N/A"
    }
    mock_iam_service.delete_login_profile.side_effect = Exception("Test error")

    mock_finding = Mock()
    mock_finding.init_remediation.return_value = mock_finding
    mock_finding.to_dict.return_value = {'remediation_result': {'status': 'FAILED'}}

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_iam_service.get_credential_report.assert_called_once()
    mock_logger.error.assert_called_once_with("Failed to disable credentials for user user1: Test error")
    mock_finding.mark_as_failed.assert_called_once_with(
        "Failed to disable credentials for users: user1"
    )
    assert result['remediation_result']['status'] == 'FAILED'

def test_execute_error_handling(mock_session, mock_logger, mock_service_factory):
    """Should mark remediation as failed if an unexpected error occurs."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service
    mock_iam_service.get_credential_report.side_effect = Exception("Unexpected error")

    mock_finding = Mock()
    mock_finding.init_remediation.return_value = mock_finding
    mock_finding.to_dict.return_value = {'remediation_result': {'status': 'FAILED'}}

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_logger.error.assert_called_once_with("Error executing CIS 1.12 fix: Unexpected error")
    mock_finding.mark_as_failed.assert_called_once_with("Error executing fix: Unexpected error")
    assert result['remediation_result']['status'] == 'FAILED'
