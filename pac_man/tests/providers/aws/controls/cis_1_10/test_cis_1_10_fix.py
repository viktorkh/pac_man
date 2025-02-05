import pytest
from unittest.mock import Mock, MagicMock
from providers.aws.lib.check_result import CheckResult
from pac_man.providers.aws.controls.cis_1_10.cis_1_10_fix import execute
import json
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

def test_execute_no_users_without_mfa(mock_session, mock_logger, mock_service_factory):
    """Should mark remediation as success when no users without MFA are found."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service

    mock_finding = Mock()
    mock_finding.get.return_value = json.dumps([])

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_PASS
    assert result.status_extended == "No users found without MFA. No action needed."


def test_execute_users_fixed(mock_session, mock_logger, mock_service_factory):
    """Should successfully enable MFA for users without MFA."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service
    mock_iam_service.create_virtual_mfa_device.return_value = {
        'success': True, 'serial_number': 'arn:aws:iam::123456789012:mfa/test-mfa-device'
    }
    mock_iam_service.enable_mfa_device.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.get.return_value = json.dumps([
        {'user': 'user1'}, {'user': 'user2'}
    ])

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_iam_service.create_virtual_mfa_device.assert_any_call('user1')
    mock_iam_service.create_virtual_mfa_device.assert_any_call('user2')
    mock_iam_service.enable_mfa_device.assert_any_call('user1', 'arn:aws:iam::123456789012:mfa/test-mfa-device', ['000000', '000000'])
    mock_iam_service.enable_mfa_device.assert_any_call('user2', 'arn:aws:iam::123456789012:mfa/test-mfa-device', ['000000', '000000'])

    assert result.status == CheckResult.STATUS_PASS
    assert "Successfully enabled MFA for 2 user(s): user1, user2." in result.status_extended


def test_execute_partial_fix(mock_session, mock_logger, mock_service_factory):
    """Should fail if unable to enable MFA for some users."""
    mock_iam_service = Mock()
    mock_service_factory.get_service.return_value = mock_iam_service
    mock_iam_service.create_virtual_mfa_device.side_effect = [
        {'success': True, 'serial_number': 'arn:aws:iam::123456789012:mfa/test-mfa-device'},
        Exception("Failed to create MFA")
    ]
    mock_iam_service.enable_mfa_device.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.get.return_value = json.dumps([
        {'user': 'user1'}, {'user': 'user2'}
    ])

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_FAIL
    assert "Successfully enabled MFA for 1 user(s): user1." in result.status_extended
    assert "Failed to enable MFA for 1 user(s): user2." in result.status_extended
