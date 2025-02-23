import pytest
from unittest.mock import MagicMock, patch
from pac_man.providers.aws.controls.cis_5_4.cis_5_4_fix import execute
from pac_man.providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_ec2_service():
    return MagicMock()

@pytest.fixture
def mock_service_factory(mock_ec2_service):
    factory = MagicMock()
    factory.get_service.return_value = mock_ec2_service
    return factory

@pytest.fixture
def mock_logger():
    return MagicMock()

@pytest.fixture
def mock_finding():
    finding = MagicMock()
    finding.resource_id = "sg-12345678"
    finding.remediation_result = MagicMock()
    return finding

def test_already_compliant(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-12345678',
            'IpPermissions': [],
            'IpPermissionsEgress': []
        }]
    }

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "PASS"
    assert "Successfully removed all rules" in result.remediation_result.mark_as_success.call_args[1]['details']
    mock_ec2_service.revoke_security_group_ingress.assert_not_called()
    mock_ec2_service.revoke_security_group_egress.assert_not_called()

def test_remove_rules_success(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.describe_security_groups.side_effect = [
        {
            'SecurityGroups': [{
                'GroupId': 'sg-12345678',
                'IpPermissions': [{'IpProtocol': '-1'}],
                'IpPermissionsEgress': [{'IpProtocol': '-1'}]
            }]
        },
        {
            'SecurityGroups': [{
                'GroupId': 'sg-12345678',
                'IpPermissions': [],
                'IpPermissionsEgress': []
            }]
        }
    ]
    mock_ec2_service.revoke_security_group_ingress.return_value = None
    mock_ec2_service.revoke_security_group_egress.return_value = None

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "PASS"
    assert "Successfully removed all rules" in result.remediation_result.mark_as_success.call_args[1]['details']
    mock_ec2_service.revoke_security_group_ingress.assert_called_once()
    mock_ec2_service.revoke_security_group_egress.assert_called_once()

def test_remove_rules_failure(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-12345678',
            'IpPermissions': [{'IpProtocol': '-1'}],
            'IpPermissionsEgress': [{'IpProtocol': '-1'}]
        }]
    }
    mock_ec2_service.revoke_security_group_ingress.side_effect = Exception("Access denied")

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Unexpected error occurred while fixing CIS 5.4" in result.remediation_result.mark_as_failed.call_args[1]['error_message']
    assert "Access denied" in result.remediation_result.mark_as_failed.call_args[1]['error_message']

def test_verification_failure(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.describe_security_groups.side_effect = [
        {
            'SecurityGroups': [{
                'GroupId': 'sg-12345678',
                'IpPermissions': [{'IpProtocol': '-1'}],
                'IpPermissionsEgress': [{'IpProtocol': '-1'}]
            }]
        },
        {
            'SecurityGroups': [{
                'GroupId': 'sg-12345678',
                'IpPermissions': [{'IpProtocol': '-1'}],
                'IpPermissionsEgress': []
            }]
        }
    ]
    mock_ec2_service.revoke_security_group_ingress.return_value = None
    mock_ec2_service.revoke_security_group_egress.return_value = None

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Failed to remove all rules" in result.remediation_result.mark_as_failed.call_args[1]['error_message']

def test_unexpected_error(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.describe_security_groups.side_effect = Exception("Unexpected error")

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Unexpected error occurred" in result.remediation_result.mark_as_failed.call_args[1]['error_message']