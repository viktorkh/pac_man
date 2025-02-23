import pytest
from unittest.mock import MagicMock, patch
from pac_man.providers.aws.controls.cis_3_9.cis_3_9_fix import execute

@pytest.fixture
def mock_ec2_service():
    return MagicMock()

@pytest.fixture
def mock_iam_service():
    return MagicMock()

@pytest.fixture
def mock_service_factory(mock_ec2_service, mock_iam_service):
    factory = MagicMock()
    factory.get_service.side_effect = lambda service_name: (
        mock_ec2_service if service_name == "ec2" else mock_iam_service
    )
    return factory

@pytest.fixture
def mock_logger():
    return MagicMock()

@pytest.fixture
def mock_finding():
    finding = MagicMock()
    finding.resource_id = "vpc-12345678"
    finding.remediation_result = MagicMock()
    return finding

# Test case: Flow logging is already enabled
def test_flow_logging_already_enabled(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.create_flow_logs.return_value = {"success": True}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "PASS"
    assert "VPC flow logging has been enabled" in result.remediation_result.mark_as_success.call_args[1]['details']

# Test case: Successfully enable flow logging
def test_enable_flow_logging_success(mock_ec2_service, mock_iam_service, mock_service_factory, mock_logger, mock_finding):
    mock_iam_service.create_role.return_value = {"success": True, "Role": {"Arn": "arn:aws:iam::123456789012:role/VPCFlowLogsRole"}}
    mock_ec2_service.create_flow_logs.return_value = {"success": True}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "PASS"
    assert "VPC flow logging has been enabled" in result.remediation_result.mark_as_success.call_args[1]['details']

# Test case: Failure in enabling flow logging
def test_enable_flow_logging_failure(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.create_flow_logs.return_value = {"success": False, "error_message": "Access denied"}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "Access denied" in result.remediation_result.mark_as_failed.call_args[1]['error_message']

# Test case: Role creation failure
def test_create_role_failure(mock_iam_service, mock_service_factory, mock_logger, mock_finding):
    mock_iam_service.create_role.return_value = {"success": False, "error_message": "Role creation failed"}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "An error occurred while enabling VPC flow logging" in result.remediation_result.mark_as_failed.call_args[1]['error_message']

# Test case: Unexpected error handling
def test_unexpected_error(mock_ec2_service, mock_service_factory, mock_logger, mock_finding):
    mock_ec2_service.create_flow_logs.side_effect = Exception("Unexpected error")

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == "FAIL"
    assert "An error occurred while enabling VPC flow logging" in result.remediation_result.mark_as_failed.call_args[1]['error_message']
