import pytest
from unittest.mock import MagicMock, patch
from pac_man.providers.aws.controls.cis_2_3_3.cis_2_3_3_fix import execute
from pac_man.providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_rds_service():
    return MagicMock()

@pytest.fixture
def mock_service_factory(mock_rds_service):
    factory = MagicMock()
    factory.get_service.return_value = mock_rds_service
    return factory

@pytest.fixture
def mock_logger():
    return MagicMock()

@pytest.fixture
def mock_finding():
    finding = MagicMock()
    finding.resource_id = "test-db-instance"
    finding.resource_arn = "arn:aws:rds:us-west-1:123456789012:db:test-db-instance"
    finding.region = "us-west-1"
    finding.remediation_result = MagicMock()
    return finding

def test_already_private(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.return_value = {
        'DBInstances': [{
            'DBInstanceIdentifier': 'test-db-instance',
            'PubliclyAccessible': False
        }]
    }

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_PASS
    assert "already private" in result.status_extended.lower()

def test_make_private_success(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.side_effect = [
        {'DBInstances': [{'DBInstanceIdentifier': 'test-db-instance', 'PubliclyAccessible': True}]},
        {'DBInstances': [{'DBInstanceIdentifier': 'test-db-instance', 'PubliclyAccessible': False}]}
    ]
    mock_rds_service.modify_db_instance.return_value = {'DBInstance': {'PubliclyAccessible': False}}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_PASS
    assert "successfully made" in result.status_extended.lower()

def test_multiple_instances_found(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.return_value = {'DBInstances': [
        {'DBInstanceIdentifier': 'test-db-instance', 'PubliclyAccessible': True},
        {'DBInstanceIdentifier': 'test-db-instance-2', 'PubliclyAccessible': True}
    ]}
    mock_rds_service.modify_db_instance.return_value = {'DBInstance': {'PubliclyAccessible': True}}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_FAIL
    assert "Failed to make DB instance test-db-instance private" in result.status_extended

def test_verification_failure(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.side_effect = [
        {'DBInstances': [{'DBInstanceIdentifier': 'test-db-instance', 'PubliclyAccessible': True}]},
        {'DBInstances': [{'DBInstanceIdentifier': 'test-db-instance', 'PubliclyAccessible': True}]}
    ]
    mock_rds_service.modify_db_instance.return_value = {'DBInstance': {'PubliclyAccessible': False}}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_FAIL
    assert "Failed to verify DB instance" in result.status_extended

def test_instance_not_found(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.return_value = {'DBInstances': []}

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_FAIL
    assert "DB instance test-db-instance not found" in result.status_extended

def test_unexpected_error(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.side_effect = Exception("Unexpected error")

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_ERROR
    assert "Error executing fix for CIS 2.3.3" in result.status_extended

def test_describe_db_instances_error(mock_rds_service, mock_service_factory, mock_logger, mock_finding):
    mock_rds_service.describe_db_instances.side_effect = Exception("API error")

    result = execute(None, mock_finding, mock_logger, mock_service_factory)

    assert result.status == CheckResult.STATUS_ERROR
    assert "Error executing fix for CIS 2.3.3" in result.status_extended