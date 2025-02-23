"""Unit tests for RDSService."""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from providers.aws.services.rds_service import RDSService

@pytest.fixture
def rds_service():
    """Create RDSService instance with mocked session."""
    mock_session = MagicMock()
    return RDSService(mock_session)

def test_describe_db_instances_success(rds_service):
    """Test successful retrieval of DB instances."""
    mock_response = {
        'DBInstances': [
            {'DBInstanceIdentifier': 'db-instance-1'},
            {'DBInstanceIdentifier': 'db-instance-2'}
        ]
    }
    rds_service.session.client.return_value.describe_db_instances = MagicMock(return_value=mock_response)
    result = rds_service.describe_db_instances()
    assert len(result) == 2
    assert result[0]['DBInstanceIdentifier'] == 'db-instance-1'
    assert result[1]['DBInstanceIdentifier'] == 'db-instance-2'
    rds_service.session.client.return_value.describe_db_instances.assert_called_once()

def test_describe_db_instances_error(rds_service):
    """Test handling of errors in describe_db_instances."""
    error_response = {
        'Error': {'Code': 'InvalidClientTokenId', 'Message': 'The security token included in the request is invalid'}
    }
    rds_service.session.client.return_value.describe_db_instances = MagicMock(
        side_effect=ClientError(error_response, 'DescribeDBInstances')
    )
    with pytest.raises(ClientError) as excinfo:
        rds_service.describe_db_instances()
    assert 'InvalidClientTokenId' in str(excinfo.value)

def test_modify_db_instance_success(rds_service):
    """Test successful modification of a DB instance."""
    mock_response = {
        'DBInstance': {
            'DBInstanceIdentifier': 'test-instance',
            'PubliclyAccessible': False
        }
    }
    rds_service.session.client.return_value.modify_db_instance = MagicMock(return_value=mock_response)
    result = rds_service.modify_db_instance('test-instance', False, True)
    assert result['DBInstance']['DBInstanceIdentifier'] == 'test-instance'
    assert result['DBInstance']['PubliclyAccessible'] is False
    rds_service.session.client.return_value.modify_db_instance.assert_called_once_with(
        DBInstanceIdentifier='test-instance',
        PubliclyAccessible=False,
        ApplyImmediately=True
    )

def test_modify_db_instance_error(rds_service):
    """Test handling of errors in modify_db_instance."""
    error_response = {
        'Error': {'Code': 'DBInstanceNotFound', 'Message': 'DB instance not found'}
    }
    rds_service.session.client.return_value.modify_db_instance = MagicMock(
        side_effect=ClientError(error_response, 'ModifyDBInstance')
    )
    with pytest.raises(ClientError) as excinfo:
        rds_service.modify_db_instance('non-existent-instance', True, True)
    assert 'DBInstanceNotFound' in str(excinfo.value)