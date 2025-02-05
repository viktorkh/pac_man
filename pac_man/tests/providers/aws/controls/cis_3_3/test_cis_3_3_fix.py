import pytest
from unittest.mock import Mock, MagicMock
from pac_man.providers.aws.controls.cis_3_3.cis_3_3_fix import execute

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

def test_execute_success_removes_public_access(mock_session, mock_logger, mock_service_factory):
    """Should successfully remove public access and apply settings for a valid bucket."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service

    mock_s3_service.get_bucket_acl.return_value = {
        'success': True,
        'Grants': [
            {
                'Grantee': {
                    'Type': 'Group',
                    'URI': "http://acs.amazonaws.com/groups/global/AllUsers"
                }
            }
        ]
    }
    mock_s3_service.get_bucket_policy.return_value = {
        'success': True,
        'policy': {
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': '*',
                }
            ]
        }
    }
    mock_s3_service.put_public_access_block.return_value = {'success': True}
    mock_s3_service.remove_bucket_acl.return_value = {'success': True}
    mock_s3_service.put_bucket_policy.return_value = {'success': True}

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_success.assert_called_once()
    assert result.remediation_result.message == "Successfully removed public access and enabled all public access block settings for bucket test-bucket"

def test_execute_failed_acl_removal(mock_session, mock_logger, mock_service_factory):
    """Should fail if ACL removal fails."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service
    
    mock_s3_service.get_bucket_acl.return_value = {
        'success': True,
        'Grants': [
            {
                'Grantee': {
                    'Type': 'Group',
                    'URI': "http://acs.amazonaws.com/groups/global/AllUsers"
                }
            }
        ]
    }
    mock_s3_service.remove_bucket_acl.return_value = {
        'success': False,
        'error_message': 'Access denied'
    }

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_failed.assert_called_once()
    assert result.remediation_result.message == "Failed to remove public ACL grant: Access denied"

def test_execute_unexpected_exception(mock_session, mock_logger, mock_service_factory):
    """Should handle and log unexpected exceptions."""
    mock_s3_service = Mock()
    mock_service_factory.get_service.return_value = mock_s3_service

    mock_s3_service.get_bucket_acl.side_effect = Exception("Unexpected error")

    mock_finding = Mock()
    mock_finding.resource_id = 'test-bucket'
    mock_finding.init_remediation.return_value = mock_finding

    result = execute(mock_session, mock_finding, mock_logger, mock_service_factory)

    mock_logger.error.assert_called_once_with(
        "Unexpected error occurred while fixing CIS 3.3 for bucket test-bucket: Unexpected error"
    )
    mock_finding.init_remediation.assert_called_once()
    mock_finding.mark_as_failed.assert_called_once()
    assert result.remediation_result.message == "Unexpected error occurred: Unexpected error"
