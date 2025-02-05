import pytest
from unittest.mock import Mock, MagicMock

from pac_man.providers.aws.controls.cis_3_3.cis_3_3_check import check_cloudtrail_bucket_public_access, execute
from pac_man.providers.aws.lib.check_result import CheckResult

@pytest.fixture
def mock_s3_service():
    return Mock()

@pytest.fixture
def mock_logger():
    return Mock()

def test_check_cloudtrail_bucket_public_access_no_public_access(mock_s3_service, mock_logger):
    """Should return STATUS_PASS when the bucket is not publicly accessible."""
    bucket_name = "test-bucket"
    mock_s3_service.get_bucket_location.return_value = {'success': True, 'location': 'us-west-2'}
    mock_s3_service.get_bucket_acl.return_value = {'success': True, 'Grants': []}
    mock_s3_service.get_bucket_policy.return_value = {'success': True, 'Policy': {'Statement': []}}

    result = check_cloudtrail_bucket_public_access(mock_s3_service, bucket_name, mock_logger)

    assert result.status == CheckResult.STATUS_PASS
    assert result.status_extended == f"S3 bucket '{bucket_name}' is not publicly accessible."

def test_check_cloudtrail_bucket_public_access_public_acl(mock_s3_service, mock_logger):
    """Should return STATUS_FAIL when the bucket has public access via ACL."""
    bucket_name = "test-bucket"
    mock_s3_service.get_bucket_location.return_value = {'success': True, 'location': 'us-west-2'}
    mock_s3_service.get_bucket_acl.return_value = {
        'success': True,
        'Grants': [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
    }

    result = check_cloudtrail_bucket_public_access(mock_s3_service, bucket_name, mock_logger)

    assert result.status == CheckResult.STATUS_FAIL
    assert "has public access via ACL" in result.status_extended

def test_check_cloudtrail_bucket_public_access_public_policy(mock_s3_service, mock_logger):
    """Should return STATUS_FAIL when the bucket has a public access policy."""
    bucket_name = "test-bucket"
    mock_s3_service.get_bucket_location.return_value = {'success': True, 'location': 'us-west-2'}
    mock_s3_service.get_bucket_acl.return_value = {'success': True, 'Grants': []}
    mock_s3_service.get_bucket_policy.return_value = {
        'success': True,
        'Policy': {
            'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 's3:*', 'Resource': '*'}]
        }
    }

    result = check_cloudtrail_bucket_public_access(mock_s3_service, bucket_name, mock_logger)

    assert result.status == CheckResult.STATUS_FAIL
    assert "has a public access policy without conditions" in result.status_extended

def test_check_cloudtrail_bucket_public_access_error_fetching_location(mock_s3_service, mock_logger):
    """Should return STATUS_ERROR when there is an error fetching bucket location."""
    bucket_name = "test-bucket"
    mock_s3_service.get_bucket_location.return_value = {'success': False, 'error_message': 'Service unavailable'}

    result = check_cloudtrail_bucket_public_access(mock_s3_service, bucket_name, mock_logger)

    assert result.status == CheckResult.STATUS_ERROR
    assert "Unable to determine bucket region" in result.status_extended

def test_check_cloudtrail_bucket_public_access_error_fetching_acl(mock_s3_service, mock_logger):
    """Should return STATUS_ERROR when there is an error fetching bucket ACL."""
    bucket_name = "test-bucket"
    mock_s3_service.get_bucket_location.return_value = {'success': True, 'location': 'us-west-2'}
    mock_s3_service.get_bucket_acl.return_value = {'success': False, 'error_message': 'Service unavailable'}

    result = check_cloudtrail_bucket_public_access(mock_s3_service, bucket_name, mock_logger)

    assert result.status == CheckResult.STATUS_ERROR
    assert "Unable to verify bucket ACL" in result.status_extended

def test_check_cloudtrail_bucket_public_access_error_fetching_policy(mock_s3_service, mock_logger):
    """Should return STATUS_ERROR when there is an error fetching bucket policy."""
    bucket_name = "test-bucket"
    mock_s3_service.get_bucket_location.return_value = {'success': True, 'location': 'us-west-2'}
    mock_s3_service.get_bucket_acl.return_value = {'success': True, 'Grants': []}
    mock_s3_service.get_bucket_policy.return_value = {'success': False, 'error_message': 'Service unavailable'}

    result = check_cloudtrail_bucket_public_access(mock_s3_service, bucket_name, mock_logger)

    assert result.status == CheckResult.STATUS_ERROR
    assert "Unable to verify bucket policy" in result.status_extended