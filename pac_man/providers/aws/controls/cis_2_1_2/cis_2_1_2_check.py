"""CIS 2.1.2 - Ensure S3 Bucket MFA Delete is enabled."""

from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_2_1_2"
CHECK_DESCRIPTION = "Ensure S3 Bucket MFA Delete is enabled"

def check_mfa_delete(s3_service, bucket_name: str, logger) -> CheckResult:
    """
    Check if MFA Delete is enabled for the specified S3 bucket.

    Args:
        s3_service: S3Service instance
        bucket_name: Name of the S3 bucket to check
        logger: Logger object for logging messages

    Returns:
        CheckResult: Object containing the check results
    """
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.resource_id = bucket_name
    result.resource_arn = f"arn:aws:s3:::{bucket_name}"
    
    # Get bucket location to set correct region
    location_response = s3_service.get_bucket_location(bucket_name)
    if not location_response['success']:
        logger.error(f"Error getting bucket location for {bucket_name}: {location_response.get('error_message')}")
        # Changed from STATUS_ERROR to STATUS_FAIL since we can't verify MFA Delete is enabled
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = f"Unable to verify MFA Delete status - Error getting bucket location: {location_response.get('error_message')}"
        return result
        
    result.region = location_response['location']
    
    # Check bucket versioning and MFA delete status
    versioning_response = s3_service.get_bucket_versioning(bucket_name)
    if not versioning_response['success']:
        logger.error(f"Error checking bucket {bucket_name}: {versioning_response.get('error_message')}")
        # Changed from STATUS_ERROR to STATUS_FAIL since we can't verify MFA Delete is enabled
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = f"Unable to verify MFA Delete status - Error checking versioning: {versioning_response.get('error_message')}"
        return result
        
    versioning_status = versioning_response['versioning']
    mfa_delete = versioning_response['mfa_delete']
    
    if versioning_status == 'Enabled' and mfa_delete == 'Enabled':
        result.status = CheckResult.STATUS_PASS
        result.status_extended = f"MFA Delete is enabled for bucket {bucket_name}"
    else:
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = (
            f"MFA Delete is not enabled for bucket {bucket_name}. "
            f"Versioning status: {versioning_status}, MFA Delete: {mfa_delete}"
        )
    
    return result

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute the CIS 2.1.2 check for S3 bucket MFA Delete.
    
    Args:
        session: boto3 session
        logger: Logger object for logging messages
        service_factory: AWS service factory instance
        
    Returns:
        List[CheckResult]: List containing check results
    """
    logger.info("Executing CIS 2.1.2 check for S3 bucket MFA Delete")
    
    # Initialize services using the factory
    s3_service = service_factory.get_service('s3')
    findings = []
    
    try:
        # List all buckets using S3 service
        list_response = s3_service.list_buckets()
        if not list_response['success']:
            result = CheckResult()
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            # Changed from STATUS_ERROR to STATUS_FAIL since we can't verify any buckets have MFA Delete enabled
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"Unable to verify MFA Delete status - Error listing buckets: {list_response.get('error_message')}"
            result.resource_id = "S3Buckets"
            result.resource_arn = "arn:aws:s3:::*"
            result.region = "global"
            return [result]
            
        # Check MFA Delete status for each bucket
        for bucket in list_response['buckets']:
            bucket_name = bucket['Name']
            result = check_mfa_delete(s3_service, bucket_name, logger)
            findings.append(result)
            
        return findings
        
    except Exception as e:
        logger.error(f"An error occurred during the CIS 2.1.2 check: {str(e)}")
        result = CheckResult()
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        # Changed from STATUS_ERROR to STATUS_FAIL since we can't verify any buckets have MFA Delete enabled
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = f"Unable to verify MFA Delete status - An error occurred during the check: {str(e)}"
        result.resource_id = "S3Buckets"
        result.resource_arn = "arn:aws:s3:::*"
        result.region = "global"
        return [result]
