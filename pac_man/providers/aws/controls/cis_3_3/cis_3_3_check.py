"""CIS 3.3 - Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible."""

from typing import List
from providers.aws.lib.check_result import CheckResult
# from services.cloudtrail_service import CloudTrailService

CHECK_ID = "cis_3_3"
CHECK_DESCRIPTION = "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"

def check_cloudtrail_bucket_public_access(s3_service, bucket_name, logger) -> CheckResult:
    """
    Check if an S3 bucket used for CloudTrail logs is publicly accessible.

    Args:
        s3_service: S3Service instance
        bucket_name: Name of the S3 bucket
        logger: Logger object for logging messages

    Returns:
        CheckResult: Object containing the check results
    """
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.resource_id = bucket_name
    result.resource_arn = f"arn:aws:s3:::{bucket_name}"
    
    try:
        bucket_location = s3_service.get_bucket_location(bucket_name)
        if not bucket_location['success']:
            logger.error(f"Error fetching location for bucket {bucket_name}: {bucket_location['error_message']}")
            result.set_status(CheckResult.STATUS_ERROR)
            result.status_extended = f"Unable to determine bucket region: {bucket_location['error_message']}"
            return result

        # Set the bucket's region in the result
        result.region = bucket_location['location']

        # Check bucket ACL for public access
        bucket_acl = s3_service.get_bucket_acl(bucket_name)
        if not bucket_acl['success']:
            logger.error(f"Error fetching ACL for bucket {bucket_name}: {bucket_acl['error_message']}")
            result.set_status(CheckResult.STATUS_ERROR)
            result.status_extended = f"Unable to verify bucket ACL: {bucket_acl['error_message']}"
            return result

        for grant in bucket_acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group' and grantee.get('URI') in [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            ]:
                result.set_status(CheckResult.STATUS_FAIL)
                result.status_extended = (
                    f"S3 bucket '{bucket_name}' has public access via ACL (grantee: {grantee.get('URI')})"
                )
                return result

        # Check bucket policy for public access
        bucket_policy = s3_service.get_bucket_policy(bucket_name)
        if not bucket_policy['success']:
            if "NoSuchBucketPolicy" not in bucket_policy['error_message']:
                logger.error(f"Error fetching policy for bucket {bucket_name}: {bucket_policy['error_message']}")
                result.set_status(CheckResult.STATUS_ERROR)
                result.status_extended = f"Unable to verify bucket policy: {bucket_policy['error_message']}"
                return result
        else:
            policy_document = bucket_policy.get('Policy', {})
            for statement in policy_document.get('Statement', []):
                if statement.get('Effect') == 'Allow' and statement.get('Principal') in ["*", {"AWS": "*"}]:
                    if 'Condition' not in statement:
                        result.set_status(CheckResult.STATUS_FAIL)
                        result.status_extended = (
                            f"S3 bucket '{bucket_name}' has a public access policy without conditions."
                        )
                        return result

        # If no issues found
        result.set_status(CheckResult.STATUS_PASS)
        result.status_extended = f"S3 bucket '{bucket_name}' is not publicly accessible."

    except Exception as e:
        logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
        result.set_status(CheckResult.STATUS_ERROR)
        result.status_extended = f"Error checking bucket access: {str(e)}"

    return result

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute the CIS 3.3 check for CloudTrail S3 bucket public accessibility.

    Args:
        session: boto3 session
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        List[CheckResult]: List containing check results
    """
    logger.info("Executing CIS 3.3 check for CloudTrail S3 bucket public accessibility")

    # Initialize services using the factory
    cloudtrail_service = service_factory.get_service('cloudtrail')
    s3_service = service_factory.get_service('s3')

    try:
        # Get CloudTrail trails
        trails_response = cloudtrail_service.describe_trails()
        if not trails_response['success']:
            logger.error(f"Error describing CloudTrail trails: {trails_response['error_message']}")
            return [
                CheckResult(
                    resource_id=CHECK_ID,
                    resource_arn=CHECK_ID
                ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                    f"Unable to retrieve CloudTrail trails: {trails_response['error_message']}"
                )
            ]

        results = []
        for trail in trails_response.get('trails', []):
            bucket_name = trail.get('S3BucketName')
            if not bucket_name:
                continue

            result = check_cloudtrail_bucket_public_access(s3_service, bucket_name, logger)
            results.append(result)

        return results

    except Exception as e:
        logger.error(f"Error executing CIS 3.3 check: {str(e)}")
        return [
            CheckResult(
                resource_id=CHECK_ID,
                resource_arn=CHECK_ID
            ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                f"Error executing CIS 3.3 check: {str(e)}"
            )
        ]
