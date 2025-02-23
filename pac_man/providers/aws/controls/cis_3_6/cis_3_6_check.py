from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_3_6"
CHECK_DESCRIPTION = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"

def check_s3_bucket_logging(s3_service, bucket_name, logger) -> CheckResult:
    """Check if S3 bucket access logging is enabled for a specific bucket."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.resource_id = bucket_name
    result.resource_arn = f"arn:aws:s3:::{bucket_name}"

    try:
        logging_config = s3_service.get_bucket_logging(bucket_name)
        if logging_config['success'] and logging_config['LoggingEnabled']:
            result.status = CheckResult.STATUS_PASS
            result.status_extended = f"S3 bucket access logging is enabled for bucket {bucket_name}."
        else:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"S3 bucket access logging is not enabled for bucket {bucket_name}."
    except Exception as e:
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error checking S3 bucket access logging for bucket {bucket_name}: {str(e)}"
        logger.error(f"Error in check_s3_bucket_logging: {str(e)}")

    return result


def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute the CIS 3.6 check for S3 bucket access logging on CloudTrail buckets.

    Args:
        session: boto3 session
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        List[CheckResult]: List containing check results
    """
    logger.info("Executing CIS 3.6 check for S3 bucket access logging on CloudTrail buckets")

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
                    check_id=CHECK_ID,
                    check_description=CHECK_DESCRIPTION,
                    resource_id="CloudTrailS3Buckets",
                    resource_arn="arn:aws:s3:::*"
                ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                    f"Unable to retrieve CloudTrail trails: {trails_response['error_message']}"
                )
            ]

        results = []
        for trail in trails_response.get('trails', []):
            bucket_name = trail.get('S3BucketName')
            if not bucket_name:
                continue

            result = check_s3_bucket_logging(s3_service, bucket_name, logger)
            results.append(result)

        return results

    except Exception as e:
        logger.error(f"Error executing CIS 3.6 check: {str(e)}")
        return [
            CheckResult(
                check_id=CHECK_ID,
                check_description=CHECK_DESCRIPTION,
                resource_id="CloudTrailS3Buckets",
                resource_arn="arn:aws:s3:::*"
            ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                f"Error executing CIS 3.6 check: {str(e)}"
            )
        ]