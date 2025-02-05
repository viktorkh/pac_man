"""CIS 2.1.4 - Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'"""

from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_2_1_4"
CHECK_DESCRIPTION = "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'"

def check_s3_public_access_block(s3_service, bucket_name, logger) -> CheckResult:
    """
    Check if an S3 bucket has public access block enabled.

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
    result.region = "global"

    try:
        public_access_block = s3_service.get_public_access_block(bucket_name)
        
        if not public_access_block['success']:
            error_message = public_access_block.get('error_message', '')
            if 'NoSuchPublicAccessBlockConfiguration' in error_message:
                result.set_status(CheckResult.STATUS_FAIL)
                result.status_extended = f"S3 bucket '{bucket_name}' does not have a public access block configuration"
            else:
                logger.error(f"Error checking public access block for bucket {bucket_name}: {error_message}")
                result.set_status(CheckResult.STATUS_ERROR)
                result.status_extended = f"Unable to verify public access block settings: {error_message}"
            return result

        config = public_access_block.get('PublicAccessBlockConfiguration', {})
        
        if all(config.values()):
            result.set_status(CheckResult.STATUS_PASS)
            result.status_extended = f"S3 bucket '{bucket_name}' has all public access block settings enabled"
        else:
            result.set_status(CheckResult.STATUS_FAIL)
            disabled_settings = [k for k, v in config.items() if not v]
            result.status_extended = f"S3 bucket '{bucket_name}' has the following public access block settings disabled: {', '.join(disabled_settings)}"

    except Exception as e:
        logger.error(f"Error checking public access block for bucket {bucket_name}: {str(e)}")
        result.set_status(CheckResult.STATUS_ERROR)
        result.status_extended = f"Error checking public access block settings: {str(e)}"

    return result

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute the CIS 2.1.4 check for S3 bucket public access block configuration.

    Args:
        session: boto3 session
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        List[CheckResult]: List containing check results
    """
    logger.info("Executing CIS 2.1.4 check for S3 bucket public access block configuration")

    # Initialize services using the factory
    s3_service = service_factory.get_service('s3')

    try:
        # List all S3 buckets
        buckets_response = s3_service.list_buckets()
        if not buckets_response['success']:
            return [
                CheckResult(
                    resource_id=CHECK_ID,
                    resource_arn=CHECK_ID
                ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                    f"Unable to verify S3 bucket public access block settings: {buckets_response['error_message']}"
                )
            ]

        results = []
        for bucket in buckets_response['buckets']:
            result = check_s3_public_access_block(s3_service, bucket['Name'], logger)
            results.append(result)

        return results

    except Exception as e:
        logger.error(f"Error executing CIS 2.1.4 check: {str(e)}")
        return [
            CheckResult(
                resource_id=CHECK_ID,
                resource_arn=CHECK_ID
            ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                f"Unable to verify S3 bucket public access block settings: {str(e)}"
            )
        ]