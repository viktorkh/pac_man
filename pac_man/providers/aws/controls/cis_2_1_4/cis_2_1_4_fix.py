"""Fix implementation for CIS 2.1.4 control."""

from ...services.s3_service import S3Service
from ...services.service_factory import AWSServiceFactory

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for the CIS 2.1.4 finding.

    Args:
        session: The AWS session
        finding: The finding object
        logger: The logger object
        service_factory: The AWS service factory

    Returns:
        The updated finding object
    """
    s3_service: S3Service = service_factory.get_service('s3')
    bucket_name = finding.resource_id

    try:
        # Check current public access block configuration
        current_config = s3_service.get_public_access_block(bucket_name)
        logger.info(f"Initial public access block configuration for bucket {bucket_name}: {current_config}")

        if not current_config['success']:
            error_message = f"Failed to get public access block configuration: {current_config.get('error_message')}"
            logger.error(f"Failed to get public access block configuration for bucket {bucket_name}: {error_message}")
            finding.remediation_result.mark_as_failed(error_message=error_message)
            return finding

        if current_config.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls') and \
           current_config.get('PublicAccessBlockConfiguration', {}).get('IgnorePublicAcls') and \
           current_config.get('PublicAccessBlockConfiguration', {}).get('BlockPublicPolicy') and \
           current_config.get('PublicAccessBlockConfiguration', {}).get('RestrictPublicBuckets'):
            success_message = f"Public access block is already properly configured for bucket {bucket_name}"
            logger.info(success_message)
            finding.remediation_result.mark_as_success(details=success_message, current_state=current_config.get('PublicAccessBlockConfiguration', {}))
            finding.status = "PASS"
            return finding

        # Apply public access block
        response = s3_service.put_public_access_block(
            bucket_name,
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True
        )
        logger.info(f"put_public_access_block response for bucket {bucket_name}: {response}")

        if response['success']:
            # Verify that public access block was actually applied
            verify_response = s3_service.get_public_access_block(bucket_name)
            logger.info(f"Verification public access block configuration for bucket {bucket_name}: {verify_response}")

            if verify_response['success'] and all(verify_response.get('PublicAccessBlockConfiguration', {}).values()):
                success_message = f"Successfully applied public access block for bucket {bucket_name}"
                logger.info(success_message)
                finding.remediation_result.mark_as_success(details=success_message, current_state=verify_response.get('PublicAccessBlockConfiguration', {}))
                finding.status = "PASS"
            else:
                error_message = f"Public access block configuration not found or incomplete after applying for bucket {bucket_name}"
                logger.error(error_message)
                finding.remediation_result.mark_as_failed(error_message=error_message)
                finding.status = "FAIL"
        else:
            error_message = f"Failed to apply public access block for bucket {bucket_name}: {response.get('error_message')}"
            logger.error(error_message)
            finding.remediation_result.mark_as_failed(error_message=error_message)
            finding.status = "FAIL"

    except Exception as e:
        error_message = f"Unexpected error occurred while fixing CIS 2.1.4 for bucket {bucket_name}: {str(e)}"
        logger.error(error_message)
        finding.remediation_result.mark_as_failed(error_message=error_message)
        finding.status = "FAIL"

    return finding
