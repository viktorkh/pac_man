"""Fix implementation for CIS 3.6 control."""

from ...services.s3_service import S3Service
from ...services.service_factory import AWSServiceFactory

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for the CIS 3.6 finding.

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
        # Check current logging configuration
        logging_response = s3_service.get_bucket_logging(bucket_name)
        logger.info(f"Initial logging configuration for bucket {bucket_name}: {logging_response}")

        if not logging_response['success']:
            error_message = f"Failed to get logging configuration: {logging_response.get('error_message')}"
            logger.error(f"Failed to get logging configuration for bucket {bucket_name}: {error_message}")
            finding.remediation_result.mark_as_failed(error_message=error_message)
            return finding

        if logging_response.get('LoggingEnabled'):
            success_message = f"Logging is already enabled for bucket {bucket_name}"
            logger.info(success_message)
            finding.remediation_result.mark_as_success(details=success_message, current_state={"logging_enabled": True})
            finding.status = "PASS"  # Update the finding status
            return finding

        # Enable logging
        logging_config = {
            'TargetBucket': bucket_name,
            'TargetPrefix': 'logs/'
        }

        response = s3_service.put_bucket_logging(bucket_name, logging_config)
        logger.info(f"put_bucket_logging response for bucket {bucket_name}: {response}")

        if response['success']:
            # Verify that logging was actually enabled
            verify_response = s3_service.get_bucket_logging(bucket_name)
            logger.info(f"Verification logging configuration for bucket {bucket_name}: {verify_response}")

            if verify_response['success'] and verify_response.get('LoggingEnabled'):
                success_message = f"Successfully enabled logging for bucket {bucket_name}"
                logger.info(success_message)
                finding.remediation_result.mark_as_success(details=success_message, current_state={"logging_enabled": True})
                finding.status = "PASS"  # Update the finding status
            else:
                error_message = f"Logging configuration not found after enabling for bucket {bucket_name}"
                logger.error(error_message)
                finding.remediation_result.mark_as_failed(error_message=error_message)
                finding.status = "FAIL"  # Update the finding status
        else:
            error_message = f"Failed to enable logging for bucket {bucket_name}: {response.get('error_message')}"
            logger.error(error_message)
            finding.remediation_result.mark_as_failed(error_message=error_message)
            finding.status = "FAIL"  # Update the finding status

    except Exception as e:
        error_message = f"Unexpected error occurred while fixing CIS 3.6 for bucket {bucket_name}: {str(e)}"
        logger.error(error_message)
        finding.remediation_result.mark_as_failed(error_message=error_message)
        finding.status = "FAIL"  # Update the finding status

    return finding


