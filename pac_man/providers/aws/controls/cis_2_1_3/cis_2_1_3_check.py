"""CIS 2.1.3 - Ensure all data in Amazon S3 has been discovered, classified and secured when required."""

from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_2_1_3"
CHECK_DESCRIPTION = "Ensure all data in Amazon S3 has been discovered, classified and secured when required"

def check_macie_enabled(macie_service, logger) -> CheckResult:
    """
    Check if Amazon Macie is enabled and configured for S3 data discovery and classification.

    Args:
        macie_service: MacieService instance
        logger: Logger object for logging messages

    Returns:
        CheckResult: Object containing the check results
    """
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.resource_id = "AmazonMacie"
    result.resource_arn = "arn:aws:macie2:::*"
    result.region = "global"

    # Check if Macie is enabled
    macie_status = macie_service.get_macie_status()
    if not macie_status['success']:
        logger.error(f"Error checking Macie status: {macie_status.get('error_message')}")
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = f"Unable to verify Macie status: {macie_status.get('error_message')}"
        return result

    if macie_status['enabled']:
        # Check if there are any active Macie jobs
        jobs = macie_service.list_classification_jobs()
        if not jobs['success']:
            logger.error(f"Error listing Macie jobs: {jobs.get('error_message')}")
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"Macie is enabled, but unable to verify active jobs: {jobs.get('error_message')}"
            return result

        if jobs['jobs']:
            result.status = CheckResult.STATUS_PASS
            result.status_extended = "Amazon Macie is enabled and has active classification jobs"
        else:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = "Amazon Macie is enabled but no active classification jobs found"
    else:
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = "Amazon Macie is not enabled"

    return result


def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute the CIS 2.1.3 check for Amazon Macie configuration.
    
    Args:
        session: boto3 session
        logger: Logger object for logging messages
        service_factory: AWS service factory instance
        
    Returns:
        List[CheckResult]: List containing check results
    """
    logger.info("Executing CIS 2.1.3 check for Amazon Macie configuration")
    
    # Initialize services using the factory
    macie_service = service_factory.get_service('macie')
    
    try:
        result = check_macie_enabled(macie_service, logger)
        return [result]
        
    except Exception as e:
        logger.error(f"An error occurred during the CIS 2.1.3 check: {str(e)}")
        result = CheckResult()
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        result.status = CheckResult.STATUS_FAIL
        result.status_extended = f"Unable to verify Macie configuration - An error occurred during the check: {str(e)}"
        result.resource_id = "AmazonMacie"
        result.resource_arn = "arn:aws:macie2:::*"
        result.region = "global"
        return [result]
