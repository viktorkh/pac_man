"""Fix implementation for CIS 1.20 control."""

from ...services.access_analyzer_service import AccessAnalyzerService
from ...services.service_factory import AWSServiceFactory

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for CIS 1.20 (Ensure IAM Access Analyzer is enabled).

    Args:
        session (boto3.Session): The boto3 session to use for making AWS API calls.
        finding (CheckResult): The CheckResult object containing the finding details.
        logger: Logger object for logging messages.
        service_factory (AWSServiceFactory): Factory for creating AWS service instances.

    Returns:
        CheckResult: The updated finding object with fix results.
    """
    logger.info(f"Executing fix for {finding.check_id} in region {finding.region}")

    # Initialize remediation tracking
    remediation = finding.init_remediation()
    remediation.provider = "aws"
    remediation.region = finding.region

    try:
        # Get the Access Analyzer service instance for the region
        service = service_factory.get_service('access_analyzer', finding.region)

        # Create the analyzer
        analyzer_name = f'DefaultAnalyzer-{finding.region}'
        result = service.create_analyzer(analyzer_name)

        if result['success']:
            logger.info(f"Successfully created IAM Access Analyzer in region {finding.region}")
            finding.status = "PASS"
            finding.status_extended = f"IAM Access Analyzer created: {result['arn']}"
            
            # Update remediation result with success
            remediation.mark_as_success(
                details=f"Successfully created IAM Access Analyzer: {result['arn']}",
                current_state={
                    "status": "PASS",
                    "analyzer_arn": result['arn'],
                    "analyzer_name": analyzer_name
                }
            )
        else:
            error_msg = result.get('error_message', 'Unknown error')
            logger.error(f"Failed to create IAM Access Analyzer in region {finding.region}: {error_msg}")
            finding.status_extended = f"Fix attempt failed: {error_msg}"
            
            # Update remediation result with failure
            remediation.mark_as_failed(
                error_message=error_msg,
                details=f"Failed to create IAM Access Analyzer in region {finding.region}"
            )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error during fix execution: {error_msg}")
        finding.status_extended = f"Fix attempt failed: {error_msg}"
        
        # Update remediation result with failure
        remediation.mark_as_failed(
            error_message=error_msg,
            details=f"Exception occurred while creating IAM Access Analyzer in region {finding.region}"
        )

    return finding
