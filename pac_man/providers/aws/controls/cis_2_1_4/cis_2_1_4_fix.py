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
    s3_service: S3Service = service_factory.get_service('S3')
    bucket_name = finding.resource_id

    try:
        response = s3_service.put_public_access_block(
            bucket_name,
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True
        )

        if response['success']:
            finding.init_remediation().mark_as_success()
            finding.remediation_result.message = f"Successfully enabled all public access block settings for bucket {bucket_name}"
        else:
            finding.init_remediation().mark_as_failed()
            finding.remediation_result.message = f"Failed to enable public access block settings for bucket {bucket_name}: {response.get('error_message')}"

    except Exception as e:
        logger.error(f"Unexpected error occurred while fixing CIS 2.1.4 for bucket {bucket_name}: {str(e)}")
        finding.init_remediation().mark_as_failed()
        finding.remediation_result.message = f"Unexpected error occurred: {str(e)}"

    return finding