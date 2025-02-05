"""Fix implementation for CIS 3.3 control."""

from ...services.s3_service import S3Service
from ...services.service_factory import AWSServiceFactory

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for the CIS 3.3 finding.

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
        # Fix bucket ACL by removing public access grants
        acl_response = s3_service.get_bucket_acl(bucket_name)
        if acl_response['success']:
            for grant in acl_response['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group' and grantee.get('URI') in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                ]:
                    # Remove offending ACL entry
                    logger.info(f"Removing public ACL grant from bucket {bucket_name}")
                    acl_update_response = s3_service.remove_bucket_acl(bucket_name, grantee)
                    if not acl_update_response['success']:
                        logger.error(f"Failed to remove public ACL grant from bucket {bucket_name}: {acl_update_response['error_message']}")
                        finding.init_remediation().mark_as_failed()
                        finding.remediation_result.message = f"Failed to remove public ACL grant: {acl_update_response['error_message']}"
                        return finding

        # Fix bucket policy by removing public access statements
        policy_response = s3_service.get_bucket_policy(bucket_name)
        if policy_response['success']:
            bucket_policy = policy_response.get('policy', {})
            updated_policy = []

            for statement in bucket_policy.get('Statement', []):
                if statement.get('Effect') == 'Allow' and statement.get('Principal') in ["*", {"AWS": "*"}]:
                    if 'Condition' not in statement:
                        logger.info(f"Removing public access policy statement from bucket {bucket_name}")
                        continue  # Skip adding this statement to the updated policy
                updated_policy.append(statement)

            # Apply updated policy
            policy_update_response = s3_service.put_bucket_policy(bucket_name, {'Version': '2012-10-17', 'Statement': updated_policy})
            if not policy_update_response['success']:
                logger.error(f"Failed to update bucket policy for {bucket_name}: {policy_update_response['error_message']}")
                finding.init_remediation().mark_as_failed()
                finding.remediation_result.message = f"Failed to update bucket policy: {policy_update_response['error_message']}"
                return finding

        # Apply public access block settings
        response = s3_service.put_public_access_block(
            bucket_name,
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True
        )

        if response['success']:
            finding.init_remediation().mark_as_success()
            finding.remediation_result.message = f"Successfully removed public access and enabled all public access block settings for bucket {bucket_name}"
        else:
            finding.init_remediation().mark_as_failed()
            finding.remediation_result.message = f"Failed to enable public access block settings for bucket {bucket_name}: {response.get('error_message')}"

    except Exception as e:
        logger.error(f"Unexpected error occurred while fixing CIS 3.3 for bucket {bucket_name}: {str(e)}")
        finding.init_remediation().mark_as_failed()
        finding.remediation_result.message = f"Unexpected error occurred: {str(e)}"

    return finding
