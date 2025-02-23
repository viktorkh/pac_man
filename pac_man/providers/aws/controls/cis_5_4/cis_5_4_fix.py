"""Fix implementation for CIS 5.4 control."""

from ...services.ec2_service import EC2Service
from ...services.service_factory import AWSServiceFactory
from botocore.exceptions import ClientError

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for the CIS 5.4 finding.

    Args:
        session: The AWS session
        finding: The finding object
        logger: The logger object
        service_factory: The AWS service factory

    Returns:
        The updated finding object
    """
  
    ec2_service: EC2Service = service_factory.get_service('ec2')
    security_group_id = finding.resource_id

    try:
        # Describe the security group first to get current rules
        describe_response = ec2_service.describe_security_groups(GroupIds=[security_group_id])
        if not isinstance(describe_response, dict) or 'SecurityGroups' not in describe_response:
            raise ValueError(f"Failed to describe security group: {describe_response}")

        security_group = describe_response['SecurityGroups'][0]
        current_ingress = security_group.get('IpPermissions', [])
        current_egress = security_group.get('IpPermissionsEgress', [])

        # Remove all inbound and outbound rules
        try:
            if current_ingress:
                ec2_service.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=current_ingress
                )
            if current_egress:
                ec2_service.revoke_security_group_egress(
                    GroupId=security_group_id,
                    IpPermissions=current_egress
                )
            response = True
        except ClientError as e:
            response = {'success': False, 'error_message': str(e)}

        logger.info(f"update_security_group_rules response for security group {security_group_id}: {response}")

        if response is True:
            # Verify that rules were actually removed
            verify_response = ec2_service.describe_security_groups(GroupIds=[security_group_id])
            logger.info(f"Verification security group configuration for {security_group_id}: {verify_response}")

            if isinstance(verify_response, dict) and 'SecurityGroups' in verify_response:
                sg = verify_response['SecurityGroups'][0]
                if not sg.get('IpPermissions') and not sg.get('IpPermissionsEgress'):
                    success_message = f"Successfully removed all rules from default security group {security_group_id}"
                    logger.info(success_message)
                    finding.remediation_result.mark_as_success(details=success_message, current_state={"rules_removed": True})
                    finding.status = "PASS"
                else:
                    error_message = f"Failed to remove all rules from default security group {security_group_id}"
                    logger.error(error_message)
                    finding.remediation_result.mark_as_failed(error_message=error_message)
                    finding.status = "FAIL"
            else:
                error_message = f"Failed to verify security group {security_group_id}: {verify_response.get('error_message', 'Unknown error')}"
                logger.error(error_message)
                finding.remediation_result.mark_as_failed(error_message=error_message)
                finding.status = "FAIL"
        else:
            error_message = f"Failed to update rules for security group {security_group_id}: {response.get('error_message', 'Unknown error')}"
            logger.error(error_message)
            finding.remediation_result.mark_as_failed(error_message=error_message)
            finding.status = "FAIL"

    except Exception as e:
        error_message = f"Unexpected error occurred while fixing CIS 5.4 for security group {security_group_id}: {str(e)}"
        logger.error(error_message)
        finding.remediation_result.mark_as_failed(error_message=error_message)
        finding.status = "FAIL"

    return finding