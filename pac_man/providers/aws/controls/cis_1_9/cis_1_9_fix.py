"""CIS 1.9 fix - Update IAM password policy to prevent password reuse."""

from providers.aws.lib.check_result import CheckResult

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for CIS 1.9 (Ensure IAM password policy prevents password reuse).

    Args:
        session: boto3 session
        finding (CheckResult): The CheckResult object containing the finding details
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        CheckResult: The updated CheckResult object after attempting the fix
    """
    logger.info(f"Executing fix for {finding.check_id}")

    try:
        # Initialize IAM service
        iam_service = service_factory.get_service('iam')
        
        # Check current password policy
        policy_response = iam_service.get_account_password_policy()
        
        if not policy_response['success']:
            if 'NoSuchEntity' in str(policy_response.get('error_message', '')):
                current_prevention = 0
            else:
                raise ValueError(f"Error checking password policy: {policy_response.get('error_message', 'Unknown error')}")
        else:
            current_prevention = policy_response['policy'].get('PasswordReusePrevention', 0)

        if current_prevention >= 24:
            finding.status = CheckResult.STATUS_PASS
            finding.status_extended = f"IAM password policy already prevents reuse of the last {current_prevention} passwords. No changes needed."
        else:
            logger.info(f"Current password reuse prevention is set to {current_prevention}. Updating to 24...")
            
            # Update password policy
            update_response = iam_service.update_account_password_policy({
                'PasswordReusePrevention': 24
            })
            
            if update_response['success']:
                finding.status = CheckResult.STATUS_PASS
                finding.status_extended = "IAM password policy updated to prevent reuse of the last 24 passwords."
            else:
                finding.status = CheckResult.STATUS_FAIL
                finding.status_extended = f"Failed to update IAM password policy: {update_response.get('error_message', 'Unknown error')}"

    except Exception as e:
        logger.error(f"An error occurred while fixing {finding.check_id}: {e}")
        finding.status = CheckResult.STATUS_FAIL
        finding.status_extended = f"Fix attempt failed: {str(e)}"

    return finding
