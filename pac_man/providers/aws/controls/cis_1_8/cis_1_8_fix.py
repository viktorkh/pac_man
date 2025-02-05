"""CIS 1.8 - Fix IAM password policy minimum length requirement."""

from typing import Dict, Any
from providers.aws.lib.check_result import CheckResult

def execute(session, finding: CheckResult, logger, service_factory) -> CheckResult:
    """
    Execute fix for CIS 1.8 check.
    Ensures IAM password policy requires minimum length of 14 or greater.
    
    Args:
        session: boto3 session
        finding: CheckResult object containing the failed check details
        logger: logging object
        service_factory: AWS service factory instance
        
    Returns:
        CheckResult: Updated check result after fix attempt
    """
    # Initialize services using the factory
    iam_service = service_factory.get_service('iam')
    
    try:
        # Get current password policy
        policy_response = iam_service.get_account_password_policy()
        
        if not policy_response['success']:
            if 'NoSuchEntity' not in str(policy_response.get('error_message', '')):
                finding.status = CheckResult.STATUS_FAIL
                finding.status_extended = f"Failed to retrieve password policy: {policy_response.get('error_message', 'Unknown error')}"
                return finding
            
            # No policy exists, create new one
            logger.info("No password policy is set. Creating a new policy with minimum length of 14...")
            policy_config = {
                'MinimumPasswordLength': 14,
                'RequireSymbols': True,
                'RequireNumbers': True,
                'RequireUppercaseCharacters': True,
                'RequireLowercaseCharacters': True,
                'AllowUsersToChangePassword': True
            }
        else:
            # Check if current policy meets requirements
            current_policy = policy_response['policy']
            min_length = current_policy.get('MinimumPasswordLength', 0)
            
            if min_length >= 14:
                finding.status = CheckResult.STATUS_PASS
                finding.status_extended = f"Password policy is already compliant. Minimum password length is {min_length}."
                return finding
            
            # Preserve existing policy settings while updating minimum length
            logger.info(f"Current minimum password length is {min_length}. Updating to 14...")
            policy_config = current_policy.copy()
            policy_config['MinimumPasswordLength'] = 14
        
        # Update or create password policy
        update_response = iam_service.update_account_password_policy(policy_config)
        
        if update_response['success']:
            finding.status = CheckResult.STATUS_PASS
            finding.status_extended = "Password policy updated successfully. Minimum password length set to 14."
        else:
            finding.status = CheckResult.STATUS_FAIL
            finding.status_extended = f"Failed to update password policy: {update_response.get('error_message', 'Unknown error')}"
        
        return finding
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.8 fix: {str(e)}")
        finding.status = CheckResult.STATUS_ERROR
        finding.status_extended = f"Error executing fix: {str(e)}"
        return finding
