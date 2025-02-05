"""CIS 1.9 - Ensure IAM password policy prevents password reuse."""

from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_1_9"
CHECK_DESCRIPTION = "Ensure IAM password policy prevents password reuse"

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.9 check.
    Ensure IAM password policy prevents reuse of the last 24 passwords.
    
    Args:
        session: boto3 session
        logger: logging object
        service_factory: AWS service factory instance
        
    Returns:
        List[CheckResult]: List containing check results
    """
    # Initialize services using the factory
    iam_service = service_factory.get_service('iam')
    sts_service = service_factory.get_service('sts')
    
    # Initialize check result
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.region = 'global'
    result.resource_tags = []  # Password policies don't have tags
    
    try:
        # Get AWS Account ID
        identity_response = sts_service.get_caller_identity()
        if not identity_response['success']:
            raise ValueError(f"Failed to get AWS Account ID: {identity_response.get('error_message', 'Unknown error')}")
        
        account_id = identity_response['account_id']
        result.resource_id = f"PasswordPolicy-{account_id}"
        result.resource_arn = f"arn:aws:iam::{account_id}:account-password-policy"
        
        # Check password policy
        policy_response = iam_service.get_account_password_policy()
        
        if not policy_response['success']:
            if 'NoSuchEntity' in str(policy_response.get('error_message', '')):
                result.status = CheckResult.STATUS_FAIL
                result.status_extended = "No IAM password policy is set."
                result.resource_details = "{}"
            else:
                raise ValueError(f"Error checking password policy: {policy_response.get('error_message', 'Unknown error')}")
            return [result]
        
        policy = policy_response['policy']
        reuse_prevention = policy.get('PasswordReusePrevention', 0)
        
        # Set result details
        result.resource_details = str(policy)
        
        if reuse_prevention == 24:
            result.status = CheckResult.STATUS_PASS
            result.status_extended = "IAM password policy prevents password reuse for 24 passwords."
        elif reuse_prevention > 0:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"IAM password policy prevents password reuse for {reuse_prevention} passwords, but it should be 24."
        else:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = "IAM password policy does not prevent password reuse."
            
    except Exception as e:
        logger.error(f"Error executing CIS 1.9 check: {str(e)}")
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
    
    return [result]
