"""CIS 1.8 - Ensure IAM password policy requires minimum length of 14 or greater."""

import json
from typing import List
from providers.aws.lib.check_result import CheckResult

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.8 check.
    Ensure IAM password policy requires minimum length of 14 or greater.
    
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
    result.check_id = 'cis_1_8'
    result.check_description = 'Ensure IAM password policy requires minimum length of 14 or greater'
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
        
        # Get password policy using IAM service
        policy_response = iam_service.get_account_password_policy()
        
        if not policy_response['success']:
            if 'NoSuchEntity' in str(policy_response.get('error_message', '')):
                # No password policy is set
                result.status = CheckResult.STATUS_FAIL
                result.status_extended = "No password policy is set. A policy with a minimum length of 14 characters should be created."
                result.resource_details = json.dumps({})
            else:
                # Other error occurred
                raise ValueError(f"Failed to get password policy: {policy_response.get('error_message', 'Unknown error')}")
        else:
            # Check password policy minimum length
            password_policy = policy_response['policy']
            min_length = password_policy.get('MinimumPasswordLength', 0)
            
            if min_length >= 14:
                result.status = CheckResult.STATUS_PASS
                result.status_extended = f"Password policy is compliant. Minimum password length is {min_length}."
            else:
                result.status = CheckResult.STATUS_FAIL
                result.status_extended = f"Password policy is not compliant. Current minimum password length is {min_length}. It should be at least 14 characters."
            
            result.resource_details = json.dumps(password_policy)
            
    except Exception as e:
        logger.error(f"Error executing CIS 1.8 check: {str(e)}")
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
    
    return [result]
