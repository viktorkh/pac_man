"""CIS 1.10 - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password."""

import json
from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = 'cis_1_10'
CHECK_DESCRIPTION = 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password'

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.10 check.
    Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password.
    
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
    result.resource_tags = []  # Credential reports don't have tags
    
    try:
        # Get AWS Account ID
        identity_response = sts_service.get_caller_identity()
        if not identity_response['success']:
            raise ValueError(f"Failed to get AWS Account ID: {identity_response.get('error_message', 'Unknown error')}")
        
        account_id = identity_response['account_id']
        result.resource_id = f"CredentialReport-{account_id}"
        result.resource_arn = f"arn:aws:iam::{account_id}:credential-report"
        
        # Get credential report
        report_response = iam_service.get_credential_report()
        if not report_response['success']:
            raise ValueError(f"Failed to get credential report: {report_response.get('error_message', 'Unknown error')}")
        
        credential_report = report_response['content'].decode('utf-8').split('\n')
        headers = credential_report[0].split(',')
        users = [dict(zip(headers, line.split(','))) for line in credential_report[1:] if line]
        
        users_without_mfa = check_users_without_mfa(users)
        
        if users_without_mfa:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"Found {len(users_without_mfa)} IAM user(s) with a console password but without MFA enabled."
            result.resource_details = json.dumps(users_without_mfa)
        else:
            result.status = CheckResult.STATUS_PASS
            result.status_extended = "All IAM users with a console password have MFA enabled."
            result.resource_details = json.dumps({})
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.10 check: {str(e)}")
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
    
    return [result]

def check_users_without_mfa(users: List[dict]) -> List[dict]:
    """
    Check for users with a console password but without MFA enabled.
    
    Args:
        users: List of user credential reports
        
    Returns:
        List of users with a console password but without MFA
    """
    users_without_mfa = []
    
    for user in users:
        # root user by default does not support console password
        if user.get('user', '') == '<root_account>':
            continue
        
        if user.get('password_enabled', 'false') == 'true' and user.get('mfa_active', 'false') == 'false':
            users_without_mfa.append({
                'user': user.get('user', 'unknown'),
                'arn': user.get('arn', 'unknown'),
                'password_last_used': user.get('password_last_used', 'N/A'),
                'password_last_changed': user.get('password_last_changed', 'N/A')
            })
    
    return users_without_mfa