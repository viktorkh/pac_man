"""CIS 1.12 - Ensure credentials unused for 45 days or greater are disabled."""

import json
from typing import List
from datetime import datetime, timezone, timedelta
from providers.aws.lib.check_result import CheckResult

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.12 check.
    Ensure credentials unused for 45 days or greater are disabled.
    
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
    result.check_id = 'cis_1_12'
    result.check_description = 'Ensure credentials unused for 45 days or greater are disabled'
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
        
        inactive_users = check_inactive_credentials(users)
        
        if inactive_users:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"Found {len(inactive_users)} user(s) with credentials unused for 45 days or greater."
            result.resource_details = json.dumps(inactive_users)
        else:
            result.status = CheckResult.STATUS_PASS
            result.status_extended = "No users found with credentials unused for 45 days or greater."
            result.resource_details = json.dumps({})
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.12 check: {str(e)}")
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
    
    return [result]

def check_inactive_credentials(users: List[dict]) -> List[dict]:
    """
    Check for users with inactive credentials.
    
    Args:
        users: List of user credential reports
        
    Returns:
        List of users with inactive credentials
    """
    inactive_users = []
    now = datetime.now(timezone.utc)
    
    for user in users:
        if user.get('user', '') == '<root_account>':
            continue
        
        is_inactive = False
        
        # Check password
        if user.get('password_enabled', 'false') == 'true':
            last_used = user.get('password_last_used', 'N/A')
            if last_used == 'no_information':
                last_used = user.get('password_last_changed', 'N/A')
            if last_used != 'N/A':
                last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=timezone.utc)
                if (now - last_used_date) > timedelta(days=45):
                    is_inactive = True
        
        # Check access keys
        for key_num in [1, 2]:
            if user.get(f'access_key_{key_num}_active', 'false') == 'true':
                last_used = user.get(f'access_key_{key_num}_last_used_date', 'N/A')
                if last_used == 'N/A':
                    last_used = user.get(f'access_key_{key_num}_last_rotated', 'N/A')
                if last_used != 'N/A':
                    last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=timezone.utc)
                    if (now - last_used_date) > timedelta(days=45):
                        is_inactive = True
        
        if is_inactive:
            inactive_users.append({
                'user': user.get('user', 'unknown'),
                'arn': user.get('arn', 'unknown'),
                'password_last_used': user.get('password_last_used', 'N/A'),
                'access_key_1_last_used_date': user.get('access_key_1_last_used_date', 'N/A'),
                'access_key_2_last_used_date': user.get('access_key_2_last_used_date', 'N/A')
            })
    
    return inactive_users

