"""CIS 1.12 - Fix for ensuring credentials unused for 45 days or greater are disabled."""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any

def execute(session, finding, logger, service_factory) -> Dict[str, Any]:
    """
    Execute CIS 1.12 fix.
    Disable credentials unused for 45 days or greater.
    
    Args:
        session: boto3 session
        finding: The finding dictionary
        logger: Logger object
        service_factory: AWS service factory instance
        
    Returns:
        Dict[str, Any]: Result of the fix execution
    """
    # Initialize services using the factory
    iam_service = service_factory.get_service('iam')
    
    result = finding.init_remediation()
    
    try:
        # Get credential report
        report_response = iam_service.get_credential_report()
        if not report_response['success']:
            raise ValueError(f"Failed to get credential report: {report_response.get('error_message', 'Unknown error')}")
        
        credential_report = report_response['content'].decode('utf-8').split('\n')
        headers = credential_report[0].split(',')
        users = [dict(zip(headers, line.split(','))) for line in credential_report[1:]]
        
        inactive_users = check_inactive_credentials(users)
        
        if not inactive_users:
            result.mark_as_success("No users found with credentials unused for 45 days or greater. No action needed.")
            return result.to_dict()
        
        fixed_users = []
        failed_users = []
        
        for user in inactive_users:
            try:
                # Disable console access if enabled
                if user['password_enabled'] == 'true':
                    iam_service.delete_login_profile(user['user'])
                
                # Deactivate access keys
                for key_num in [1, 2]:
                    if user[f'access_key_{key_num}_active'] == 'true':
                        iam_service.update_access_key(user['user'], user[f'access_key_{key_num}_id'], 'Inactive')
                
                fixed_users.append(user['user'])
            except Exception as e:
                logger.error(f"Failed to disable credentials for user {user['user']}: {str(e)}")
                failed_users.append(user['user'])
        
        if failed_users:
            result.mark_as_failed(f"Failed to disable credentials for users: {', '.join(failed_users)}")
        elif fixed_users:
            result.mark_as_success(f"Successfully disabled credentials for users: {', '.join(fixed_users)}")
        else:
            result.mark_as_success("No credentials required disabling.")
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.12 fix: {str(e)}")
        result.mark_as_failed(f"Error executing fix: {str(e)}")
    
    return result.to_dict()

def check_inactive_credentials(users):
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
        if user['user'] == '<root_account>':
            continue
        
        is_inactive = False
        
        # Check password
        if user['password_enabled'] == 'true':
            last_used = user['password_last_used']
            if last_used == 'no_information':
                last_used = user['password_last_changed']
            if last_used != 'N/A':
                last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=timezone.utc)
                if (now - last_used_date) > timedelta(days=45):
                    is_inactive = True
        
        # Check access keys
        for key_num in [1, 2]:
            if user[f'access_key_{key_num}_active'] == 'true':
                last_used = user[f'access_key_{key_num}_last_used_date']
                if last_used == 'N/A':
                    last_used = user[f'access_key_{key_num}_last_rotated']
                last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=timezone.utc)
                if (now - last_used_date) > timedelta(days=45):
                    is_inactive = True
        
        if is_inactive:
            inactive_users.append(user)
    
    return inactive_users