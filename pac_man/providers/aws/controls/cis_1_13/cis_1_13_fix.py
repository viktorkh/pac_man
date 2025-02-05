"""Fix implementation for CIS 1.13 - Ensure there is only one active access key available for any single IAM user."""

from typing import List, Tuple
from providers.aws.lib.check_result import CheckResult

def execute(session, finding: CheckResult, logger, service_factory) -> CheckResult:
    """
    Execute the fix for CIS 1.13 (Ensure there is only one active access key available for any single IAM user).

    Args:
        session: boto3 session
        finding: CheckResult object containing the finding details
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        CheckResult: The updated CheckResult object after attempting the fix
    """
    logger.info(f"Executing fix for {finding.check_id}")

    try:
        # Initialize IAM service
        iam_service = service_factory.get_service('iam')
        
        # Get list of all IAM users
        users_response = iam_service.list_users()
        if not users_response['success']:
            raise ValueError(f"Failed to list IAM users: {users_response.get('error_message', 'Unknown error')}")
        
        users_with_multiple_keys = []
        successful_fixes = []
        failed_fixes = []
        error_users = []  # Track users where we couldn't determine key status

        # Check each user's access keys
        for user in users_response['users']:
            user_name = user['UserName']
            
            # Get user's access keys
            keys_response = iam_service.list_access_keys(user_name)
            if not keys_response['success']:
                logger.error(f"Failed to list access keys for user {user_name}: {keys_response.get('error_message', 'Unknown error')}")
                error_users.append(user_name)
                continue
            
            active_keys = [key for key in keys_response['access_keys'] 
                         if key['Status'] == 'Active']
            
            if len(active_keys) > 1:
                users_with_multiple_keys.append((user_name, active_keys))
        
        # Fix users with multiple active keys
        for user_name, active_keys in users_with_multiple_keys:
            try:
                # Keep the first key active, deactivate all others
                for key in active_keys[1:]:
                    update_response = iam_service.update_access_key(
                        user_name=user_name,
                        access_key_id=key['AccessKeyId'],
                        status='Inactive'
                    )
                    if not update_response['success']:
                        raise ValueError(f"Failed to deactivate access key: {update_response.get('error_message', 'Unknown error')}")
                
                successful_fixes.append(user_name)
                logger.info(f"Successfully deactivated extra access keys for user {user_name}")
            
            except Exception as e:
                logger.error(f"Failed to deactivate access keys for user {user_name}: {str(e)}")
                failed_fixes.append(user_name)
        
        # Update finding status based on results
        if error_users:
            finding.status = CheckResult.STATUS_ERROR
            finding.status_extended = f"Could not verify access key status for users: {', '.join(error_users)}"
        elif not users_with_multiple_keys:
            finding.status = CheckResult.STATUS_PASS
            finding.status_extended = "No users with multiple active access keys found. No action needed."
        elif failed_fixes:
            finding.status = CheckResult.STATUS_FAIL
            finding.status_extended = (
                f"Failed to deactivate extra access keys for users: {', '.join(failed_fixes)}. "
                f"Successfully fixed for users: {', '.join(successful_fixes)}"
            )
        else:
            finding.status = CheckResult.STATUS_PASS
            finding.status_extended = f"Successfully deactivated extra access keys for all affected users: {', '.join(successful_fixes)}"

    except Exception as e:
        logger.error(f"Error executing fix for {finding.check_id}: {str(e)}")
        finding.status = CheckResult.STATUS_ERROR
        finding.status_extended = f"Error executing fix: {str(e)}"
    
    return finding
