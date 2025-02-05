"""Fix implementation for CIS 1.14 - Ensure access keys are rotated every 90 days or less."""

from typing import Dict, Any
from datetime import datetime, timezone
import csv
import io
from providers.aws.lib.check_result import CheckResult

def rotate_access_key(iam_service, user_name: str, key_id: str, logger) -> Dict[str, Any]:
    """
    Rotate access key for a given IAM user.
    
    Args:
        iam_service: IAM service instance
        user_name: Name of the IAM user
        key_id: ID of the access key to rotate
        logger: Logger object for logging messages
    
    Returns:
        Dict containing the operation result
    """
    try:
        # Create a new access key
        new_key_response = iam_service.create_access_key(user_name)
        if not new_key_response['success']:
            return {
                'success': False,
                'error_message': f"Failed to create new access key: {new_key_response.get('error_message', 'Unknown error')}"
            }
        
        # Deactivate the old access key
        update_response = iam_service.update_access_key(user_name, key_id, 'Inactive')
        if not update_response['success']:
            return {
                'success': False,
                'error_message': f"Failed to deactivate old access key: {update_response.get('error_message', 'Unknown error')}"
            }
        
        return {
            'success': True,
            'new_key': new_key_response['access_key']
        }
    except Exception as e:
        return {
            'success': False,
            'error_message': str(e)
        }

def get_users_with_old_keys(cred_report: list, max_age_days: int = 90) -> list:
    """
    Get a list of IAM users with access keys older than the specified maximum age.
    
    Args:
        cred_report: List of credential report entries
        max_age_days: Maximum allowed age for access keys in days
    
    Returns:
        List of tuples containing (user_name, key_id, age) for keys older than max_age_days
    """
    users_with_old_keys = []
    now = datetime.now(timezone.utc)
    
    for user in cred_report:
        for key_num in [1, 2]:
            last_rotated = user[f'access_key_{key_num}_last_rotated']
            if last_rotated != 'N/A':
                last_rotated_date = datetime.strptime(last_rotated, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=timezone.utc)
                age = (now - last_rotated_date).days
                if age > max_age_days:
                    users_with_old_keys.append((
                        user['user'],
                        user[f'access_key_{key_num}_active'],
                        age
                    ))
    
    return users_with_old_keys

def execute(session, finding: CheckResult, logger, service_factory) -> CheckResult:
    """
    Execute the fix for CIS 1.14 (Ensure access keys are rotated every 90 days or less).

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
        
        # Get credential report
        cred_report_response = iam_service.get_credential_report()
        if not cred_report_response['success']:
            raise ValueError(f"Failed to get credential report: {cred_report_response.get('error_message', 'Unknown error')}")
        
        # Parse credential report
        report = csv.DictReader(io.StringIO(cred_report_response['content'].decode('utf-8')))
        users_with_old_keys = get_users_with_old_keys(list(report))
        
        if not users_with_old_keys:
            finding.status = CheckResult.STATUS_PASS
            finding.status_extended = "No access keys older than 90 days found. No action needed."
            return finding
        
        rotated_keys = []
        failed_rotations = []
        
        # Rotate old access keys
        for user_name, key_id, age in users_with_old_keys:
            logger.info(f"Attempting to rotate access key for user {user_name} (Key ID: {key_id}, Age: {age} days)")
            rotation_result = rotate_access_key(iam_service, user_name, key_id, logger)
            
            if rotation_result['success']:
                new_key = rotation_result['new_key']
                rotated_keys.append({
                    'user': user_name,
                    'old_key_id': key_id,
                    'new_key_id': new_key['AccessKeyId']
                })
            else:
                failed_rotations.append({
                    'user': user_name,
                    'key_id': key_id,
                    'error': rotation_result['error_message']
                })
        
        # Update finding status based on results
        if failed_rotations:
            finding.status = CheckResult.STATUS_FAIL
            finding.status_extended = (
                f"Failed to rotate some access keys. Successfully rotated: {len(rotated_keys)}, "
                f"Failed: {len(failed_rotations)}"
            )
        else:
            finding.status = CheckResult.STATUS_PASS
            finding.status_extended = f"Successfully rotated all old access keys. Total rotated: {len(rotated_keys)}"
        
        # Add detailed information to the finding
        finding.resource_details = {
            "rotated_keys": rotated_keys,
            "failed_rotations": failed_rotations
        }

    except Exception as e:
        logger.error(f"Error executing fix for {finding.check_id}: {str(e)}")
        finding.status = CheckResult.STATUS_ERROR
        finding.status_extended = f"Error executing fix: {str(e)}"
    
    return finding
