"""CIS 1.14 - Ensure access keys are rotated every 90 days or less."""

from typing import List
import csv
import io
from datetime import datetime, timezone
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_1_14"
CHECK_DESCRIPTION = "Ensure access keys are rotated every 90 days or less"

def check_access_key_rotation(report: List[dict], max_age_days: int = 90) -> List[dict]:
    """
    Check IAM users for access keys older than the specified maximum age.
    
    Args:
        report: List of credential report entries
        max_age_days: Maximum allowed age for access keys in days
        
    Returns:
        List of dictionaries containing information about non-compliant access keys
    """
    issues = []
    now = datetime.now(timezone.utc)
    
    for user in report:
        for key_num in [1, 2]:
            last_rotated = user[f'access_key_{key_num}_last_rotated']
            if last_rotated != 'N/A':
                last_rotated_date = datetime.strptime(last_rotated, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=timezone.utc)
                age = (now - last_rotated_date).days
                if age > max_age_days:
                    issues.append({
                        'user': user['user'],
                        'key_id': user[f'access_key_{key_num}_active'],
                        'age': age,
                        'arn': user['arn']
                    })
    return issues

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.14 check.
    Ensure access keys are rotated every 90 days or less.
    
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
    findings = []
    
    try:
        # Get AWS Account ID
        identity_response = sts_service.get_caller_identity()
        if not identity_response['success']:
            raise ValueError(f"Failed to get AWS Account ID: {identity_response.get('error_message', 'Unknown error')}")
        
        account_id = identity_response['account_id']
        
        # Get credential report
        cred_report_response = iam_service.get_credential_report()
        if not cred_report_response['success']:
            raise ValueError(f"Failed to get credential report: {cred_report_response.get('error_message', 'Unknown error')}")
        
        # Parse credential report
        report = csv.DictReader(io.StringIO(cred_report_response['content'].decode('utf-8')))
        issues = check_access_key_rotation(list(report))
        
        # Create findings based on issues found
        for issue in issues:
            result = CheckResult()
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            result.status = CheckResult.STATUS_FAIL
            result.resource_id = f"AccessKey-{issue['user']}-{issue['key_id']}"
            result.resource_arn = issue['arn']
            result.region = 'global'
            result.resource_tags = []  # Access keys don't have tags
            result.status_extended = f"Access key for user {issue['user']} (Key ID: {issue['key_id']}) has not been rotated in {issue['age']} days."
            result.resource_details = {
                "user": issue['user'],
                "key_id": issue['key_id'],
                "age_days": issue['age']
            }
            findings.append(result)
        
        # If no issues found, create a PASS finding
        if not findings:
            result = CheckResult()
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            result.status = CheckResult.STATUS_PASS
            result.resource_id = f"AccessKeys-{account_id}"
            result.resource_arn = f"arn:aws:iam::{account_id}:root"
            result.region = 'global'
            result.resource_tags = []
            result.status_extended = "All access keys have been rotated within the last 90 days."
            result.resource_details = {"compliant_keys_count": len(list(report))}
            findings.append(result)
            
    except Exception as e:
        logger.error(f"Error executing CIS 1.14 check: {str(e)}")
        result = CheckResult()
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
        result.resource_id = f"AccessKeys-{account_id}" if 'account_id' in locals() else "Unknown"
        result.resource_arn = f"arn:aws:iam::{account_id}:root" if 'account_id' in locals() else "Unknown"
        result.region = 'global'
        result.resource_tags = []
        findings = [result]
    
    return findings
