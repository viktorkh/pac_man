"""CIS 1.13 - Ensure there is only one active access key available for any single IAM user (including root)."""

from typing import List
import csv
import io
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_1_13"
CHECK_DESCRIPTION = "Ensure there is only one active access key available for any single IAM user (including root)"

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.13 check.
    Ensure there is only one active access key available for any single IAM user (including root).
    
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
        
        # Check root account access keys
        cred_report_response = iam_service.get_credential_report()
        if not cred_report_response['success']:
            raise ValueError(f"Failed to get credential report: {cred_report_response.get('error_message', 'Unknown error')}")
        
        report = csv.DictReader(io.StringIO(cred_report_response['content'].decode('utf-8')))
        for row in report:
            if row['user'] == '<root_account>':
                result = CheckResult()
                result.check_id = CHECK_ID
                result.check_description = CHECK_DESCRIPTION
                result.resource_id = f"{account_id}:root"
                result.resource_arn = f"arn:aws:iam::{account_id}:root"
                result.region = 'global'
                result.resource_tags = []  # Root account doesn't have tags
                
                active_keys_count = sum(1 for key in ['access_key_1_active', 'access_key_2_active'] 
                                     if row[key] == 'true')
                
                if active_keys_count > 0:
                    result.status = CheckResult.STATUS_FAIL
                    result.status_extended = f"Root account has {active_keys_count} active access key(s). It's recommended to have 0 active access keys for the root account."
                else:
                    result.status = CheckResult.STATUS_PASS
                    result.status_extended = "Root account has 0 active access keys."
                
                findings.append(result)
                break
        
        # Check IAM users
        users_response = iam_service.list_users()
        if not users_response['success']:
            logger.error(f"Failed to list IAM users: {users_response.get('error_message', 'Unknown error')}")
            result = CheckResult()
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            result.status = CheckResult.STATUS_ERROR
            result.status_extended = f"Failed to list IAM users: {users_response.get('error_message', 'Unknown error')}"
            result.resource_id = f"{account_id}:users"
            result.resource_arn = f"arn:aws:iam::{account_id}:root"
            result.region = 'global'
            findings.append(result)
            return findings
        
        for user in users_response['users']:
            result = CheckResult()
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            result.resource_id = user['UserName']
            result.resource_arn = user['Arn']
            result.region = 'global'
            result.resource_tags = []  # We could add user tags here if needed
            
            # Get user's access keys
            keys_response = iam_service.list_access_keys(user['UserName'])
            if not keys_response['success']:
                result.status = CheckResult.STATUS_ERROR
                result.status_extended = f"Failed to list access keys for user {user['UserName']}: {keys_response.get('error_message', 'Unknown error')}"
                findings.append(result)
                continue
            
            active_keys = [key for key in keys_response['access_keys'] 
                         if key['Status'] == 'Active']
            
            if len(active_keys) > 1:
                result.status = CheckResult.STATUS_FAIL
                result.status_extended = f"User {user['UserName']} has {len(active_keys)} active access keys."
            else:
                result.status = CheckResult.STATUS_PASS
                result.status_extended = f"User {user['UserName']} has {len(active_keys)} active access key."
            
            findings.append(result)
            
    except Exception as e:
        logger.error(f"Error executing CIS 1.13 check: {str(e)}")
        result = CheckResult()
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
        result.resource_id = f"{account_id}:users" if 'account_id' in locals() else "UNKNOWN"
        result.resource_arn = f"arn:aws:iam::{account_id}:root" if 'account_id' in locals() else "UNKNOWN"
        result.region = 'global'
        findings = [result]
    
    return findings
