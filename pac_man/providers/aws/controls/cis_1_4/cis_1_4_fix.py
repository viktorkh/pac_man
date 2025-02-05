"""CIS 1.4 - Fix root account access key existence."""

import csv
import io
from typing import Dict, Any
from providers.aws.lib.check_result import CheckResult

def execute(session, finding: CheckResult, logger, service_factory) -> CheckResult:
    """
    Execute fix for CIS 1.4 check.
    Deletes any existing root account access keys.
    
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
        # Get credential report to identify active keys
        response = iam_service.get_credential_report()
        
        if not response['success']:
            finding.status = CheckResult.STATUS_FAIL
            finding.status_extended = f"Error getting credential report: {response.get('error_message', 'Unknown error')}"
            return finding
            
        try:
            # Parse CSV content to find root account keys
            csv_content = io.StringIO(response['content'].decode('utf-8'))
            reader = csv.DictReader(csv_content)
            
            # Verify all required fields are present
            required_fields = ['user', 'access_key_1_active', 'access_key_1_last_rotated', 
                             'access_key_2_active', 'access_key_2_last_rotated']
            header = reader.fieldnames
            if not header or not all(field in header for field in required_fields):
                finding.status = CheckResult.STATUS_ERROR
                finding.status_extended = "Error parsing credential report: Missing required fields"
                return finding
            
            root_keys_deleted = []
            root_found = False
            
            for row in reader:
                if row['user'] == '<root_account>':
                    root_found = True
                    if row['access_key_1_active'] == 'true':
                        # Delete access key 1
                        key_id = row['access_key_1_last_rotated'].split('/')[0]
                        delete_response = iam_service.delete_access_key(
                            user_name='root',
                            access_key_id=key_id
                        )
                        if delete_response['success']:
                            root_keys_deleted.append('Key 1')
                        else:
                            finding.status = CheckResult.STATUS_FAIL
                            finding.status_extended = f"Failed to delete root access key 1: {delete_response.get('error_message', 'Unknown error')}"
                            return finding
                            
                    if row['access_key_2_active'] == 'true':
                        # Delete access key 2
                        key_id = row['access_key_2_last_rotated'].split('/')[0]
                        delete_response = iam_service.delete_access_key(
                            user_name='root',
                            access_key_id=key_id
                        )
                        if delete_response['success']:
                            root_keys_deleted.append('Key 2')
                        else:
                            finding.status = CheckResult.STATUS_FAIL
                            finding.status_extended = f"Failed to delete root access key 2: {delete_response.get('error_message', 'Unknown error')}"
                            return finding
                    
                    break
            
            if not root_found:
                finding.status = CheckResult.STATUS_ERROR
                finding.status_extended = "Error parsing credential report: Root account not found"
                return finding
            
            # Update finding status based on remediation results
            if root_keys_deleted:
                finding.status = CheckResult.STATUS_PASS
                finding.status_extended = f"Successfully deleted root account access keys: {', '.join(root_keys_deleted)}"
            else:
                finding.status = CheckResult.STATUS_PASS
                finding.status_extended = "No root account access keys found to delete"
                
            return finding
            
        except csv.Error as e:
            finding.status = CheckResult.STATUS_ERROR
            finding.status_extended = f"Error parsing credential report: {str(e)}"
            return finding
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.4 fix: {str(e)}")
        finding.status = CheckResult.STATUS_ERROR
        finding.status_extended = f"Error executing fix: {str(e)}"
        return finding
