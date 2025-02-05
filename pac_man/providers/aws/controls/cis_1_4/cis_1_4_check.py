"""CIS 1.4 - Ensure no 'root' user account access key exists."""

import csv
import io
from typing import List
from providers.aws.lib.check_result import CheckResult

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.4 check.
    Ensure no root account access key exists.
    
    Args:
        session: boto3 session
        logger: logging object
        service_factory: AWS service factory instance
        
    Returns:
        List[CheckResult]: List containing check results
    """
    # Initialize services using the factory
    iam_service = service_factory.get_service('iam')
    
    # Initialize check result
    result = CheckResult()
    result.check_id = 'cis_1_4'
    result.check_description = 'Ensure no root account access key exists'
    result.resource_id = 'Root Account'
    result.region = 'global'
    result.resource_tags = []
    result.resource_details = 'AWS root account'
    
    try:
        # Get credential report using IAM service
        response = iam_service.get_credential_report()
        
        if not response['success']:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"Error getting credential report: {response.get('error_message', 'Unknown error')}"
            return [result]
            
        try:
            # Parse CSV content to find root account keys
            csv_content = io.StringIO(response['content'].decode('utf-8'))
            reader = csv.DictReader(csv_content)
            
            # Verify all required fields are present
            required_fields = ['user', 'access_key_1_active', 'access_key_2_active']
            header = reader.fieldnames
            if not header or not all(field in header for field in required_fields):
                result.status = CheckResult.STATUS_ERROR
                result.status_extended = "Error parsing credential report: Missing required fields"
                return [result]
            
            root_found = False
            for row in reader:
                if row['user'] == '<root_account>':
                    root_found = True
                    # Check if root account has access keys
                    try:
                        key1_active = row['access_key_1_active'].lower() == 'true'
                        key2_active = row['access_key_2_active'].lower() == 'true'
                        
                        if key1_active or key2_active:
                            active_keys = []
                            if key1_active:
                                active_keys.append('Key 1')
                            if key2_active:
                                active_keys.append('Key 2')
                            
                            result.status = CheckResult.STATUS_FAIL
                            result.status_extended = f"Root account has active access keys: {', '.join(active_keys)}"
                        else:
                            result.status = CheckResult.STATUS_PASS
                            result.status_extended = "Root account has no active access keys"
                    except (KeyError, ValueError) as e:
                        result.status = CheckResult.STATUS_ERROR
                        result.status_extended = f"Error parsing credential report: Invalid field values: {str(e)}"
                        return [result]
                    break
            
            if not root_found:
                result.status = CheckResult.STATUS_FAIL
                result.status_extended = "Root account not found in credential report"
                return [result]
            
            # Get account ID for resource ARN if not already set
            if not result.resource_arn:
                sts_service = service_factory.get_service('sts')
                identity_response = sts_service.get_caller_identity()
                if identity_response['success']:
                    result.resource_arn = f"arn:aws:iam::{identity_response['account_id']}:root"
            
            return [result]
            
        except csv.Error as e:
            result.status = CheckResult.STATUS_ERROR
            result.status_extended = f"Error parsing credential report: {str(e)}"
            return [result]
            
    except Exception as e:
        logger.error(f"Error executing CIS 1.4 check: {str(e)}")
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
        return [result]
