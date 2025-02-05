"""CIS 1.16 - Ensure IAM policies that allow full '*:*' administrative privileges are not attached."""

from typing import List
from providers.aws.lib.check_result import CheckResult
from providers.aws.lib.whitelist import whitelist as default_whitelist

CHECK_ID = "cis_1_16"
CHECK_DESCRIPTION = "Ensure IAM policies that allow full '*:*' administrative privileges are not attached"

def execute(session, logger, service_factory, whitelist=None) -> List[CheckResult]:
    """
    Execute CIS 1.16 check.
    Check IAM policies for full administrative privileges.
    
    Args:
        session: boto3 session
        logger: logging object
        service_factory: AWS service factory instance
        whitelist: Optional whitelist instance for testing
        
    Returns:
        List[CheckResult]: List containing check results
    """
    # Initialize services using the factory
    iam_service = service_factory.get_service('iam')
    # Use provided whitelist or default
    whitelist_instance = whitelist or default_whitelist
    findings = []
    
    try:
        # Get list of attached policies
        policies_response = iam_service.list_policies(only_attached=True)
        if not policies_response['success']:
            logger.error(f"Error listing IAM policies: {policies_response.get('error_message')}")
            return [create_error_result(f"Error listing IAM policies: {policies_response.get('error_message')}")]
        
        policies = policies_response['policies']
        
        for policy in policies:
            policy_arn = policy['Arn']
            policy_name = policy['PolicyName']
            
            # Get policy details
            policy_response = iam_service.get_policy(policy_arn)
            if not policy_response['success']:
                logger.error(f"Error getting policy {policy_name}: {policy_response.get('error_message')}")
                return [create_error_result(f"Error getting policy {policy_name}: {policy_response.get('error_message')}")]
                
            policy_version = policy_response['policy']['DefaultVersionId']
            
            # Get policy version details
            version_response = iam_service.get_policy_version(policy_arn, policy_version)
            if not version_response['success']:
                logger.error(f"Error getting policy version for {policy_name}: {version_response.get('error_message')}")
                return [create_error_result(f"Error getting policy version for {policy_name}: {version_response.get('error_message')}")]
                
            policy_document = version_response['policy_version']['Document']
            
            # Initialize check result
            report = CheckResult()
            report.check_id = CHECK_ID
            report.check_description = CHECK_DESCRIPTION
            report.resource_id = policy_name
            report.resource_arn = policy_arn
            report.region = 'global'
            
            # Get policy attachments to check if any attached roles are whitelisted
            entities_response = iam_service.list_entities_for_policy(policy_arn)
            if not entities_response['success']:
                logger.error(f"Error getting policy entities for {policy_name}: {entities_response.get('error_message')}")
                return [create_error_result(f"Error getting policy entities for {policy_name}: {entities_response.get('error_message')}")]
                
            whitelisted_roles = []
            
            # Check if any attached roles are whitelisted
            for role in entities_response.get('policy_roles', []):
                role_name = role['RoleName']
                if whitelist_instance:  # Check if whitelist instance exists
                    mute_reason = whitelist_instance.is_whitelisted(CHECK_ID, 'roles', role_name)
                    if mute_reason:
                        whitelisted_roles.append(role_name)
            
            # Check policy statements for full admin privileges
            for statement in policy_document['Statement']:
                if (
                    statement['Effect'] == 'Allow' and
                    statement.get('Action') == '*' and
                    statement.get('Resource') == '*'
                ):
                    if whitelisted_roles:
                        # If any attached roles are whitelisted, mark as MUTED
                        report.status = "MUTED"
                        report.mute_reason = f"Policy is attached to whitelisted roles: {', '.join(whitelisted_roles)}"
                        report.status_extended = f"Policy '{policy_name}' allows full administrative privileges but is attached to whitelisted roles."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Policy '{policy_name}' allows full administrative privileges."
                        logger.warning(f"Policy '{policy_name}' ({policy_arn}) allows full administrative privileges.")
                    break
            else:
                report.status = "PASS"
                report.status_extended = f"Policy '{policy_name}' does not allow full administrative privileges."
                logger.info(f"Policy '{policy_name}' ({policy_arn}) does not allow full administrative privileges.")
            
            findings.append(report)
        
        return findings
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.16 check: {str(e)}")
        return [create_error_result(f"Error executing check: {str(e)}")]

def create_error_result(error_message: str) -> CheckResult:
    """Create an error check result."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.status = "ERROR"
    result.status_extended = error_message
    result.region = 'global'
    return result
