"""CIS 1.16 Fix - Detach IAM policies that allow full '*:*' administrative privileges."""

from typing import Tuple, List
from providers.aws.lib.whitelist import whitelist

def detach_policy_from_entities(iam_service, policy_arn: str, logger) -> Tuple[bool, List[str]]:
    """
    Detach the specified policy from all associated entities (users, groups, roles).

    Args:
        iam_service: IAM service instance
        policy_arn: The ARN of the policy to detach
        logger: Logger object for logging messages

    Returns:
        tuple: (bool, list) - True if all detach operations were successful, False otherwise,
               and a list of failed detach operations.
               
    Required Permissions:
        - `iam:ListEntitiesForPolicy` to list users, groups, and roles associated with the policy.
        - `iam:DetachUserPolicy` to detach the policy from each user.
        - `iam:DetachGroupPolicy` to detach the policy from each group.
        - `iam:DetachRolePolicy` to detach the policy from each role.
    """
    entities_response = iam_service.list_entities_for_policy(policy_arn)
    if not entities_response['success']:
        logger.error(f"Failed to list entities for policy {policy_arn}: {entities_response.get('error_message')}")
        return False, [f"Failed to list entities for policy: {policy_arn}"]
    
    all_successful = True
    failed_detachments = []
    whitelisted_roles = []
    
    # Check for whitelisted roles first
    for role in entities_response.get('policy_roles', []):
        role_name = role['RoleName']
        if whitelist.is_whitelisted('cis_1_16', 'roles', role_name):
            whitelisted_roles.append(role_name)
            logger.info(f"Skipping whitelisted role: {role_name}")
            continue
        
        logger.info(f"Detaching policy from role: {role_name}")
        response = iam_service.detach_role_policy(role_name, policy_arn)
        if not response['success']:
            logger.error(f"Failed to detach policy from role {role_name}: {response.get('error_message')}")
            all_successful = False
            failed_detachments.append(f"Role: {role_name}")
    
    # Detach policy from each user
    for user in entities_response.get('policy_users', []):
        user_name = user['UserName']
        logger.info(f"Detaching policy from user: {user_name}")
        response = iam_service.detach_user_policy(user_name, policy_arn)
        if not response['success']:
            logger.error(f"Failed to detach policy from user {user_name}: {response.get('error_message')}")
            all_successful = False
            failed_detachments.append(f"User: {user_name}")
    
    # Detach policy from each group
    for group in entities_response.get('policy_groups', []):
        group_name = group['GroupName']
        logger.info(f"Detaching policy from group: {group_name}")
        response = iam_service.detach_group_policy(group_name, policy_arn)
        if not response['success']:
            logger.error(f"Failed to detach policy from group {group_name}: {response.get('error_message')}")
            all_successful = False
            failed_detachments.append(f"Group: {group_name}")
    
    if whitelisted_roles:
        # If there were whitelisted roles, add them to the failed_detachments with a special note
        failed_detachments.extend([f"Role: {role} (Whitelisted)" for role in whitelisted_roles])
        all_successful = False
    
    return all_successful, failed_detachments

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for CIS 1.16 (Ensure IAM policies that allow full "*:*" administrative privileges are not attached).

    Args:
        session: The boto3 session to use for making AWS API calls
        finding: The CheckResult object containing the finding details
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        CheckResult: The updated CheckResult object after attempting the fix.
        
    Required Permissions:
        - `iam:GetPolicy` to retrieve policy metadata
        - `iam:GetPolicyVersion` to get the document for the current version of the policy
        - `iam:DetachUserPolicy`, `iam:DetachGroupPolicy`, and `iam:DetachRolePolicy` to detach the policy
    """
    # If the finding is muted, skip the fix
    if finding.status == "MUTED":
        finding.status_extended = f"Fix skipped: {finding.mute_reason}"
        return finding

    logger.info(f"Executing fix for {finding.check_id}")

    try:
        # Initialize services using the factory
        iam_service = service_factory.get_service('iam')

        policy_arn = finding.resource_arn
        policy_name = finding.resource_id

        # Get the policy details
        policy_response = iam_service.get_policy(policy_arn)
        if not policy_response['success']:
            raise Exception(f"Failed to get policy details: {policy_response.get('error_message')}")
        
        policy_version = policy_response['policy']['DefaultVersionId']
        
        # Get the policy version details
        version_response = iam_service.get_policy_version(policy_arn, policy_version)
        if not version_response['success']:
            raise Exception(f"Failed to get policy version details: {version_response.get('error_message')}")
        
        policy_document = version_response['policy_version']['Document']

        # Check if the policy has full administrative privileges
        for statement in policy_document['Statement']:
            if (
                statement['Effect'] == 'Allow' and
                statement.get('Action') == '*' and
                statement.get('Resource') == '*'
            ):
                logger.warning(f"Policy '{policy_name}' ({policy_arn}) allows full administrative privileges.")
                logger.info(f"Detaching policy '{policy_name}' from all associated entities...")
                success, failed_detachments = detach_policy_from_entities(iam_service, policy_arn, logger)
                
                if success:
                    finding.status = "PASS"
                    finding.status_extended = f"Policy '{policy_name}' with full administrative privileges has been successfully detached from all entities."
                else:
                    finding.status = "FAIL"
                    failed_entities = ", ".join(failed_detachments)
                    finding.status_extended = f"Failed to detach policy '{policy_name}' from the following entities: {failed_entities}"
                break
        else:
            logger.info(f"Policy '{policy_name}' does not have full administrative privileges. No action needed.")
            finding.status = "PASS"
            finding.status_extended = f"Policy '{policy_name}' does not have full administrative privileges. No action was needed."

    except Exception as e:
        logger.error(f"An error occurred while fixing {finding.check_id}: {e}")
        finding.status = "FAIL"
        finding.status_extended = f"Fix attempt failed: {str(e)}"

    return finding
