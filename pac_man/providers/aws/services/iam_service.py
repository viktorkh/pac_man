"""IAM service abstraction."""

from typing import Dict, List, Optional, Any, Tuple
from .base import AWSServiceBase

class IAMService(AWSServiceBase):
    """Service class for AWS IAM operations."""
    
    def __init__(self, session, region_name=None):
        """Initialize IAM service."""
        super().__init__(session, region_name)
        self.client = self._get_client('iam')
    
    def get_credential_report(self) -> Dict[str, Any]:
        """
        Generate and get IAM credential report.
        
        Returns:
            Dict containing the credential report or error information
        """
        try:
            # Generate report
            self.client.generate_credential_report()
            
            # Get the generated report
            response = self.client.get_credential_report()
            return {
                'success': True,
                'content': response['Content'],
                'report_format': response['ReportFormat'],
                'generation_time': response['GeneratedTime']
            }
        except Exception as e:
            return self._handle_error(e, 'get_credential_report')
    
    def get_account_password_policy(self) -> Dict[str, Any]:
        """
        Get the account password policy settings.
        
        Returns:
            Dict containing the password policy or error information
        """
        try:
            response = self.client.get_account_password_policy()
            return {
                'success': True,
                'policy': response['PasswordPolicy']
            }
        except Exception as e:
            return self._handle_error(e, 'get_account_password_policy')
    
    def list_users(self) -> Dict[str, Any]:
        """
        List all IAM users in the account.
        
        Returns:
            Dict containing the list of users or error information
        """
        try:
            users = []
            paginator = self.client.get_paginator('list_users')
            
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            return {
                'success': True,
                'users': users
            }
        except Exception as e:
            return self._handle_error(e, 'list_users')
    
    def list_access_keys(self, user_name: str) -> Dict[str, Any]:
        """
        List access keys for a specific IAM user.
        
        Args:
            user_name: Name of the IAM user
            
        Returns:
            Dict containing the list of access keys or error information
        """
        try:
            response = self.client.list_access_keys(UserName=user_name)
            return {
                'success': True,
                'access_keys': response['AccessKeyMetadata']
            }
        except Exception as e:
            return self._handle_error(e, f'list_access_keys for user {user_name}')
    
    def list_attached_user_policies(self, user_name: str) -> Dict[str, Any]:
        """
        List policies attached to a specific IAM user.
        
        Args:
            user_name: Name of the IAM user
            
        Returns:
            Dict containing the list of attached policies or error information
        """
        try:
            policies = []
            paginator = self.client.get_paginator('list_attached_user_policies')
            
            for page in paginator.paginate(UserName=user_name):
                policies.extend(page['AttachedPolicies'])
            
            return {
                'success': True,
                'attached_policies': policies
            }
        except Exception as e:
            return self._handle_error(e, f'list_attached_user_policies for user {user_name}')
    
    def list_policies(self, only_attached: bool = True) -> Dict[str, Any]:
        """
        List IAM policies.
        
        Args:
            only_attached: If True, lists only attached policies
            
        Returns:
            Dict containing the list of policies or error information
        """
        try:
            policies = []
            paginator = self.client.get_paginator('list_policies')
            
            for page in paginator.paginate(OnlyAttached=only_attached):
                policies.extend(page['Policies'])
            
            return {
                'success': True,
                'policies': policies
            }
        except Exception as e:
            return self._handle_error(e, 'list_policies')
    
    def get_policy(self, policy_arn: str) -> Dict[str, Any]:
        """
        Get details about an IAM policy.
        
        Args:
            policy_arn: ARN of the IAM policy
            
        Returns:
            Dict containing the policy details or error information
        """
        try:
            response = self.client.get_policy(PolicyArn=policy_arn)
            return {
                'success': True,
                'policy': response['Policy']
            }
        except Exception as e:
            return self._handle_error(e, f'get_policy for {policy_arn}')
    
    def get_policy_version(self, policy_arn: str, version_id: str) -> Dict[str, Any]:
        """
        Get the specified version of the specified managed policy.
        
        Args:
            policy_arn: ARN of the IAM policy
            version_id: Version of the policy to get
            
        Returns:
            Dict containing the policy version or error information
        """
        try:
            response = self.client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            return {
                'success': True,
                'policy_version': response['PolicyVersion']
            }
        except Exception as e:
            return self._handle_error(e, f'get_policy_version for policy {policy_arn}')
    
    def list_entities_for_policy(self, policy_arn: str) -> Dict[str, Any]:
        """
        List all entities (users, groups, roles) that a policy is attached to.
        
        Args:
            policy_arn: ARN of the IAM policy
            
        Returns:
            Dict containing the list of entities or error information
        """
        try:
            response = self.client.list_entities_for_policy(PolicyArn=policy_arn)
            return {
                'success': True,
                'policy_groups': response.get('PolicyGroups', []),
                'policy_users': response.get('PolicyUsers', []),
                'policy_roles': response.get('PolicyRoles', [])
            }
        except Exception as e:
            return self._handle_error(e, f'list_entities_for_policy for {policy_arn}')
    
    def detach_role_policy(self, role_name: str, policy_arn: str) -> Dict[str, Any]:
        """
        Detach an IAM policy from a role.
        
        Args:
            role_name: Name of the IAM role
            policy_arn: ARN of the policy to detach
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            return {
                'success': True,
                'message': f'Successfully detached policy from role {role_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'detach_role_policy for role {role_name}')
    
    def detach_user_policy(self, user_name: str, policy_arn: str) -> Dict[str, Any]:
        """
        Detach an IAM policy from a user.
        
        Args:
            user_name: Name of the IAM user
            policy_arn: ARN of the policy to detach
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            return {
                'success': True,
                'message': f'Successfully detached policy from user {user_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'detach_user_policy for user {user_name}')
    
    def detach_group_policy(self, group_name: str, policy_arn: str) -> Dict[str, Any]:
        """
        Detach an IAM policy from a group.
        
        Args:
            group_name: Name of the IAM group
            policy_arn: ARN of the policy to detach
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
            return {
                'success': True,
                'message': f'Successfully detached policy from group {group_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'detach_group_policy for group {group_name}')
    
    def update_account_password_policy(self, policy_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update the account password policy.
        
        Args:
            policy_config: Dictionary containing password policy configuration
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.update_account_password_policy(**policy_config)
            return {
                'success': True,
                'message': 'Password policy updated successfully'
            }
        except Exception as e:
            return self._handle_error(e, 'update_account_password_policy')
    
    def delete_access_key(self, user_name: str, access_key_id: str) -> Dict[str, Any]:
        """
        Delete an IAM access key.
        
        Args:
            user_name: Name of the IAM user
            access_key_id: ID of the access key to delete
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.delete_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id
            )
            return {
                'success': True,
                'message': f'Access key {access_key_id} deleted successfully'
            }
        except Exception as e:
            return self._handle_error(e, f'delete_access_key for user {user_name}')

    def update_access_key(self, user_name: str, access_key_id: str, status: str) -> Dict[str, Any]:
        """
        Update the status of an IAM access key.
        
        Args:
            user_name: Name of the IAM user
            access_key_id: ID of the access key to update
            status: New status for the access key ('Active' or 'Inactive')
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status=status
            )
            return {
                'success': True,
                'message': f'Access key {access_key_id} status updated to {status}'
            }
        except Exception as e:
            return self._handle_error(e, f'update_access_key for user {user_name}')

    def create_access_key(self, user_name: str) -> Dict[str, Any]:
        """
        Create a new access key for an IAM user.
        
        Args:
            user_name: Name of the IAM user
            
        Returns:
            Dict containing the new access key information or error information
        """
        try:
            response = self.client.create_access_key(UserName=user_name)
            return {
                'success': True,
                'access_key': response['AccessKey']
            }
        except Exception as e:
            return self._handle_error(e, f'create_access_key for user {user_name}')
