"""Unit tests for IAM service."""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from providers.aws.services.iam_service import IAMService

@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
    return session

@pytest.fixture
def iam_service(mock_session):
    """Create an IAMService instance with a mock session."""
    return IAMService(mock_session)

@pytest.fixture
def mock_client(iam_service):
    """Get the mock IAM client from the service."""
    return iam_service.client

def test_init(mock_session):
    """Test IAMService initialization."""
    service = IAMService(mock_session)
    mock_session.client.assert_called_once_with('iam', region_name=None)
    assert service.client == mock_session.client.return_value

class TestGetCredentialReport:
    """Tests for get_credential_report method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful credential report generation and retrieval."""
        mock_response = {
            'Content': b'test-content',
            'ReportFormat': 'text/csv',
            'GeneratedTime': '2023-01-01T00:00:00Z'
        }
        mock_client.get_credential_report.return_value = mock_response
        
        result = iam_service.get_credential_report()
        
        mock_client.generate_credential_report.assert_called_once()
        mock_client.get_credential_report.assert_called_once()
        assert result['success'] is True
        assert result['content'] == b'test-content'
        assert result['report_format'] == 'text/csv'
        assert result['generation_time'] == '2023-01-01T00:00:00Z'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in credential report generation."""
        error_response = {
            'Error': {
                'Code': 'TestError',
                'Message': 'Test error message'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.generate_credential_report.side_effect = ClientError(
            error_response, 'GenerateCredentialReport'
        )
        
        result = iam_service.get_credential_report()
        
        assert result['success'] is False
        assert result['error_code'] == 'TestError'
        assert result['operation'] == 'get_credential_report'

class TestGetAccountPasswordPolicy:
    """Tests for get_account_password_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful password policy retrieval."""
        mock_response = {
            'PasswordPolicy': {
                'MinimumPasswordLength': 14,
                'RequireSymbols': True
            }
        }
        mock_client.get_account_password_policy.return_value = mock_response
        
        result = iam_service.get_account_password_policy()
        
        mock_client.get_account_password_policy.assert_called_once()
        assert result['success'] is True
        assert result['policy'] == mock_response['PasswordPolicy']
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in password policy retrieval."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Policy not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_account_password_policy.side_effect = ClientError(
            error_response, 'GetAccountPasswordPolicy'
        )
        
        result = iam_service.get_account_password_policy()
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'get_account_password_policy'

class TestListUsers:
    """Tests for list_users method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful user listing."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'Users': [{'UserName': 'user1'}, {'UserName': 'user2'}]},
            {'Users': [{'UserName': 'user3'}]}
        ]
        mock_client.get_paginator.return_value = mock_paginator
        
        result = iam_service.list_users()
        
        mock_client.get_paginator.assert_called_once_with('list_users')
        assert result['success'] is True
        assert len(result['users']) == 3
        assert result['users'][0]['UserName'] == 'user1'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in user listing."""
        error_response = {
            'Error': {
                'Code': 'ServiceError',
                'Message': 'Internal error'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 500
            }
        }
        mock_client.get_paginator.side_effect = ClientError(
            error_response, 'ListUsers'
        )
        
        result = iam_service.list_users()
        
        assert result['success'] is False
        assert result['error_code'] == 'ServiceError'
        assert result['operation'] == 'list_users'

class TestListAccessKeys:
    """Tests for list_access_keys method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful access key listing."""
        mock_response = {
            'AccessKeyMetadata': [
                {'AccessKeyId': 'AKIA123456789'},
                {'AccessKeyId': 'AKIA987654321'}
            ]
        }
        mock_client.list_access_keys.return_value = mock_response
        
        result = iam_service.list_access_keys('testuser')
        
        mock_client.list_access_keys.assert_called_once_with(UserName='testuser')
        assert result['success'] is True
        assert len(result['access_keys']) == 2
        assert result['access_keys'][0]['AccessKeyId'] == 'AKIA123456789'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in access key listing."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'User not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.list_access_keys.side_effect = ClientError(
            error_response, 'ListAccessKeys'
        )
        
        result = iam_service.list_access_keys('testuser')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'list_access_keys for user testuser'

class TestListAttachedUserPolicies:
    """Tests for list_attached_user_policies method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy listing."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'AttachedPolicies': [{'PolicyName': 'policy1'}, {'PolicyName': 'policy2'}]},
            {'AttachedPolicies': [{'PolicyName': 'policy3'}]}
        ]
        mock_client.get_paginator.return_value = mock_paginator
        
        result = iam_service.list_attached_user_policies('testuser')
        
        mock_client.get_paginator.assert_called_once_with('list_attached_user_policies')
        assert result['success'] is True
        assert len(result['attached_policies']) == 3
        assert result['attached_policies'][0]['PolicyName'] == 'policy1'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy listing."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'User not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_paginator.side_effect = ClientError(
            error_response, 'ListAttachedUserPolicies'
        )
        
        result = iam_service.list_attached_user_policies('testuser')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'list_attached_user_policies for user testuser'

class TestListPolicies:
    """Tests for list_policies method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy listing."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'Policies': [{'PolicyName': 'policy1', 'Arn': 'arn1'}, {'PolicyName': 'policy2', 'Arn': 'arn2'}]},
            {'Policies': [{'PolicyName': 'policy3', 'Arn': 'arn3'}]}
        ]
        mock_client.get_paginator.return_value = mock_paginator
        
        result = iam_service.list_policies(only_attached=True)
        
        mock_client.get_paginator.assert_called_once_with('list_policies')
        mock_paginator.paginate.assert_called_once_with(OnlyAttached=True)
        assert result['success'] is True
        assert len(result['policies']) == 3
        assert result['policies'][0]['PolicyName'] == 'policy1'
        assert result['policies'][0]['Arn'] == 'arn1'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy listing."""
        error_response = {
            'Error': {
                'Code': 'ServiceError',
                'Message': 'Internal error'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 500
            }
        }
        mock_client.get_paginator.side_effect = ClientError(
            error_response, 'ListPolicies'
        )
        
        result = iam_service.list_policies()
        
        assert result['success'] is False
        assert result['error_code'] == 'ServiceError'
        assert result['operation'] == 'list_policies'

class TestGetPolicy:
    """Tests for get_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy retrieval."""
        mock_response = {
            'Policy': {
                'PolicyName': 'test-policy',
                'Arn': 'arn:aws:iam::policy',
                'DefaultVersionId': 'v1'
            }
        }
        mock_client.get_policy.return_value = mock_response
        
        result = iam_service.get_policy('arn:aws:iam::policy')
        
        mock_client.get_policy.assert_called_once_with(PolicyArn='arn:aws:iam::policy')
        assert result['success'] is True
        assert result['policy'] == mock_response['Policy']
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy retrieval."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Policy not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_policy.side_effect = ClientError(
            error_response, 'GetPolicy'
        )
        
        result = iam_service.get_policy('arn:aws:iam::policy')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'get_policy for arn:aws:iam::policy'

class TestGetPolicyVersion:
    """Tests for get_policy_version method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy version retrieval."""
        mock_response = {
            'PolicyVersion': {
                'Document': {'Version': '2012-10-17'},
                'VersionId': 'v1'
            }
        }
        mock_client.get_policy_version.return_value = mock_response
        
        result = iam_service.get_policy_version('arn:aws:iam::policy', 'v1')
        
        mock_client.get_policy_version.assert_called_once_with(
            PolicyArn='arn:aws:iam::policy',
            VersionId='v1'
        )
        assert result['success'] is True
        assert result['policy_version'] == mock_response['PolicyVersion']
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy version retrieval."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Policy not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.get_policy_version.side_effect = ClientError(
            error_response, 'GetPolicyVersion'
        )
        
        result = iam_service.get_policy_version('arn:aws:iam::policy', 'v1')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'get_policy_version for policy arn:aws:iam::policy'

class TestListEntitiesForPolicy:
    """Tests for list_entities_for_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy entities listing."""
        mock_response = {
            'PolicyGroups': [{'GroupName': 'group1'}],
            'PolicyUsers': [{'UserName': 'user1'}],
            'PolicyRoles': [{'RoleName': 'role1'}]
        }
        mock_client.list_entities_for_policy.return_value = mock_response
        
        result = iam_service.list_entities_for_policy('arn:aws:iam::policy')
        
        mock_client.list_entities_for_policy.assert_called_once_with(PolicyArn='arn:aws:iam::policy')
        assert result['success'] is True
        assert len(result['policy_groups']) == 1
        assert len(result['policy_users']) == 1
        assert len(result['policy_roles']) == 1
        assert result['policy_groups'][0]['GroupName'] == 'group1'
        assert result['policy_users'][0]['UserName'] == 'user1'
        assert result['policy_roles'][0]['RoleName'] == 'role1'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy entities listing."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Policy not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.list_entities_for_policy.side_effect = ClientError(
            error_response, 'ListEntitiesForPolicy'
        )
        
        result = iam_service.list_entities_for_policy('arn:aws:iam::policy')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'list_entities_for_policy for arn:aws:iam::policy'

class TestDetachRolePolicy:
    """Tests for detach_role_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy detachment from role."""
        result = iam_service.detach_role_policy('test-role', 'arn:aws:iam::policy')
        
        mock_client.detach_role_policy.assert_called_once_with(
            RoleName='test-role',
            PolicyArn='arn:aws:iam::policy'
        )
        assert result['success'] is True
        assert result['message'] == 'Successfully detached policy from role test-role'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy detachment from role."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Role not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.detach_role_policy.side_effect = ClientError(
            error_response, 'DetachRolePolicy'
        )
        
        result = iam_service.detach_role_policy('test-role', 'arn:aws:iam::policy')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'detach_role_policy for role test-role'

class TestDetachUserPolicy:
    """Tests for detach_user_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy detachment from user."""
        result = iam_service.detach_user_policy('test-user', 'arn:aws:iam::policy')
        
        mock_client.detach_user_policy.assert_called_once_with(
            UserName='test-user',
            PolicyArn='arn:aws:iam::policy'
        )
        assert result['success'] is True
        assert result['message'] == 'Successfully detached policy from user test-user'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy detachment from user."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'User not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.detach_user_policy.side_effect = ClientError(
            error_response, 'DetachUserPolicy'
        )
        
        result = iam_service.detach_user_policy('test-user', 'arn:aws:iam::policy')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'detach_user_policy for user test-user'

class TestDetachGroupPolicy:
    """Tests for detach_group_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful policy detachment from group."""
        result = iam_service.detach_group_policy('test-group', 'arn:aws:iam::policy')
        
        mock_client.detach_group_policy.assert_called_once_with(
            GroupName='test-group',
            PolicyArn='arn:aws:iam::policy'
        )
        assert result['success'] is True
        assert result['message'] == 'Successfully detached policy from group test-group'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in policy detachment from group."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Group not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.detach_group_policy.side_effect = ClientError(
            error_response, 'DetachGroupPolicy'
        )
        
        result = iam_service.detach_group_policy('test-group', 'arn:aws:iam::policy')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'detach_group_policy for group test-group'

class TestUpdateAccountPasswordPolicy:
    """Tests for update_account_password_policy method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful password policy update."""
        policy_config = {
            'MinimumPasswordLength': 14,
            'RequireSymbols': True
        }
        
        result = iam_service.update_account_password_policy(policy_config)
        
        mock_client.update_account_password_policy.assert_called_once_with(**policy_config)
        assert result['success'] is True
        assert result['message'] == 'Password policy updated successfully'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in password policy update."""
        error_response = {
            'Error': {
                'Code': 'ValidationError',
                'Message': 'Invalid policy configuration'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 400
            }
        }
        mock_client.update_account_password_policy.side_effect = ClientError(
            error_response, 'UpdateAccountPasswordPolicy'
        )
        
        result = iam_service.update_account_password_policy({})
        
        assert result['success'] is False
        assert result['error_code'] == 'ValidationError'
        assert result['operation'] == 'update_account_password_policy'

class TestDeleteAccessKey:
    """Tests for delete_access_key method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful access key deletion."""
        result = iam_service.delete_access_key('testuser', 'AKIA123456789')
        
        mock_client.delete_access_key.assert_called_once_with(
            UserName='testuser',
            AccessKeyId='AKIA123456789'
        )
        assert result['success'] is True
        assert result['message'] == 'Access key AKIA123456789 deleted successfully'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in access key deletion."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Access key not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.delete_access_key.side_effect = ClientError(
            error_response, 'DeleteAccessKey'
        )
        
        result = iam_service.delete_access_key('testuser', 'AKIA123456789')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'delete_access_key for user testuser'

class TestUpdateAccessKey:
    """Tests for update_access_key method."""
    
    def test_success(self, iam_service, mock_client):
        """Test successful access key status update."""
        result = iam_service.update_access_key('testuser', 'AKIA123456789', 'Inactive')
        
        mock_client.update_access_key.assert_called_once_with(
            UserName='testuser',
            AccessKeyId='AKIA123456789',
            Status='Inactive'
        )
        assert result['success'] is True
        assert result['message'] == 'Access key AKIA123456789 status updated to Inactive'
    
    def test_error(self, iam_service, mock_client):
        """Test error handling in access key status update."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'Access key not found'
            },
            'ResponseMetadata': {
                'RequestId': '1234567890',
                'HTTPStatusCode': 404
            }
        }
        mock_client.update_access_key.side_effect = ClientError(
            error_response, 'UpdateAccessKey'
        )
        
        result = iam_service.update_access_key('testuser', 'AKIA123456789', 'Inactive')
        
        assert result['success'] is False
        assert result['error_code'] == 'NoSuchEntity'
        assert result['operation'] == 'update_access_key for user testuser'
