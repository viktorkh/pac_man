"""S3 service abstraction."""

from typing import Dict, List, Optional, Any
from .base import AWSServiceBase

class S3Service(AWSServiceBase):
    """Service class for AWS S3 operations."""
    
    def __init__(self, session, region_name=None):
        """Initialize S3 service."""
        super().__init__(session, region_name)
        self.client = self._get_client('s3')
    
    def list_buckets(self) -> Dict[str, Any]:
        """
        List all S3 buckets in the account.
        
        Returns:
            Dict containing the list of buckets or error information
        """
        try:
            response = self.client.list_buckets()
            return {
                'success': True,
                'buckets': response['Buckets'],
                'owner': response['Owner']
            }
        except Exception as e:
            return self._handle_error(e, 'list_buckets')
    
    def get_bucket_location(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get the region where a bucket is located.
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Dict containing the bucket location or error information
        """
        try:
            response = self.client.get_bucket_location(Bucket=bucket_name)
            # Convert None to 'us-east-1' as per AWS behavior
            location = response.get('LocationConstraint') or 'us-east-1'
            return {
                'success': True,
                'location': location
            }
        except Exception as e:
            return self._handle_error(e, f'get_bucket_location for bucket {bucket_name}')
    
    def get_bucket_encryption(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get the encryption configuration for a bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Dict containing the bucket encryption configuration or error information
        """
        try:
            response = self.client.get_bucket_encryption(Bucket=bucket_name)
            return {
                'success': True,
                'encryption': response['ServerSideEncryptionConfiguration']
            }
        except Exception as e:
            return self._handle_error(e, f'get_bucket_encryption for bucket {bucket_name}')
    
    def get_bucket_versioning(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get the versioning configuration for a bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Dict containing the bucket versioning configuration or error information
        """
        try:
            response = self.client.get_bucket_versioning(Bucket=bucket_name)
            return {
                'success': True,
                'versioning': response.get('Status', 'Disabled'),
                'mfa_delete': response.get('MFADelete', 'Disabled')
            }
        except Exception as e:
            return self._handle_error(e, f'get_bucket_versioning for bucket {bucket_name}')
    
    def put_bucket_encryption(self, bucket_name: str, encryption_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set the encryption configuration for a bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            encryption_config: Dictionary containing encryption configuration
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration=encryption_config
            )
            return {
                'success': True,
                'message': f'Encryption configured successfully for bucket {bucket_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'put_bucket_encryption for bucket {bucket_name}')
    
    def put_bucket_versioning(self, bucket_name: str, status: str, mfa_delete: str = None, mfa: str = None) -> Dict[str, Any]:
        """
        Set the versioning configuration for a bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            status: Versioning status ('Enabled' or 'Suspended')
            mfa_delete: MFA delete status ('Enabled' or 'Disabled')
            mfa: MFA authentication code (required if mfa_delete is specified)
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            config = {
                'Bucket': bucket_name,
                'VersioningConfiguration': {
                    'Status': status
                }
            }
            
            if mfa_delete:
                config['VersioningConfiguration']['MFADelete'] = mfa_delete
                if mfa:
                    config['MFA'] = mfa
            
            self.client.put_bucket_versioning(**config)
            return {
                'success': True,
                'message': f'Versioning configured successfully for bucket {bucket_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'put_bucket_versioning for bucket {bucket_name}')
    
    def get_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get the bucket policy.
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Dict containing the bucket policy or error information
        """
        try:
            response = self.client.get_bucket_policy(Bucket=bucket_name)
            return {
                'success': True,
                'policy': response['Policy']
            }
        except Exception as e:
            return self._handle_error(e, f'get_bucket_policy for bucket {bucket_name}')

    def get_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get the public access block configuration for a bucket.

        Args:
            bucket_name (str): The name of the bucket.

        Returns:
            Dict[str, Any]: A dictionary containing the public access block configuration.
        """
        try:
            response = self.client.get_public_access_block(Bucket=bucket_name)
            return {
                'success': True,
                'PublicAccessBlockConfiguration': response['PublicAccessBlockConfiguration']
            }
        except self.client.exceptions.NoSuchPublicAccessBlockConfiguration:
            # If there's no public access block configuration, return an empty configuration
            return {
                'success': True,
                'PublicAccessBlockConfiguration': {
                    'BlockPublicAcls': False,
                    'IgnorePublicAcls': False,
                    'BlockPublicPolicy': False,
                    'RestrictPublicBuckets': False
                }
            }
        except Exception as e:
            return self._handle_error(e, f'get_public_access_block for bucket {bucket_name}')


    def put_public_access_block(self, bucket_name: str, block_public_acls: bool, ignore_public_acls: bool, block_public_policy: bool, restrict_public_buckets: bool) -> Dict[str, Any]:
        """
        Set the public access block configuration for a bucket.

        Args:
            bucket_name: Name of the S3 bucket
            block_public_acls: Block public ACLs
            ignore_public_acls: Ignore public ACLs
            block_public_policy: Block public bucket policies
            restrict_public_buckets: Restrict public bucket policies

        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': block_public_acls,
                    'IgnorePublicAcls': ignore_public_acls,
                    'BlockPublicPolicy': block_public_policy,
                    'RestrictPublicBuckets': restrict_public_buckets
                }
            )
            return {
                'success': True,
                'message': f'Public access block configuration updated successfully for bucket {bucket_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'put_public_access_block for bucket {bucket_name}')

    def get_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get the ACL configuration for a bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Dict containing the bucket ACL or error information
        """
        try:
            response = self.client.get_bucket_acl(Bucket=bucket_name)
            return {
                'success': True,
                'Grants': response.get('Grants', []),
                'Owner': response.get('Owner', {})
            }
        except Exception as e:
            return self._handle_error(e, f'get_bucket_acl for bucket {bucket_name}')
