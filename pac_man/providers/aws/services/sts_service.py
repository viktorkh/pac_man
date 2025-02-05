"""STS (Security Token Service) service abstraction."""

from typing import Dict, Any
from .base import AWSServiceBase

class STSService(AWSServiceBase):
    """Service class for AWS STS operations."""
    
    def __init__(self, session, region_name=None):
        """Initialize STS service."""
        super().__init__(session, region_name)
        self.client = self._get_client('sts')
    
    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Get the caller identity information.
        
        Returns:
            Dict containing the caller identity information or error information
        """
        try:
            response = self.client.get_caller_identity()
            return {
                'success': True,
                'account_id': response['Account'],
                'arn': response['Arn'],
                'user_id': response['UserId']
            }
        except Exception as e:
            return self._handle_error(e, 'get_caller_identity')
