"""Base class for AWS service abstractions."""

from typing import Any, Dict
import boto3
import logging
from botocore.exceptions import ClientError

class AWSServiceBase:
    """Base class for AWS service clients."""
    
    def __init__(self, session: boto3.Session, region_name: str = None):
        """
        Initialize the AWS service base.
        
        Args:
            session: Boto3 session to use for creating clients
            region_name: Optional region name to override session default
        """
        self.session = session
        self.region_name = region_name
        self.logger = logging.getLogger(__name__)
    
    def _get_client(self, service_name: str) -> Any:
        """
        Get a boto3 client for the specified service.
        
        Args:
            service_name: Name of the AWS service
            
        Returns:
            boto3.client: Boto3 client for the service
        """
        try:
            return self.session.client(service_name, region_name=self.region_name)
        except Exception as e:
            self.logger.error(f"Error creating {service_name} client: {str(e)}")
            raise
    
    def _handle_error(self, error: Exception, operation: str) -> Dict[str, Any]:
        """
        Handle AWS service errors in a consistent way.
        
        Args:
            error: The caught exception
            operation: Name of the operation that failed
            
        Returns:
            Dict containing error details
        """
        error_info = {
            'success': False,
            'operation': operation,
            'error_type': type(error).__name__,
            'error_message': str(error)
        }
        
        if isinstance(error, ClientError):
            error_info.update({
                'error_code': error.response['Error']['Code'],
                'request_id': error.response['ResponseMetadata'].get('RequestId'),
                'http_status': error.response['ResponseMetadata'].get('HTTPStatusCode')
            })
        
        self.logger.error(f"AWS operation '{operation}' failed: {error_info}")
        return error_info
