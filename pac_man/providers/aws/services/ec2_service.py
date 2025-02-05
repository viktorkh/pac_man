"""EC2 service abstraction."""

from typing import Any, Dict, List
from .base import AWSServiceBase

class EC2Service(AWSServiceBase):
    """Service class for AWS EC2 operations."""
    
    def __init__(self, session, region_name=None):
        """
        Initialize EC2 service.
        
        Args:
            session: Boto3 session
            region_name: Optional region name override
        """
        super().__init__(session, region_name)
        self.client = self._get_client('ec2')
    
    def list_active_regions(self) -> Dict[str, Any]:
        """
        List all active AWS regions.
        
        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - regions (List[str]): List of active region names if successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            # Get all regions including opt-in regions
            response = self.client.describe_regions(AllRegions=True)
            
            # Filter for active regions (opt-in-not-required or opted-in)
            active_regions = [
                region['RegionName']
                for region in response['Regions']
                if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']
            ]
            
            # Sort regions for consistent ordering
            active_regions.sort()
            
            return {
                'success': True,
                'regions': active_regions
            }
            
        except Exception as e:
            return self._handle_error(e, 'list_active_regions')
