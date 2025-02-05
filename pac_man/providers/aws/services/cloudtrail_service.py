"""CloudTrail service abstraction."""

from typing import Dict, List, Optional, Any
from .base import AWSServiceBase

class CloudTrailService(AWSServiceBase):
    """Service class for AWS CloudTrail operations."""
    
    def __init__(self, session, region_name=None):
        """Initialize CloudTrail service."""
        super().__init__(session, region_name)
        self.client = self._get_client('cloudtrail')
    
    def describe_trails(self, include_shadow_trails: bool = False) -> Dict[str, Any]:
        """
        Get a list of trails in the current region.
        
        Args:
            include_shadow_trails: Include replicated trails from other regions
            
        Returns:
            Dict containing the list of trails or error information
        """
        try:
            response = self.client.describe_trails(
                includeShadowTrails=include_shadow_trails
            )
            return {
                'success': True,
                'trails': response['trailList']
            }
        except Exception as e:
            return self._handle_error(e, 'describe_trails')
    
    def get_trail_status(self, trail_name: str) -> Dict[str, Any]:
        """
        Get the status of a specific trail.
        
        Args:
            trail_name: Name or ARN of the trail
            
        Returns:
            Dict containing the trail status or error information
        """
        try:
            response = self.client.get_trail_status(Name=trail_name)
            return {
                'success': True,
                'status': {
                    'is_logging': response['IsLogging'],
                    'latest_delivery_time': response.get('LatestDeliveryTime'),
                    'latest_delivery_error': response.get('LatestDeliveryError'),
                    'start_logging_time': response.get('StartLoggingTime'),
                    'stop_logging_time': response.get('StopLoggingTime'),
                    'latest_notification_time': response.get('LatestNotificationTime'),
                    'latest_notification_error': response.get('LatestNotificationError')
                }
            }
        except Exception as e:
            return self._handle_error(e, f'get_trail_status for trail {trail_name}')
    
    def get_event_selectors(self, trail_name: str) -> Dict[str, Any]:
        """
        Get the event selectors for a trail.
        
        Args:
            trail_name: Name or ARN of the trail
            
        Returns:
            Dict containing the event selectors or error information
        """
        try:
            response = self.client.get_event_selectors(TrailName=trail_name)
            return {
                'success': True,
                'event_selectors': response['EventSelectors'],
                'advanced_event_selectors': response.get('AdvancedEventSelectors', [])
            }
        except Exception as e:
            return self._handle_error(e, f'get_event_selectors for trail {trail_name}')
    
    def create_trail(self, trail_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new CloudTrail trail.
        
        Args:
            trail_config: Dictionary containing trail configuration
            
        Returns:
            Dict containing the created trail information or error information
        """
        try:
            response = self.client.create_trail(**trail_config)
            return {
                'success': True,
                'trail': response
            }
        except Exception as e:
            return self._handle_error(e, 'create_trail')
    
    def update_trail(self, trail_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing CloudTrail trail.
        
        Args:
            trail_config: Dictionary containing trail configuration updates
            
        Returns:
            Dict containing the updated trail information or error information
        """
        try:
            response = self.client.update_trail(**trail_config)
            return {
                'success': True,
                'trail': response
            }
        except Exception as e:
            return self._handle_error(e, f'update_trail for trail {trail_config.get("Name")}')
    
    def start_logging(self, trail_name: str) -> Dict[str, Any]:
        """
        Start logging for a trail.
        
        Args:
            trail_name: Name or ARN of the trail
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.start_logging(Name=trail_name)
            return {
                'success': True,
                'message': f'Logging started for trail {trail_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'start_logging for trail {trail_name}')
    
    def stop_logging(self, trail_name: str) -> Dict[str, Any]:
        """
        Stop logging for a trail.
        
        Args:
            trail_name: Name or ARN of the trail
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.stop_logging(Name=trail_name)
            return {
                'success': True,
                'message': f'Logging stopped for trail {trail_name}'
            }
        except Exception as e:
            return self._handle_error(e, f'stop_logging for trail {trail_name}')
    
    def put_event_selectors(self, trail_name: str, event_selectors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Configure event selectors for a trail.
        
        Args:
            trail_name: Name or ARN of the trail
            event_selectors: List of event selector configurations
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            response = self.client.put_event_selectors(
                TrailName=trail_name,
                EventSelectors=event_selectors
            )
            return {
                'success': True,
                'event_selectors': response['EventSelectors']
            }
        except Exception as e:
            return self._handle_error(e, f'put_event_selectors for trail {trail_name}')
