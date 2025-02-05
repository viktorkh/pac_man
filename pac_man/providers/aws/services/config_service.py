"""AWS Config service abstraction."""

from typing import Dict, List, Optional, Any
from .base import AWSServiceBase

class ConfigService(AWSServiceBase):
    """Service class for AWS Config operations."""
    
    def __init__(self, session, region_name=None):
        """Initialize Config service."""
        super().__init__(session, region_name)
        self.client = self._get_client('config')
    
    def describe_configuration_recorders(self) -> Dict[str, Any]:
        """
        Get a list of configuration recorders.
        
        Returns:
            Dict containing the list of configuration recorders or error information
        """
        try:
            response = self.client.describe_configuration_recorders()
            return {
                'success': True,
                'configuration_recorders': response['ConfigurationRecorders']
            }
        except Exception as e:
            return self._handle_error(e, 'describe_configuration_recorders')
    
    def describe_configuration_recorder_status(self) -> Dict[str, Any]:
        """
        Get the status of configuration recorders.
        
        Returns:
            Dict containing the configuration recorder status or error information
        """
        try:
            response = self.client.describe_configuration_recorder_status()
            return {
                'success': True,
                'recorder_statuses': response['ConfigurationRecordersStatus']
            }
        except Exception as e:
            return self._handle_error(e, 'describe_configuration_recorder_status')
    
    def put_configuration_recorder(self, recorder_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a configuration recorder.
        
        Args:
            recorder_config: Dictionary containing configuration recorder settings
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.put_configuration_recorder(
                ConfigurationRecorder=recorder_config
            )
            return {
                'success': True,
                'message': f'Configuration recorder {recorder_config.get("name")} created/updated successfully'
            }
        except Exception as e:
            return self._handle_error(e, 'put_configuration_recorder')
    
    def start_configuration_recorder(self, recorder_name: str) -> Dict[str, Any]:
        """
        Start a configuration recorder.
        
        Args:
            recorder_name: Name of the configuration recorder
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.start_configuration_recorder(
                ConfigurationRecorderName=recorder_name
            )
            return {
                'success': True,
                'message': f'Configuration recorder {recorder_name} started successfully'
            }
        except Exception as e:
            return self._handle_error(e, f'start_configuration_recorder for recorder {recorder_name}')
    
    def stop_configuration_recorder(self, recorder_name: str) -> Dict[str, Any]:
        """
        Stop a configuration recorder.
        
        Args:
            recorder_name: Name of the configuration recorder
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.stop_configuration_recorder(
                ConfigurationRecorderName=recorder_name
            )
            return {
                'success': True,
                'message': f'Configuration recorder {recorder_name} stopped successfully'
            }
        except Exception as e:
            return self._handle_error(e, f'stop_configuration_recorder for recorder {recorder_name}')
    
    def put_delivery_channel(self, channel_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a delivery channel.
        
        Args:
            channel_config: Dictionary containing delivery channel configuration
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.put_delivery_channel(
                DeliveryChannel=channel_config
            )
            return {
                'success': True,
                'message': f'Delivery channel {channel_config.get("name")} created/updated successfully'
            }
        except Exception as e:
            return self._handle_error(e, 'put_delivery_channel')
    
    def describe_delivery_channels(self) -> Dict[str, Any]:
        """
        Get a list of delivery channels.
        
        Returns:
            Dict containing the list of delivery channels or error information
        """
        try:
            response = self.client.describe_delivery_channels()
            return {
                'success': True,
                'delivery_channels': response['DeliveryChannels']
            }
        except Exception as e:
            return self._handle_error(e, 'describe_delivery_channels')
    
    def describe_delivery_channel_status(self) -> Dict[str, Any]:
        """
        Get the status of delivery channels.
        
        Returns:
            Dict containing the delivery channel status or error information
        """
        try:
            response = self.client.describe_delivery_channel_status()
            return {
                'success': True,
                'delivery_channel_status': response['DeliveryChannelsStatus']
            }
        except Exception as e:
            return self._handle_error(e, 'describe_delivery_channel_status')
    
    def put_config_rule(self, rule_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a Config rule.
        
        Args:
            rule_config: Dictionary containing Config rule configuration
            
        Returns:
            Dict containing the operation result or error information
        """
        try:
            self.client.put_config_rule(
                ConfigRule=rule_config
            )
            return {
                'success': True,
                'message': f'Config rule {rule_config.get("ConfigRuleName")} created/updated successfully'
            }
        except Exception as e:
            return self._handle_error(e, 'put_config_rule')
