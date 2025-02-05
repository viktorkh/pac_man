import os
import yaml
import fnmatch
from typing import Dict, List, Optional, Any

class Whitelist:
    """
    Handles loading and checking of whitelisted resources for security checks.
    """

    def __init__(self, custom_whitelist_path: Optional[str] = None):
        """
        Initialize the whitelist handler.
        
        Args:
            custom_whitelist_path: Optional path to a custom whitelist YAML file.
                                 If not provided, the default whitelist will be used.
        """
        self._whitelist_data = {}
        self._load_whitelist(custom_whitelist_path)

    def _load_whitelist(self, custom_whitelist_path: Optional[str] = None) -> None:
        """
        Load whitelist configuration from the YAML file.
        
        Args:
            custom_whitelist_path: Optional path to a custom whitelist YAML file.
                                 If not provided, the default whitelist will be used.
        """
        if custom_whitelist_path:
            # Use custom whitelist if provided
            if not os.path.exists(custom_whitelist_path):
                raise FileNotFoundError(f"Custom whitelist file not found: {custom_whitelist_path}")
            whitelist_path = custom_whitelist_path
        else:
            # Use default whitelist
            whitelist_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'config',
                'aws_default_whitelist.yaml'
            )
            if not os.path.exists(whitelist_path):
                # If default whitelist doesn't exist, use empty whitelist
                self._whitelist_data = {}
                return

        try:
            with open(whitelist_path, 'r') as f:
                self._whitelist_data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing whitelist configuration: {str(e)}")

    def get_whitelist_config(self, check_id: str) -> Dict[str, Any]:
        """
        Get whitelist configuration for a specific check.
        
        Args:
            check_id: The ID of the check to get whitelist config for
            
        Returns:
            Dictionary containing whitelist configuration for the check
        """
        return self._whitelist_data.get(check_id, {})

    def is_whitelisted(self, check_id: str, resource_type: str, resource_name: str) -> Optional[str]:
        """
        Check if a resource is whitelisted for a specific check.
        
        Args:
            check_id: The ID of the check
            resource_type: Type of resource (roles, users, policies, etc.)
            resource_name: Name of the resource to check
            
        Returns:
            The reason for whitelisting if resource is whitelisted, None otherwise
        """
        check_config = self.get_whitelist_config(check_id)
        if not check_config:
            return None

        # Get list of whitelisted resources for the specified type
        whitelisted_resources = check_config.get(resource_type, [])
        
        # Check if resource matches any whitelisted pattern
        for pattern in whitelisted_resources:
            if fnmatch.fnmatch(resource_name, pattern):
                return check_config.get('reason', 'Resource is whitelisted')
                
        return None

    def get_whitelisted_resources(self, check_id: str, resource_type: str) -> List[str]:
        """
        Get list of whitelisted resources of a specific type for a check.
        
        Args:
            check_id: The ID of the check
            resource_type: Type of resource (roles, users, policies, etc.)
            
        Returns:
            List of whitelisted resource names/patterns
        """
        check_config = self.get_whitelist_config(check_id)
        return check_config.get(resource_type, [])

    @property
    def is_using_default_whitelist(self) -> bool:
        """
        Check if the default whitelist is being used.
        
        Returns:
            True if using default whitelist, False if using custom whitelist
        """
        return not hasattr(self, '_custom_whitelist_path') or self._custom_whitelist_path is None

# Global instance - will be initialized with custom path if provided
whitelist = None  # type: Optional[Whitelist]

def initialize_whitelist(custom_whitelist_path: Optional[str] = None) -> None:
    """
    Initialize the global whitelist instance.
    
    Args:
        custom_whitelist_path: Optional path to a custom whitelist YAML file.
                             If not provided, the default whitelist will be used.
    """
    global whitelist
    whitelist = Whitelist(custom_whitelist_path)
