from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

@dataclass
class RemediationResult:
    """
    Contains information about a remediation attempt for a security check finding.
    
    This class tracks the details and outcome of attempts to fix security issues
    identified during the audit process.
    
    Attributes:
        check_id (str): The ID of the security check that was remediated
        resource_id (str): The ID of the resource that was remediated
        status (str): The status of the remediation attempt (SUCCESS, FAILED, IN_PROGRESS)
        timestamp (datetime): When the remediation was attempted
        details (str): Detailed description of what was done or attempted
        error_message (Optional[str]): Error message if remediation failed
        original_state (Dict[str, Any]): The state of the resource before remediation
        current_state (Dict[str, Any]): The state of the resource after remediation
        action_taken (str): Description of the specific action taken to remediate
        provider (str): The cloud provider (e.g., 'aws', 'gcp')
        region (str): The region where remediation was performed
    """

    def __init__(self):
        self.check_id: str = ""
        self.resource_id: str = ""
        self.status: str = "IN_PROGRESS"  # Default status
        self.timestamp: datetime = datetime.now()
        self.details: str = ""
        self.error_message: Optional[str] = None
        self.original_state: Dict[str, Any] = {}
        self.current_state: Dict[str, Any] = {}
        self.action_taken: str = ""
        self.provider: str = ""
        self.region: str = ""

    def mark_as_success(self, details: str, current_state: Dict[str, Any]) -> None:
        """
        Mark the remediation attempt as successful.
        
        Args:
            details: Detailed description of what was done
            current_state: The new state of the resource after remediation
        """
        self.status = "SUCCESS"
        self.details = details
        self.current_state = current_state
        self.timestamp = datetime.now()

    def mark_as_failed(self, error_message: str, details: str = "") -> None:
        """
        Mark the remediation attempt as failed.
        
        Args:
            error_message: Description of what went wrong
            details: Optional additional context about the failure
        """
        self.status = "FAILED"
        self.error_message = error_message
        self.details = details
        self.timestamp = datetime.now()

    def set_original_state(self, state: Dict[str, Any]) -> None:
        """
        Record the original state of the resource before remediation.
        
        Args:
            state: Dictionary containing the resource's original state
        """
        self.original_state = state

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the remediation result to a dictionary format.
        
        Returns:
            Dict containing all non-empty attributes of the remediation result
        """
        result = {
            'check_id': self.check_id,
            'resource_id': self.resource_id,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'action_taken': self.action_taken,
            'provider': self.provider,
            'region': self.region
        }

        # Only include non-empty optional fields
        if self.error_message:
            result['error_message'] = self.error_message
        if self.original_state:
            result['original_state'] = self.original_state
        if self.current_state:
            result['current_state'] = self.current_state

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RemediationResult':
        """
        Create a RemediationResult instance from a dictionary.
        
        Args:
            data: Dictionary containing remediation result data
            
        Returns:
            A new RemediationResult instance
        """
        result = cls()
        result.check_id = data.get('check_id', '')
        result.resource_id = data.get('resource_id', '')
        result.status = data.get('status', 'IN_PROGRESS')
        result.details = data.get('details', '')
        result.error_message = data.get('error_message')
        result.original_state = data.get('original_state', {})
        result.current_state = data.get('current_state', {})
        result.action_taken = data.get('action_taken', '')
        result.provider = data.get('provider', '')
        result.region = data.get('region', '')
        
        # Parse timestamp if present
        timestamp_str = data.get('timestamp')
        if timestamp_str:
            try:
                result.timestamp = datetime.fromisoformat(timestamp_str)
            except (ValueError, TypeError):
                result.timestamp = datetime.now()
        
        return result
