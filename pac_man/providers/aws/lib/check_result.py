from typing import List, Optional
from dataclasses import dataclass
from .remediation_result import RemediationResult

@dataclass
class CheckResult:
    """
    Contains the Check's finding information and associated remediation results.
    
    This class represents the result of a security check, including both the initial
    finding and any subsequent remediation attempts.
    """
    # Status constants
    STATUS_PASS = "PASS"
    STATUS_FAIL = "FAIL"
    STATUS_ERROR = "ERROR"
    STATUS_MUTED = "MUTED"

    check_id: str
    check_description: str
    status: str
    status_extended: str
    resource_details: str
    resource_tags: list
    resource_id: str
    resource_arn: str
    region: str
    remediation_result: Optional[RemediationResult]  # Added to track remediation attempts
    mute_reason: Optional[str]  # Added to track why a finding was muted

    def __init__(self):
        self.check_id: str
        self.check_description: str
        self.status = ""
        self.status_extended = ""
        self.resource_details = ""
        self.resource_tags = []
        self.resource_id = ""
        self.resource_arn = ""
        self.region = ""
        self.remediation_result = None  # Will be set when remediation is attempted
        self.mute_reason = None  # Will be set when a finding is muted

    def init_remediation(self) -> RemediationResult:
        """
        Initialize a new remediation attempt for this finding.
        
        Returns:
            A new RemediationResult instance linked to this finding
        """
        self.remediation_result = RemediationResult()
        self.remediation_result.check_id = self.check_id
        self.remediation_result.resource_id = self.resource_id
        self.remediation_result.region = self.region
        return self.remediation_result

    def get_remediation_status(self) -> str:
        """
        Get the current status of remediation attempts.
        
        Returns:
            The status of remediation, or 'NOT_ATTEMPTED' if no remediation has been tried
        """
        if self.remediation_result is None:
            return "NOT_ATTEMPTED"
        return self.remediation_result.status

    def get_remediation_details(self) -> str:
        """
        Get the details of remediation attempts.
        
        Returns:
            Details about the remediation attempt, or empty string if no remediation has been tried
        """
        if self.remediation_result is None:
            return ""
        return self.remediation_result.details

    def set_status(self, status: str, extended_msg: str = "") -> None:
        """
        Set the status of the check result with an optional extended message.
        
        Args:
            status: The status to set (should be one of the STATUS_ constants)
            extended_msg: Optional detailed message explaining the status
        """
        self.status = status
        if extended_msg:
            self.status_extended = extended_msg

    def mute(self, reason: str) -> None:
        """
        Mute a finding with a specific reason.
        
        Args:
            reason: The reason why this finding is being muted
        """
        self.status = self.STATUS_MUTED
        self.mute_reason = reason
        self.status_extended = f"Finding muted: {reason}"

    def is_muted(self) -> bool:
        """
        Check if the finding is muted.
        
        Returns:
            True if the finding is muted, False otherwise
        """
        return self.status == self.STATUS_MUTED

    def needs_remediation(self) -> bool:
        """
        Check if the finding needs remediation.
        
        Returns:
            True if the finding failed and is not muted, False otherwise
        """
        return self.status == self.STATUS_FAIL and not self.is_muted()
