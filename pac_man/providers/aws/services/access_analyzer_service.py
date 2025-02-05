"""Access Analyzer service abstraction."""

from typing import Any, Dict, List
from .base import AWSServiceBase

class AccessAnalyzerService(AWSServiceBase):
    """Service class for AWS IAM Access Analyzer operations."""
    
    def __init__(self, session, region_name=None):
        """
        Initialize Access Analyzer service.
        
        Args:
            session: Boto3 session
            region_name: Optional region name override
        """
        super().__init__(session, region_name)
        self.client = self._get_client('accessanalyzer')
    
    def list_analyzers(self) -> Dict[str, Any]:
        """
        List IAM Access Analyzers in the current region.
        
        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - analyzers (List[Dict]): List of analyzer details if successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            response = self.client.list_analyzers()
            return {
                'success': True,
                'analyzers': response['analyzers']
            }
            
        except Exception as e:
            return self._handle_error(e, 'list_analyzers')

    def create_analyzer(self, analyzer_name: str) -> Dict[str, Any]:
        """
        Create an IAM Access Analyzer in the current region.

        Args:
            analyzer_name (str): The name for the new analyzer

        Returns:
            Dict containing:
                - success (bool): Whether the operation was successful
                - arn (str): The ARN of the created analyzer if successful
                - error_message (str): Error message if unsuccessful
        """
        try:
            response = self.client.create_analyzer(
                analyzerName=analyzer_name,
                type='ACCOUNT'
            )
            return {
                'success': True,
                'arn': response['arn']
            }
        except Exception as e:
            return self._handle_error(e, 'create_analyzer')
