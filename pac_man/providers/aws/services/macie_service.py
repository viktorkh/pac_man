"""AWS Macie Service module for pac_man security audit tool."""

from botocore.exceptions import ClientError
from .base import AWSServiceBase

class MacieService(AWSServiceBase):
    """Service class for interacting with AWS Macie."""

    def __init__(self, session, logger):
        """
        Initialize the MacieService.

        Args:
            session (boto3.Session): The boto3 session to use for AWS calls.
            logger: Logger object for logging messages.
        """
        super().__init__(session, logger)
        self.client = self.session.client('macie2')

    def get_macie_status(self):
        """
        Get the status of Amazon Macie for the current account.

        Returns:
            dict: A dictionary containing the success status and Macie status.
        """
        try:
            response = self.client.get_macie_session()
            return {
                'success': True,
                'enabled': response['status'] == 'ENABLED'
            }
        except ClientError as e:
            self.logger.error(f"Error getting Macie status: {str(e)}")
            return {
                'success': False,
                'error_message': str(e)
            }

    def list_classification_jobs(self):
        """
        List all classification jobs for the current account.

        Returns:
            dict: A dictionary containing the success status and list of jobs.
        """
        try:
            response = self.client.list_classification_jobs(
                filterCriteria={
                    'jobStatus': {
                        'eq': ['RUNNING', 'PAUSED']
                    }
                }
            )
            return {
                'success': True,
                'jobs': response.get('items', [])
            }
        except ClientError as e:
            self.logger.error(f"Error listing Macie classification jobs: {str(e)}")
            return {
                'success': False,
                'error_message': str(e)
            }

    # Add more Macie-related methods as needed