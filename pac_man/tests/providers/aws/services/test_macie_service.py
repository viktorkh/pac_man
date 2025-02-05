import unittest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from pac_man.providers.aws.services.macie_service import MacieService

class TestMacieService(unittest.TestCase):

    def setUp(self):
        self.session = MagicMock()
        self.logger = MagicMock()
        self.macie_service = MacieService(self.session, self.logger)

    def test_get_macie_status_enabled(self):
        self.macie_service.client.get_macie_session.return_value = {'status': 'ENABLED'}
        result = self.macie_service.get_macie_status()
        self.assertTrue(result['success'])
        self.assertTrue(result['enabled'])

    def test_get_macie_status_disabled(self):
        self.macie_service.client.get_macie_session.return_value = {'status': 'DISABLED'}
        result = self.macie_service.get_macie_status()
        self.assertTrue(result['success'])
        self.assertFalse(result['enabled'])

    def test_get_macie_status_error(self):
        self.macie_service.client.get_macie_session.side_effect = ClientError(
            {'Error': {'Code': 'SomeError', 'Message': 'An error occurred'}},
            'get_macie_session'
        )
        result = self.macie_service.get_macie_status()
        self.assertFalse(result['success'])
        self.assertIn('error_message', result)

    def test_list_classification_jobs_success(self):
        self.macie_service.client.list_classification_jobs.return_value = {
            'items': [{'jobId': 'job1'}, {'jobId': 'job2'}]
        }
        result = self.macie_service.list_classification_jobs()
        self.assertTrue(result['success'])
        self.assertEqual(len(result['jobs']), 2)

    def test_list_classification_jobs_error(self):
        self.macie_service.client.list_classification_jobs.side_effect = ClientError(
            {'Error': {'Code': 'SomeError', 'Message': 'An error occurred'}},
            'list_classification_jobs'
        )
        result = self.macie_service.list_classification_jobs()
        self.assertFalse(result['success'])
        self.assertIn('error_message', result)

if __name__ == '__main__':
    unittest.main()