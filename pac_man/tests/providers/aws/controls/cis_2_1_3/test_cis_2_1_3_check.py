import unittest
from unittest.mock import Mock, MagicMock
from pac_man.providers.aws.controls.cis_2_1_3.cis_2_1_3_check import execute, check_macie_enabled
from pac_man.providers.aws.lib.check_result import CheckResult

class TestCIS213Check(unittest.TestCase):

    def setUp(self):
        # Mock logger
        self.logger = Mock()
        
        # Mock Macie service
        self.macie_service = Mock()
        
        # Mock service factory
        self.service_factory = Mock()
        self.service_factory.get_service.return_value = self.macie_service

    def test_macie_disabled(self):
        """Test when Amazon Macie is not enabled"""
        self.macie_service.get_macie_status.return_value = {'success': True, 'enabled': False}
        result = check_macie_enabled(self.macie_service, self.logger)
        self.assertEqual(result.status, CheckResult.STATUS_FAIL)
        self.assertIn("Amazon Macie is not enabled", result.status_extended)

    def test_macie_enabled_no_jobs(self):
        """Test when Amazon Macie is enabled but no jobs are active"""
        self.macie_service.get_macie_status.return_value = {'success': True, 'enabled': True}
        self.macie_service.list_classification_jobs.return_value = {'success': True, 'jobs': []}
        result = check_macie_enabled(self.macie_service, self.logger)
        self.assertEqual(result.status, CheckResult.STATUS_FAIL)
        self.assertIn("no active classification jobs found", result.status_extended)

    def test_macie_enabled_with_jobs(self):
        """Test when Amazon Macie is enabled and jobs are active"""
        self.macie_service.get_macie_status.return_value = {'success': True, 'enabled': True}
        self.macie_service.list_classification_jobs.return_value = {'success': True, 'jobs': [{'id': 'job1'}]}
        result = check_macie_enabled(self.macie_service, self.logger)
        self.assertEqual(result.status, CheckResult.STATUS_PASS)
        self.assertIn("Amazon Macie is enabled and has active classification jobs", result.status_extended)

    def test_macie_status_error(self):
        """Test when there is an error checking Macie status"""
        self.macie_service.get_macie_status.return_value = {'success': False, 'error_message': 'API error'}
        result = check_macie_enabled(self.macie_service, self.logger)
        self.assertEqual(result.status, CheckResult.STATUS_FAIL)
        self.assertIn("Unable to verify Macie status", result.status_extended)

    def test_execute(self):
        """Test the execute function"""
        self.macie_service.get_macie_status.return_value = {'success': True, 'enabled': True}
        self.macie_service.list_classification_jobs.return_value = {'success': True, 'jobs': [{'id': 'job1'}]}

        session = Mock()
        results = execute(session, self.logger, self.service_factory)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, CheckResult.STATUS_PASS)
        self.assertIn("Amazon Macie is enabled and has active classification jobs", results[0].status_extended)

if __name__ == '__main__':
    unittest.main()
