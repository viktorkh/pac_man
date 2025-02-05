"""Test cases for CIS 2.1.2 check implementation."""

import unittest
from unittest.mock import Mock, patch

from pac_man.providers.aws.controls.cis_2_1_2.cis_2_1_2_check import check_mfa_delete, execute, CHECK_ID
from pac_man.providers.aws.lib.check_result import CheckResult

class TestCIS212Check(unittest.TestCase):
    """Test cases for CIS 2.1.2 check implementation."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mock_session = Mock()
        self.mock_logger = Mock()
        self.mock_s3_service = Mock()
        self.mock_service_factory = Mock()
        self.mock_service_factory.get_service.return_value = self.mock_s3_service

    def test_check_mfa_delete_enabled(self):
        """Test when MFA Delete is enabled."""
        self.mock_s3_service.get_bucket_location.return_value = {
            'success': True,
            'location': 'eu-west-1'
        }
        self.mock_s3_service.get_bucket_versioning.return_value = {
            'success': True,
            'versioning': 'Enabled',
            'mfa_delete': 'Enabled'
        }

        result = check_mfa_delete(self.mock_s3_service, 'test-bucket', self.mock_logger)

        self.assertEqual(result.status, CheckResult.STATUS_PASS)
        self.assertEqual(result.check_id, CHECK_ID)
        self.assertEqual(result.resource_id, "test-bucket")
        self.assertEqual(result.resource_arn, "arn:aws:s3:::test-bucket")
        self.assertEqual(result.region, "eu-west-1")
        self.assertIn("MFA Delete is enabled", result.status_extended)

    def test_check_mfa_delete_disabled(self):
        """Test when MFA Delete is disabled."""
        self.mock_s3_service.get_bucket_location.return_value = {
            'success': True,
            'location': 'us-east-1'
        }
        self.mock_s3_service.get_bucket_versioning.return_value = {
            'success': True,
            'versioning': 'Enabled',
            'mfa_delete': 'Disabled'
        }

        result = check_mfa_delete(self.mock_s3_service, 'test-bucket', self.mock_logger)

        self.assertEqual(result.status, CheckResult.STATUS_FAIL)
        self.assertEqual(result.check_id, CHECK_ID)
        self.assertEqual(result.resource_id, "test-bucket")
        self.assertIn("MFA Delete is not enabled", result.status_extended)

    def test_check_mfa_delete_versioning_disabled(self):
        """Test when versioning is disabled."""
        self.mock_s3_service.get_bucket_location.return_value = {
            'success': True,
            'location': 'us-east-1'
        }
        self.mock_s3_service.get_bucket_versioning.return_value = {
            'success': True,
            'versioning': 'Suspended',
            'mfa_delete': 'Disabled'
        }

        result = check_mfa_delete(self.mock_s3_service, 'test-bucket', self.mock_logger)

        self.assertEqual(result.status, CheckResult.STATUS_FAIL)
        self.assertEqual(result.check_id, CHECK_ID)
        self.assertEqual(result.resource_id, "test-bucket")
        self.assertIn("MFA Delete is not enabled", result.status_extended)
        self.assertIn("Versioning status: Suspended", result.status_extended)

    def test_check_mfa_delete_location_error(self):
        """Test error handling for get_bucket_location."""
        self.mock_s3_service.get_bucket_location.return_value = {
            'success': False,
            'error_message': 'Test error'
        }

        result = check_mfa_delete(self.mock_s3_service, 'test-bucket', self.mock_logger)

        self.assertEqual(result.status, CheckResult.STATUS_FAIL)  # Changed from ERROR to FAIL
        self.assertEqual(result.check_id, CHECK_ID)
        self.assertEqual(result.resource_id, "test-bucket")
        self.assertIn("Unable to verify MFA Delete status", result.status_extended)
        self.mock_logger.error.assert_called_once()

    def test_check_mfa_delete_versioning_error(self):
        """Test error handling for get_bucket_versioning."""
        self.mock_s3_service.get_bucket_location.return_value = {
            'success': True,
            'location': 'us-east-1'
        }
        self.mock_s3_service.get_bucket_versioning.return_value = {
            'success': False,
            'error_message': 'Test error'
        }

        result = check_mfa_delete(self.mock_s3_service, 'test-bucket', self.mock_logger)

        self.assertEqual(result.status, CheckResult.STATUS_FAIL)  # Changed from ERROR to FAIL
        self.assertEqual(result.check_id, CHECK_ID)
        self.assertEqual(result.resource_id, "test-bucket")
        self.assertIn("Unable to verify MFA Delete status", result.status_extended)
        self.mock_logger.error.assert_called_once()

    def test_execute_with_buckets(self):
        """Test execute function with buckets."""
        self.mock_s3_service.list_buckets.return_value = {
            'success': True,
            'buckets': [
                {'Name': 'bucket1'},
                {'Name': 'bucket2'}
            ]
        }
        self.mock_s3_service.get_bucket_location.return_value = {
            'success': True,
            'location': 'us-east-1'
        }
        self.mock_s3_service.get_bucket_versioning.return_value = {
            'success': True,
            'versioning': 'Enabled',
            'mfa_delete': 'Enabled'
        }

        findings = execute(self.mock_session, self.mock_logger, self.mock_service_factory)

        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertTrue(isinstance(finding, CheckResult))
            self.assertEqual(finding.status, CheckResult.STATUS_PASS)
            self.assertEqual(finding.check_id, CHECK_ID)

    def test_execute_list_buckets_error(self):
        """Test execute function error handling for list_buckets."""
        self.mock_s3_service.list_buckets.return_value = {
            'success': False,
            'error_message': 'Test error'
        }

        findings = execute(self.mock_session, self.mock_logger, self.mock_service_factory)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertTrue(isinstance(finding, CheckResult))
        self.assertEqual(finding.status, CheckResult.STATUS_FAIL)  # Changed from ERROR to FAIL
        self.assertEqual(finding.check_id, CHECK_ID)
        self.assertEqual(finding.resource_id, "S3Buckets")
        self.assertEqual(finding.resource_arn, "arn:aws:s3:::*")
        self.assertEqual(finding.region, "global")
        self.assertIn("Unable to verify MFA Delete status", finding.status_extended)

    def test_execute_general_error(self):
        """Test execute function general error handling."""
        self.mock_s3_service.list_buckets.side_effect = Exception("Test error")

        findings = execute(self.mock_session, self.mock_logger, self.mock_service_factory)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertTrue(isinstance(finding, CheckResult))
        self.assertEqual(finding.status, CheckResult.STATUS_FAIL)  # Changed from ERROR to FAIL
        self.assertEqual(finding.check_id, CHECK_ID)
        self.assertEqual(finding.resource_id, "S3Buckets")
        self.assertEqual(finding.resource_arn, "arn:aws:s3:::*")
        self.assertEqual(finding.region, "global")
        self.assertIn("Unable to verify MFA Delete status", finding.status_extended)
        self.mock_logger.error.assert_called_once()

if __name__ == '__main__':
    unittest.main()
