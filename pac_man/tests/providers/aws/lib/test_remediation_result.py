"""Unit tests for the RemediationResult class."""

import unittest
from datetime import datetime
from unittest.mock import Mock

from pac_man.providers.aws.lib.remediation_result import RemediationResult
from pac_man.providers.aws.lib.check_result import CheckResult

def run_tests():
    """Run the test suite with detailed output."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRemediationResult)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)

class TestRemediationResult(unittest.TestCase):
    """Test cases for the RemediationResult class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.remediation = RemediationResult()
        self.remediation.check_id = "CIS_1_1"
        self.remediation.resource_id = "test-resource"
        self.remediation.provider = "aws"
        self.remediation.region = "us-east-1"

        # Set up a mock finding
        self.finding = Mock(spec=CheckResult)
        self.finding.check_id = "CIS_1_1"
        self.finding.resource_id = "test-resource"
        self.finding.region = "us-east-1"
        self.finding.status = "FAIL"
        self.finding.status_extended = "Initial state"

    def test_initial_state(self):
        """Test the initial state of a new RemediationResult instance."""
        result = RemediationResult()
        self.assertEqual(result.status, "IN_PROGRESS")
        self.assertIsNone(result.error_message)
        self.assertEqual(result.original_state, {})
        self.assertEqual(result.current_state, {})
        self.assertEqual(result.details, "")
        self.assertEqual(result.provider, "")
        self.assertEqual(result.action_taken, "")
        self.assertIsInstance(result.timestamp, datetime)

    def test_mark_as_success(self):
        """Test marking a remediation as successful."""
        details = "Successfully updated IAM password policy"
        new_state = {"password_length": 14}
        
        self.remediation.mark_as_success(details, new_state)
        
        self.assertEqual(self.remediation.status, "SUCCESS")
        self.assertEqual(self.remediation.details, details)
        self.assertEqual(self.remediation.current_state, new_state)
        self.assertIsNone(self.remediation.error_message)

    def test_mark_as_success_with_finding_update(self):
        """Test marking a remediation as successful with finding status update."""
        # Create a finding and remediation result
        finding = CheckResult()
        finding.check_id = "CIS_1_1"
        finding.status = "FAIL"
        finding.status_extended = "Initial failure state"
        
        remediation = RemediationResult()
        remediation.check_id = finding.check_id
        
        # Mark as success and update finding
        details = "Successfully updated configuration"
        new_state = {"config": "updated"}
        remediation.mark_as_success(details, new_state)
        finding.status = "PASS"
        finding.status_extended = details
        
        # Verify both remediation and finding are updated correctly
        self.assertEqual(remediation.status, "SUCCESS")
        self.assertEqual(remediation.details, details)
        self.assertEqual(remediation.current_state, new_state)
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.status_extended, details)

    def test_mark_as_failed(self):
        """Test marking a remediation as failed."""
        error = "Insufficient permissions"
        details = "Failed to update IAM password policy"
        
        self.remediation.mark_as_failed(error, details)
        
        self.assertEqual(self.remediation.status, "FAILED")
        self.assertEqual(self.remediation.error_message, error)
        self.assertEqual(self.remediation.details, details)

    def test_mark_as_failed_with_finding_update(self):
        """Test marking a remediation as failed with finding status update."""
        # Create a finding and remediation result
        finding = CheckResult()
        finding.check_id = "CIS_1_1"
        finding.status = "FAIL"
        finding.status_extended = "Initial failure state"
        
        remediation = RemediationResult()
        remediation.check_id = finding.check_id
        
        # Mark as failed and update finding
        error = "Permission denied"
        details = "Failed to update configuration"
        remediation.mark_as_failed(error, details)
        finding.status_extended = f"Fix attempt failed: {error}"
        
        # Verify both remediation and finding are updated correctly
        self.assertEqual(remediation.status, "FAILED")
        self.assertEqual(remediation.error_message, error)
        self.assertEqual(remediation.details, details)
        self.assertEqual(finding.status, "FAIL")  # Status should remain FAIL
        self.assertEqual(finding.status_extended, f"Fix attempt failed: {error}")

    def test_set_original_state(self):
        """Test setting the original state of the resource."""
        original_state = {"password_length": 8, "require_symbols": False}
        
        self.remediation.set_original_state(original_state)
        
        self.assertEqual(self.remediation.original_state, original_state)

    def test_provider_handling(self):
        """Test setting and getting provider."""
        self.remediation.provider = "gcp"
        self.assertEqual(self.remediation.provider, "gcp")

    def test_action_taken(self):
        """Test setting and getting action_taken."""
        action = "Updated IAM password policy configuration"
        self.remediation.action_taken = action
        self.assertEqual(self.remediation.action_taken, action)

    def test_timestamp_in_to_dict(self):
        """Test that timestamp is properly formatted in to_dict output."""
        result_dict = self.remediation.to_dict()
        # Verify timestamp is in ISO format
        try:
            datetime.fromisoformat(result_dict["timestamp"])
        except ValueError:
            self.fail("Timestamp is not in valid ISO format")

    def test_error_message_in_to_dict(self):
        """Test that error_message is properly handled in to_dict."""
        # Test without error message
        result_dict = self.remediation.to_dict()
        self.assertNotIn("error_message", result_dict)

        # Test with error message
        self.remediation.error_message = "Test error"
        result_dict = self.remediation.to_dict()
        self.assertEqual(result_dict["error_message"], "Test error")

    def test_to_dict(self):
        """Test converting remediation result to dictionary."""
        self.remediation.details = "Test details"
        self.remediation.action_taken = "Updated configuration"
        self.remediation.original_state = {"old": "value"}
        self.remediation.current_state = {"new": "value"}
        
        result_dict = self.remediation.to_dict()
        
        self.assertEqual(result_dict["check_id"], "CIS_1_1")
        self.assertEqual(result_dict["resource_id"], "test-resource")
        self.assertEqual(result_dict["status"], "IN_PROGRESS")
        self.assertEqual(result_dict["details"], "Test details")
        self.assertEqual(result_dict["action_taken"], "Updated configuration")
        self.assertEqual(result_dict["provider"], "aws")
        self.assertEqual(result_dict["region"], "us-east-1")
        self.assertEqual(result_dict["original_state"], {"old": "value"})
        self.assertEqual(result_dict["current_state"], {"new": "value"})

    def test_from_dict_complete(self):
        """Test creating remediation result from complete dictionary."""
        timestamp = datetime.now()
        data = {
            "check_id": "CIS_1_2",
            "resource_id": "test-resource-2",
            "status": "SUCCESS",
            "timestamp": timestamp.isoformat(),
            "details": "Successfully remediated",
            "error_message": "Test error",
            "action_taken": "Updated policy",
            "provider": "aws",
            "region": "us-west-2",
            "original_state": {"old": "config"},
            "current_state": {"new": "config"}
        }
        
        result = RemediationResult.from_dict(data)
        
        self.assertEqual(result.check_id, "CIS_1_2")
        self.assertEqual(result.resource_id, "test-resource-2")
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.details, "Successfully remediated")
        self.assertEqual(result.error_message, "Test error")
        self.assertEqual(result.action_taken, "Updated policy")
        self.assertEqual(result.provider, "aws")
        self.assertEqual(result.region, "us-west-2")
        self.assertEqual(result.original_state, {"old": "config"})
        self.assertEqual(result.current_state, {"new": "config"})
        self.assertEqual(result.timestamp.isoformat(), timestamp.isoformat())

    def test_from_dict_minimal(self):
        """Test creating remediation result from minimal dictionary."""
        data = {
            "check_id": "CIS_1_3"
        }
        
        result = RemediationResult.from_dict(data)
        
        self.assertEqual(result.check_id, "CIS_1_3")
        self.assertEqual(result.resource_id, "")
        self.assertEqual(result.status, "IN_PROGRESS")
        self.assertEqual(result.details, "")
        self.assertIsNone(result.error_message)
        self.assertEqual(result.action_taken, "")
        self.assertEqual(result.provider, "")
        self.assertEqual(result.region, "")
        self.assertEqual(result.original_state, {})
        self.assertEqual(result.current_state, {})

    def test_from_dict_with_invalid_timestamp(self):
        """Test handling invalid timestamp in from_dict method."""
        data = {
            "check_id": "CIS_1_3",
            "timestamp": "invalid-timestamp"
        }
        
        result = RemediationResult.from_dict(data)
        
        self.assertIsInstance(result.timestamp, datetime)

    def test_to_dict_empty_optional_fields(self):
        """Test that to_dict excludes empty optional fields."""
        result_dict = self.remediation.to_dict()
        
        self.assertNotIn("error_message", result_dict)
        self.assertNotIn("original_state", result_dict)
        self.assertNotIn("current_state", result_dict)

    def test_remediation_with_finding_workflow(self):
        """Test the complete workflow of remediation with a finding object."""
        # Create a finding
        finding = CheckResult()
        finding.check_id = "CIS_1_1"
        finding.resource_id = "test-resource"
        finding.region = "us-east-1"
        finding.status = "FAIL"
        finding.status_extended = "Initial failure state"
        
        # Initialize remediation from finding
        remediation = RemediationResult()
        remediation.check_id = finding.check_id
        remediation.resource_id = finding.resource_id
        remediation.provider = "aws"
        remediation.region = finding.region
        
        # Set original state
        original_state = {"config": "initial"}
        remediation.set_original_state(original_state)
        
        # Simulate successful remediation
        details = "Successfully updated configuration"
        new_state = {"config": "updated"}
        remediation.mark_as_success(details, new_state)
        finding.status = "PASS"
        finding.status_extended = details
        
        # Verify final state
        self.assertEqual(remediation.status, "SUCCESS")
        self.assertEqual(remediation.details, details)
        self.assertEqual(remediation.current_state, new_state)
        self.assertEqual(remediation.original_state, original_state)
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.status_extended, details)

if __name__ == '__main__':
    run_tests()
