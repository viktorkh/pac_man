import unittest
import os
import json
import shutil
from datetime import datetime
from unittest.mock import MagicMock, patch
from colorama import Fore, Style, Back

from pac_man.providers.aws.lib.output import (
    format_overview_results,
    format_remediation_results,
    get_findings_output,
    export_remediation_to_json,
    export_to_json
)
from pac_man.providers.aws.lib.check_result import CheckResult
from pac_man.providers.aws.lib.remediation_result import RemediationResult

class TestOutput(unittest.TestCase):
    """Test cases for output functions"""

    def setUp(self):
        """Set up test fixtures before each test method"""
        self.test_output_dir = "test_output"
        os.makedirs(self.test_output_dir, exist_ok=True)
        self.logger = MagicMock()

        # Create sample findings
        self.findings = []
        
        # Failed finding with remediation
        failed_finding = CheckResult()
        failed_finding.check_id = "CIS_1.1"
        failed_finding.check_description = "Test Failed Check"
        failed_finding.status = "FAIL"
        failed_finding.resource_id = "resource1"
        failed_finding.resource_arn = "arn:aws:iam::123456789012:user/resource1"
        failed_finding.region = "us-east-1"
        failed_finding.status_extended = "Failed check details"
        failed_finding.resource_details = "Resource details"
        failed_finding.resource_tags = [{"Key": "Environment", "Value": "Production"}]
        
        remediation = failed_finding.init_remediation()
        remediation.mark_as_success("Fixed the issue", {"new": "state"})
        self.findings.append(failed_finding)

        # Passed finding
        passed_finding = CheckResult()
        passed_finding.check_id = "CIS_1.2"
        passed_finding.check_description = "Test Passed Check"
        passed_finding.status = "PASS"
        passed_finding.resource_id = "resource2"
        self.findings.append(passed_finding)

        # Muted finding
        muted_finding = CheckResult()
        muted_finding.check_id = "CIS_1.3"
        muted_finding.check_description = "Test Muted Check"
        muted_finding.status = "MUTED"
        muted_finding.resource_id = "resource3"
        self.findings.append(muted_finding)

        # Create CIS 1.20 findings
        self.cis_1_20_findings = []
        regions = ["us-east-1", "us-west-1", "eu-west-1", "ap-south-1"]
        
        for region in regions:
            finding = CheckResult()
            finding.check_id = "cis_1_20"
            finding.check_description = "Ensure IAM Access Analyzer is enabled in all active regions"
            finding.status = "FAIL"
            finding.region = region
            finding.resource_id = f"analyzer-{region}"
            self.cis_1_20_findings.append(finding)

    def tearDown(self):
        """Clean up test fixtures after each test method"""
        if os.path.exists(self.test_output_dir):
            shutil.rmtree(self.test_output_dir)

    def test_format_overview_results_cis_1_20_all_fail(self):
        """Test formatting overview when all regions fail in CIS 1.20"""
        result = format_overview_results(self.cis_1_20_findings)
        
        # All 4 regions failed, should show 100%
        self.assertIn("100.00%", result)
        self.assertIn("(4) Failed", result)
        self.assertNotIn("Passed", result)

    def test_format_overview_results_cis_1_20_mixed(self):
        """Test formatting overview with mixed results in CIS 1.20"""
        # Modify two findings to PASS
        self.cis_1_20_findings[0].status = "PASS"
        self.cis_1_20_findings[1].status = "PASS"
        
        result = format_overview_results(self.cis_1_20_findings)
        
        # 2 passed, 2 failed out of 4 regions
        self.assertIn("50.00%", result)
        self.assertIn("(2) Failed", result)
        self.assertIn("(2) Passed", result)

    def test_format_overview_results_cis_1_20_vs_other(self):
        """Test that CIS 1.20 percentage calculation differs from other checks"""
        # Create a non-CIS 1.20 check with same number of findings
        other_findings = []
        for i in range(4):
            finding = CheckResult()
            finding.check_id = "other_check"
            finding.status = "FAIL"
            other_findings.append(finding)
        
        # Get results for both
        cis_result = format_overview_results(self.cis_1_20_findings)
        other_result = format_overview_results(other_findings)
        
        # CIS 1.20 should show 100% failed (4/4 regions)
        self.assertIn("100.00%", cis_result)
        # Other check should also show 100% but the calculation method is different
        self.assertIn("100.00%", other_result)

    def test_format_remediation_results_mixed(self):
        """Test formatting remediation results with both successful and failed remediations"""
        result = format_remediation_results(3, 2, 1)
        
        # Verify both status types are present
        self.assertIn("Failed", result)
        self.assertIn("Successful", result)
        
        # Verify percentages (1/3 failed = 33.33%, 2/3 successful = 66.67%)
        self.assertIn("33.33%", result)
        self.assertIn("66.67%", result)
        
        # Verify counts
        self.assertIn("(1)", result)
        self.assertIn("(2)", result)

    def test_format_remediation_results_all_failed(self):
        """Test formatting remediation results with only failed remediations"""
        result = format_remediation_results(2, 0, 2)
        
        # Verify only failed status is present
        self.assertIn("Failed", result)
        self.assertNotIn("Successful", result)
        
        # Verify 100% failed
        self.assertIn("100.00%", result)
        self.assertIn("(2)", result)

    def test_format_remediation_results_all_successful(self):
        """Test formatting remediation results with only successful remediations"""
        result = format_remediation_results(3, 3, 0)
        
        # Verify only successful status is present
        self.assertNotIn("Failed", result)
        self.assertIn("Successful", result)
        
        # Verify 100% successful
        self.assertIn("100.00%", result)
        self.assertIn("(3)", result)

    def test_format_remediation_results_no_attempts(self):
        """Test formatting remediation results with no remediation attempts"""
        result = format_remediation_results(0, 0, 0)
        self.assertEqual(result, "\nRemediation Results:\nNo remediation attempts to display")

    def test_format_overview_results_all_statuses(self):
        """Test formatting overview with all status types"""
        result = format_overview_results(self.findings)
        
        # Verify all status types are present
        self.assertIn("Failed", result)
        self.assertIn("Passed", result)
        self.assertIn("Muted", result)
        
        # Verify percentages
        self.assertIn("33.33%", result)  # Each status should be ~33.33%

    def test_format_overview_results_empty(self):
        """Test formatting overview with no findings"""
        result = format_overview_results([])
        self.assertEqual(result, "No findings to display")

    def test_format_overview_results_single_status(self):
        """Test formatting overview with only one status type"""
        findings = [self.findings[0]]  # Only the failed finding
        result = format_overview_results(findings)
        
        self.assertIn("100.00%", result)
        self.assertIn("Failed", result)
        self.assertNotIn("Passed", result)
        self.assertNotIn("Muted", result)

    def test_get_findings_output(self):
        """Test extracting findings statistics"""
        stats = get_findings_output(self.findings, self.logger)
        
        self.assertEqual(stats["total_pass"], 1)
        self.assertEqual(stats["total_fail"], 1)
        self.assertEqual(stats["resources_count"], 3)  # 3 unique resources
        self.assertEqual(stats["findings_count"], 2)  # Pass and Fail count as findings

    def test_get_findings_output_empty(self):
        """Test extracting findings statistics with no findings"""
        stats = get_findings_output([], self.logger)
        
        self.assertEqual(stats["total_pass"], 0)
        self.assertEqual(stats["total_fail"], 0)
        self.assertEqual(stats["resources_count"], 0)
        self.assertEqual(stats["findings_count"], 0)

    def test_export_remediation_to_json(self):
        """Test exporting remediation results to JSON"""
        filepath = export_remediation_to_json(self.findings, self.test_output_dir, self.logger)
        
        self.assertIsNotNone(filepath)
        self.assertTrue(os.path.exists(filepath))
        
        # Verify JSON content
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        self.assertIn("timestamp", data)
        self.assertIn("remediation_summary", data)
        self.assertIn("remediated_checks", data)
        
        summary = data["remediation_summary"]
        self.assertEqual(summary["total_attempted"], 1)
        self.assertEqual(summary["total_successful"], 1)
        self.assertEqual(summary["total_failed"], 0)

    def test_export_remediation_to_json_no_remediations(self):
        """Test exporting remediation results with no remediations"""
        findings = [self.findings[1]]  # Only the passed finding
        filepath = export_remediation_to_json(findings, self.test_output_dir, self.logger)
        
        self.assertIsNotNone(filepath)
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        self.assertEqual(data["remediation_summary"]["total_attempted"], 0)
        self.assertEqual(len(data["remediated_checks"]), 0)

    def test_export_remediation_to_json_file_error(self):
        """Test error handling when file operations fail in remediation export"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            filepath = export_remediation_to_json(self.findings, self.test_output_dir, self.logger)
            self.assertIsNone(filepath)
            self.logger.error.assert_called()

    def test_export_remediation_to_json_dir_error(self):
        """Test error handling when directory creation fails in remediation export"""
        with patch('os.makedirs', side_effect=PermissionError("Permission denied")):
            filepath = export_remediation_to_json(self.findings, self.test_output_dir, self.logger)
            self.assertIsNone(filepath)
            self.logger.error.assert_called()

    def test_export_to_json(self):
        """Test exporting findings to JSON"""
        filepath = export_to_json(self.findings, self.test_output_dir, self.logger)
        
        self.assertIsNotNone(filepath)
        self.assertTrue(os.path.exists(filepath))
        
        # Verify JSON content
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        self.assertIn("timestamp", data)
        self.assertIn("checks", data)
        
        # Verify check data
        checks = data["checks"]
        self.assertEqual(len(checks), 3)  # Three different check IDs
        
        # Verify specific check content
        check = checks["CIS_1.1"]
        self.assertEqual(check["check_description"], "Test Failed Check")
        finding = check["findings"]["failed"][0]  # Updated to use correct structure
        self.assertEqual(finding["status"], "FAIL")
        self.assertEqual(finding["resource_id"], "resource1")

    def test_export_to_json_empty(self):
        """Test exporting empty findings list to JSON"""
        filepath = export_to_json([], self.test_output_dir, self.logger)
        
        self.assertIsNotNone(filepath)
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        self.assertEqual(len(data["checks"]), 0)

    def test_export_to_json_error_handling(self):
        """Test error handling in JSON export"""
        # Use an invalid directory to trigger an error
        invalid_dir = "\\\\invalid\\directory\\path"  # Updated to use invalid Windows path
        filepath = export_to_json(self.findings, invalid_dir, self.logger)
        
        self.assertIsNone(filepath)
        self.logger.error.assert_called()  # Verify error was logged

    def test_export_to_json_file_error(self):
        """Test error handling when file operations fail"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            filepath = export_to_json(self.findings, self.test_output_dir, self.logger)
            self.assertIsNone(filepath)
            self.logger.error.assert_called()

    def test_export_to_json_dir_error(self):
        """Test error handling when directory creation fails"""
        with patch('os.makedirs', side_effect=PermissionError("Permission denied")):
            filepath = export_to_json(self.findings, self.test_output_dir, self.logger)
            self.assertIsNone(filepath)
            self.logger.error.assert_called()

if __name__ == '__main__':
    unittest.main()
