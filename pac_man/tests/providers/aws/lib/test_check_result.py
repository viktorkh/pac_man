import unittest

from pac_man.providers.aws.lib.check_result import CheckResult
from pac_man.providers.aws.lib.remediation_result import RemediationResult

class TestCheckResult(unittest.TestCase):
    """Test cases for the CheckResult class"""
    
    def setUp(self):
        """Set up test fixtures before each test method"""
        self.check_result = CheckResult()
        self.check_result.check_id = "CIS_1.1"
        self.check_result.check_description = "Test Description"
        self.check_result.resource_id = "test-resource-123"
        self.check_result.region = "us-east-1"
        
    def test_initialization(self):
        """Test that CheckResult initializes with correct default values"""
        check_result = CheckResult()
        
        # Verify default values
        self.assertEqual(check_result.status, "")
        self.assertEqual(check_result.status_extended, "")
        self.assertEqual(check_result.resource_details, "")
        self.assertEqual(check_result.resource_tags, [])
        self.assertEqual(check_result.resource_id, "")
        self.assertEqual(check_result.resource_arn, "")
        self.assertEqual(check_result.region, "")
        self.assertIsNone(check_result.remediation_result)

    def test_check_description(self):
        """Test setting and getting check description"""
        description = "Ensure IAM password policy requires minimum length"
        self.check_result.check_description = description
        self.assertEqual(self.check_result.check_description, description)

    def test_status(self):
        """Test setting and getting status"""
        status = "FAIL"
        self.check_result.status = status
        self.assertEqual(self.check_result.status, status)

    def test_status_extended(self):
        """Test setting and getting status extended"""
        status_extended = "Password policy minimum length is set to 8 characters"
        self.check_result.status_extended = status_extended
        self.assertEqual(self.check_result.status_extended, status_extended)

    def test_resource_details(self):
        """Test setting and getting resource details"""
        details = {"MinimumPasswordLength": 8, "RequireSymbols": True}
        self.check_result.resource_details = str(details)
        self.assertEqual(self.check_result.resource_details, str(details))

    def test_resource_tags(self):
        """Test setting and getting resource tags"""
        tags = [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "Security"}]
        self.check_result.resource_tags = tags
        self.assertEqual(self.check_result.resource_tags, tags)

    def test_resource_arn(self):
        """Test setting and getting resource ARN"""
        arn = "arn:aws:iam::123456789012:user/test-user"
        self.check_result.resource_arn = arn
        self.assertEqual(self.check_result.resource_arn, arn)
        
    def test_init_remediation(self):
        """Test initialization of remediation result"""
        remediation = self.check_result.init_remediation()
        
        # Verify remediation was initialized with correct values
        self.assertIsInstance(remediation, RemediationResult)
        self.assertEqual(remediation.check_id, self.check_result.check_id)
        self.assertEqual(remediation.resource_id, self.check_result.resource_id)
        self.assertEqual(remediation.region, self.check_result.region)
        
        # Verify remediation was properly attached to check result
        self.assertIs(self.check_result.remediation_result, remediation)
        
    def test_get_remediation_status_not_attempted(self):
        """Test getting remediation status when no remediation has been attempted"""
        status = self.check_result.get_remediation_status()
        self.assertEqual(status, "NOT_ATTEMPTED")
        
    def test_get_remediation_status_with_remediation(self):
        """Test getting remediation status after remediation has been initialized"""
        remediation = self.check_result.init_remediation()
        remediation.status = "SUCCESS"
        
        status = self.check_result.get_remediation_status()
        self.assertEqual(status, "SUCCESS")
        
    def test_get_remediation_details_not_attempted(self):
        """Test getting remediation details when no remediation has been attempted"""
        details = self.check_result.get_remediation_details()
        self.assertEqual(details, "")
        
    def test_get_remediation_details_with_remediation(self):
        """Test getting remediation details after remediation has been initialized"""
        remediation = self.check_result.init_remediation()
        remediation.details = "Fixed security group rules"
        
        details = self.check_result.get_remediation_details()
        self.assertEqual(details, "Fixed security group rules")

if __name__ == '__main__':
    unittest.main()
