"""Unit tests for AWS service factory."""

import pytest
from unittest.mock import Mock, patch
from providers.aws.services.service_factory import AWSServiceFactory
from providers.aws.services.iam_service import IAMService
from providers.aws.services.s3_service import S3Service
from providers.aws.services.cloudtrail_service import CloudTrailService
from providers.aws.services.config_service import ConfigService
from providers.aws.services.sts_service import STSService
from providers.aws.services.ec2_service import EC2Service
from providers.aws.services.access_analyzer_service import AccessAnalyzerService


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    return Mock()

@pytest.fixture
def service_factory(mock_session):
    """Create an AWSServiceFactory instance with a mock session."""
    return AWSServiceFactory(mock_session)

class TestInit:
    """Tests for AWSServiceFactory initialization."""
    
    def test_init(self, mock_session):
        """Test factory initialization."""
        factory = AWSServiceFactory(mock_session)
        assert factory.session == mock_session
        assert factory._service_cache == {}

class TestGetService:
    """Tests for get_service method."""
    
    def test_get_iam_service(self, service_factory):
        """Test getting IAM service."""
        service = service_factory.get_service('iam')
        assert isinstance(service, IAMService)
        assert service.region_name is None
    
    def test_get_s3_service(self, service_factory):
        """Test getting S3 service."""
        service = service_factory.get_service('s3')
        assert isinstance(service, S3Service)
        assert service.region_name is None
    
    def test_get_cloudtrail_service_with_region(self, service_factory):
        """Test getting CloudTrail service with region."""
        service = service_factory.get_service('cloudtrail', 'us-west-2')
        assert isinstance(service, CloudTrailService)
        assert service.region_name == 'us-west-2'
    
    def test_get_config_service_with_region(self, service_factory):
        """Test getting Config service with region."""
        service = service_factory.get_service('config', 'us-west-2')
        assert isinstance(service, ConfigService)
        assert service.region_name == 'us-west-2'
    
    def test_get_sts_service(self, service_factory):
        """Test getting STS service."""
        service = service_factory.get_service('sts')
        assert isinstance(service, STSService)
        assert service.region_name is None

    def test_get_ec2_service(self, service_factory):
        """Test getting EC2 service."""
        service = service_factory.get_service('ec2')
        assert isinstance(service, EC2Service)
        assert service.region_name is None

    def test_get_access_analyzer_service_with_region(self, service_factory):
        """Test getting AccessAnalyzer service with region."""
        service = service_factory.get_service('access_analyzer', 'us-west-2')
        assert isinstance(service, AccessAnalyzerService)
        assert service.region_name == 'us-west-2'
    
    def test_invalid_service_type(self, service_factory):
        """Test getting invalid service type."""
        with pytest.raises(ValueError) as exc_info:
            service_factory.get_service('invalid')
        assert str(exc_info.value) == 'Unsupported service type: invalid'
    
    def test_caching_global_service(self, service_factory):
        """Test caching behavior for global services."""
        service1 = service_factory.get_service('iam')
        service2 = service_factory.get_service('iam')
        assert service1 is service2
        assert 'global' in service_factory._service_cache
        assert 'iam' in service_factory._service_cache['global']
    
    def test_caching_regional_service(self, service_factory):
        """Test caching behavior for regional services."""
        service1 = service_factory.get_service('cloudtrail', 'us-west-2')
        service2 = service_factory.get_service('cloudtrail', 'us-west-2')
        assert service1 is service2
        assert 'us-west-2' in service_factory._service_cache
        assert 'cloudtrail' in service_factory._service_cache['us-west-2']
    
    def test_different_regions_different_instances(self, service_factory):
        """Test that different regions get different instances."""
        service1 = service_factory.get_service('cloudtrail', 'us-west-2')
        service2 = service_factory.get_service('cloudtrail', 'us-east-1')
        assert service1 is not service2
        assert service1.region_name == 'us-west-2'
        assert service2.region_name == 'us-east-1'

    def test_caching_ec2_service(self, service_factory):
        """Test caching behavior for EC2 service."""
        service1 = service_factory.get_service('ec2')
        service2 = service_factory.get_service('ec2')
        assert service1 is service2
        assert 'global' in service_factory._service_cache
        assert 'ec2' in service_factory._service_cache['global']

    def test_caching_access_analyzer_service(self, service_factory):
        """Test caching behavior for AccessAnalyzer service."""
        service1 = service_factory.get_service('access_analyzer', 'us-west-2')
        service2 = service_factory.get_service('access_analyzer', 'us-west-2')
        assert service1 is service2
        assert 'us-west-2' in service_factory._service_cache
        assert 'access_analyzer' in service_factory._service_cache['us-west-2']

class TestClearCache:
    """Tests for clear_cache method."""
    
    def test_clear_all(self, service_factory):
        """Test clearing entire cache."""
        service_factory.get_service('iam')
        service_factory.get_service('cloudtrail', 'us-west-2')
        service_factory.get_service('config', 'us-east-1')
        service_factory.get_service('ec2')
        service_factory.get_service('access_analyzer', 'us-west-2')
        
        service_factory.clear_cache()
        
        assert service_factory._service_cache == {}
    
    def test_clear_region(self, service_factory):
        """Test clearing cache for specific region."""
        iam = service_factory.get_service('iam')
        cloudtrail_west = service_factory.get_service('cloudtrail', 'us-west-2')
        cloudtrail_east = service_factory.get_service('cloudtrail', 'us-east-1')
        ec2 = service_factory.get_service('ec2')
        access_analyzer_west = service_factory.get_service('access_analyzer', 'us-west-2')
        
        service_factory.clear_cache(region='us-west-2')
        
        assert 'us-west-2' not in service_factory._service_cache
        assert 'global' in service_factory._service_cache
        assert 'us-east-1' in service_factory._service_cache
        
        # Global and other region services should remain cached
        assert service_factory.get_service('iam') is iam
        assert service_factory.get_service('ec2') is ec2
        assert service_factory.get_service('cloudtrail', 'us-east-1') is cloudtrail_east
        # New instance for cleared region
        assert service_factory.get_service('cloudtrail', 'us-west-2') is not cloudtrail_west
        assert service_factory.get_service('access_analyzer', 'us-west-2') is not access_analyzer_west
    
    def test_clear_service_type(self, service_factory):
        """Test clearing cache for specific service type."""
        iam = service_factory.get_service('iam')
        cloudtrail_west = service_factory.get_service('cloudtrail', 'us-west-2')
        cloudtrail_east = service_factory.get_service('cloudtrail', 'us-east-1')
        ec2 = service_factory.get_service('ec2')
        access_analyzer_west = service_factory.get_service('access_analyzer', 'us-west-2')
        
        service_factory.clear_cache(service_type='cloudtrail')
        
        # Other services should remain cached
        assert service_factory.get_service('iam') is iam
        assert service_factory.get_service('ec2') is ec2
        assert service_factory.get_service('access_analyzer', 'us-west-2') is access_analyzer_west
        # New instances for cleared service type
        assert service_factory.get_service('cloudtrail', 'us-west-2') is not cloudtrail_west
        assert service_factory.get_service('cloudtrail', 'us-east-1') is not cloudtrail_east
    
    def test_clear_specific_service_in_region(self, service_factory):
        """Test clearing specific service in specific region."""
        iam = service_factory.get_service('iam')
        cloudtrail_west = service_factory.get_service('cloudtrail', 'us-west-2')
        config_west = service_factory.get_service('config', 'us-west-2')
        cloudtrail_east = service_factory.get_service('cloudtrail', 'us-east-1')
        ec2 = service_factory.get_service('ec2')
        access_analyzer_west = service_factory.get_service('access_analyzer', 'us-west-2')
        
        service_factory.clear_cache(region='us-west-2', service_type='cloudtrail')
        
        # Only us-west-2 cloudtrail should be cleared
        assert service_factory.get_service('iam') is iam
        assert service_factory.get_service('ec2') is ec2
        assert service_factory.get_service('config', 'us-west-2') is config_west
        assert service_factory.get_service('cloudtrail', 'us-east-1') is cloudtrail_east
        assert service_factory.get_service('access_analyzer', 'us-west-2') is access_analyzer_west
        assert service_factory.get_service('cloudtrail', 'us-west-2') is not cloudtrail_west
