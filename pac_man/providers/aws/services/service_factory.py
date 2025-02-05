"""AWS Service Factory for managing service instances."""

from typing import Dict, Any, Optional
import boto3
from .base import AWSServiceBase
from .iam_service import IAMService
from .s3_service import S3Service
from .cloudtrail_service import CloudTrailService
from .config_service import ConfigService
from .sts_service import STSService
from .ec2_service import EC2Service
from .access_analyzer_service import AccessAnalyzerService
from .macie_service import MacieService 


class AWSServiceFactory:
    """Factory class for creating AWS service instances."""
    
    def __init__(self, session: boto3.Session):
        """
        Initialize the service factory.
        
        Args:
            session: Boto3 session to use for creating service clients
        """
        self.session = session
        self._service_cache: Dict[str, Dict[str, AWSServiceBase]] = {}
    
    def get_service(self, service_type: str, region: Optional[str] = None) -> AWSServiceBase:
        """
        Get a service instance for the specified service type and region.
        Uses cached instances when possible.
        
        Args:
            service_type: Type of service to create ('iam', 's3', 'cloudtrail', 'config', 'sts', 'ec2', 'access_analyzer')
            region: Optional region name for region-specific services
            
        Returns:
            Instance of the requested service
            
        Raises:
            ValueError: If the service type is not supported
        """
        # Use 'global' as key for services that don't need specific regions
        cache_key = region or 'global'
        
        # Initialize cache for this region if it doesn't exist
        if cache_key not in self._service_cache:
            self._service_cache[cache_key] = {}
            
        # Return cached instance if it exists
        if service_type in self._service_cache[cache_key]:
            return self._service_cache[cache_key][service_type]
        
        # Create new service instance
        service = self._create_service(service_type, region)
        
        # Cache the instance
        self._service_cache[cache_key][service_type] = service
        
        return service
    
    def _create_service(self, service_type: str, region: Optional[str] = None) -> AWSServiceBase:
        """
        Create a new service instance.
        
        Args:
            service_type: Type of service to create
            region: Optional region name for region-specific services
            
        Returns:
            New instance of the requested service
            
        Raises:
            ValueError: If the service type is not supported
        """
        service_map = {
            'iam': IAMService,
            's3': S3Service,
            'cloudtrail': CloudTrailService,
            'config': ConfigService,
            'sts': STSService,
            'ec2': EC2Service,
            'access_analyzer': AccessAnalyzerService,
            'macie' : MacieService
        }
        
        if service_type not in service_map:
            raise ValueError(f"Unsupported service type: {service_type}")
        
        service_class = service_map[service_type]
        return service_class(self.session, region)
    
    def clear_cache(self, region: Optional[str] = None, service_type: Optional[str] = None):
        """
        Clear the service cache.
        
        Args:
            region: Optional region to clear cache for. If None, clears all regions.
            service_type: Optional service type to clear. If None, clears all services.
        """
        if region:
            if service_type:
                # Clear specific service in specific region
                if region in self._service_cache and service_type in self._service_cache[region]:
                    del self._service_cache[region][service_type]
            else:
                # Clear all services in specific region
                if region in self._service_cache:
                    del self._service_cache[region]
        else:
            if service_type:
                # Clear specific service in all regions
                for region_cache in self._service_cache.values():
                    if service_type in region_cache:
                        del region_cache[service_type]
            else:
                # Clear entire cache
                self._service_cache = {}

# Example usage:
"""
# Create a factory with a session
session = boto3.Session()
factory = AWSServiceFactory(session)

# Get service instances
iam = factory.get_service('iam')  # Global service
s3 = factory.get_service('s3')    # Global service
sts = factory.get_service('sts')  # Global service
cloudtrail = factory.get_service('cloudtrail', 'us-west-2')  # Regional service
config = factory.get_service('config', 'us-west-2')          # Regional service
ec2 = factory.get_service('ec2')  # Global service for listing regions
access_analyzer = factory.get_service('access_analyzer', 'us-west-2')  # Regional service

# Service instances are cached and reused
same_iam = factory.get_service('iam')  # Returns the same instance

# Clear cache when needed
factory.clear_cache()  # Clear all
factory.clear_cache(region='us-west-2')  # Clear specific region
factory.clear_cache(service_type='iam')  # Clear specific service
"""
