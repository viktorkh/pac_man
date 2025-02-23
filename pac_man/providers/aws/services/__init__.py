"""AWS Services package for pac_man security audit tool.

This package provides abstracted interfaces to AWS services used in security auditing.
Each service module implements a consistent interface pattern defined by AWSServiceBase.

Available Services:
    - IAMService: Identity and Access Management operations
    - S3Service: Simple Storage Service operations
    - CloudTrailService: CloudTrail logging and audit operations
    - ConfigService: AWS Config resource monitoring operations
    - STSService: Security Token Service operations
    - MacieService: Amazon Macie operations

The ServiceFactory provides a centralized way to create and manage service instances:
    factory = AWSServiceFactory(session)
    iam_service = factory.get_service('iam')
"""

from .base import AWSServiceBase
from .iam_service import IAMService
from .s3_service import S3Service
from .cloudtrail_service import CloudTrailService
from .config_service import ConfigService
from .sts_service import STSService
from .macie_service import MacieService
from .service_factory import AWSServiceFactory
from .rds_service import RDSService

__all__ = [
    'AWSServiceBase',
    'IAMService',
    'S3Service',
    'CloudTrailService',
    'ConfigService',
    'STSService',
    'MacieService',
    'AWSServiceFactory',
    'RDSService'
]

