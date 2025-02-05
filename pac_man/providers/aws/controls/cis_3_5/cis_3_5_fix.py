"""Fix for CIS 3.5 - Enable AWS Config in all regions."""

import uuid
import json
from typing import Tuple

def generate_unique_name(prefix: str) -> str:
    """Generate a unique name with the given prefix."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

def check_config_status(config_service, logger) -> bool:
    """
    Check the current status of AWS Config in the specified region.
    
    Args:
        config_service: AWS Config service instance
        logger: Logger object
        
    Returns:
        bool: True if Config is properly configured, False otherwise
    """
    try:
        recorders_response = config_service.describe_configuration_recorders()
        if not recorders_response['success']:
            logger.error(f"Error checking Config recorders: {recorders_response.get('error_message')}")
            return False
            
        status_response = config_service.describe_configuration_recorder_status()
        if not status_response['success']:
            logger.error(f"Error checking Config recorder status: {status_response.get('error_message')}")
            return False
        
        recorders = recorders_response['configuration_recorders']
        if not recorders:
            return False
        
        recorder = recorders[0]
        status = status_response['recorder_statuses'][0]
        
        return (status['recording'] and 
                recorder['recordingGroup'].get('allSupported', False) and
                recorder['recordingGroup'].get('includeGlobalResourceTypes', False) and
                status.get('lastStatus', '') == 'SUCCESS')
                
    except Exception as e:
        logger.error(f"Error checking Config status: {str(e)}")
        return False

def create_config_prerequisites(service_factory, region: str, logger) -> Tuple[str, str, str]:
    """
    Create prerequisites for AWS Config: S3 bucket, SNS topic, and IAM role.
    
    Args:
        service_factory: AWS service factory instance
        region: AWS region
        logger: Logger object
        
    Returns:
        Tuple[str, str, str]: Tuple containing bucket name, topic ARN, and role ARN
        
    Raises:
        Exception: If any prerequisite creation fails
    """
    s3_service = service_factory.get_service('s3', region)
    iam_service = service_factory.get_service('iam')
    sts_service = service_factory.get_service('sts')
    sns_client = service_factory.session.client('sns', region_name=region)  # Using boto3 client for SNS

    # Get account ID
    account_response = sts_service.get_caller_identity()
    if not account_response['success']:
        error_msg = f"Failed to get account ID: {account_response.get('error_message')}"
        logger.error(error_msg)
        raise Exception(error_msg)
    account_id = account_response['account_id']

    bucket_name = generate_unique_name(f"config-bucket-{account_id}")
    topic_name = generate_unique_name("config-topic")

    # Create S3 bucket
    bucket_config = {'LocationConstraint': region} if region != 'us-east-1' else None
    bucket_response = s3_service.create_bucket(bucket_name, bucket_config)
    if not bucket_response['success']:
        error_msg = bucket_response.get('error_message', 'Unknown error')
        if 'BucketAlreadyExists' not in str(error_msg):
            logger.error(f"Failed to create S3 bucket: {error_msg}")
            raise Exception(f"Failed to create bucket: {error_msg}")
        logger.info(f"S3 bucket already exists: {bucket_name}")
    else:
        logger.info(f"Created S3 bucket: {bucket_name}")

    # Create SNS topic
    try:
        topic_arn = sns_client.create_topic(Name=topic_name)['TopicArn']
        logger.info(f"Created SNS topic: {topic_arn}")
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Failed to create SNS topic: {error_msg}")
        raise Exception(f"Failed to create SNS topic: {error_msg}")

    # Create IAM role
    role_name = 'AWSConfigRole'
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "config.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    role_response = iam_service.create_role(
        role_name=role_name,
        assume_role_policy_document=json.dumps(assume_role_policy)
    )
    
    if not role_response['success']:
        error_msg = role_response.get('error_message', 'Unknown error')
        if 'EntityAlreadyExists' not in str(error_msg):
            logger.error(f"Failed to create IAM role: {error_msg}")
            raise Exception(f"Failed to create IAM role: {error_msg}")
        role_response = iam_service.get_role(role_name)
        if not role_response['success']:
            error_msg = role_response.get('error_message', 'Unknown error')
            logger.error(f"Failed to get existing IAM role: {error_msg}")
            raise Exception(f"Failed to get existing IAM role: {error_msg}")
        logger.info(f"IAM role already exists: {role_name}")
    else:
        logger.info(f"Created IAM role: {role_name}")

    # Attach necessary policies to the role
    policy_response = iam_service.attach_role_policy(
        role_name=role_name,
        policy_arn='arn:aws:iam::aws:policy/service-role/AWSConfigRole'
    )
    if not policy_response['success']:
        error_msg = policy_response.get('error_message', 'Unknown error')
        logger.error(f"Failed to attach policy to IAM role: {error_msg}")
        raise Exception(f"Failed to attach policy to IAM role: {error_msg}")

    return bucket_name, topic_arn, role_response['role']['Arn']

def configure_aws_config(config_service, bucket_name: str, topic_arn: str, role_arn: str, logger) -> Tuple[bool, str]:
    """
    Configure AWS Config in the specified region.
    
    Args:
        config_service: AWS Config service instance
        bucket_name: Name of the S3 bucket for Config
        topic_arn: ARN of the SNS topic
        role_arn: ARN of the IAM role
        logger: Logger object
        
    Returns:
        Tuple[bool, str]: Success status and error message if any
    """
    try:
        # Create configuration recorder
        recorder_config = {
            'name': 'default',
            'roleARN': role_arn,
            'recordingGroup': {
                'allSupported': True,
                'includeGlobalResourceTypes': True
            }
        }
        recorder_response = config_service.put_configuration_recorder(recorder_config)
        if not recorder_response['success']:
            error_msg = recorder_response.get('error_message', 'Unknown error')
            logger.error(f"Failed to create configuration recorder: {error_msg}")
            return False, f"Failed to create configuration recorder: {error_msg}"

        # Create delivery channel
        channel_config = {
            "name": "default",
            "s3BucketName": bucket_name,
            "snsTopicARN": topic_arn,
            "configSnapshotDeliveryProperties": {
                "deliveryFrequency": "Twelve_Hours"
            }
        }
        channel_response = config_service.put_delivery_channel(channel_config)
        if not channel_response['success']:
            error_msg = channel_response.get('error_message', 'Unknown error')
            logger.error(f"Failed to create delivery channel: {error_msg}")
            return False, f"Failed to create delivery channel: {error_msg}"

        # Start configuration recorder
        start_response = config_service.start_configuration_recorder('default')
        if not start_response['success']:
            error_msg = start_response.get('error_message', 'Unknown error')
            logger.error(f"Failed to start configuration recorder: {error_msg}")
            return False, f"Failed to start configuration recorder: {error_msg}"

        logger.info("Successfully configured AWS Config")
        return True, ""
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error configuring AWS Config: {error_msg}")
        return False, error_msg

def execute(session, finding, logger, service_factory):
    """
    Execute the fix for CIS 3.5 (Ensure AWS Config is enabled in all regions).

    Args:
        session: boto3 session
        finding: The finding object containing the finding details
        logger: Logger object
        service_factory: AWS service factory instance

    Returns:
        finding: The updated finding object with fix results
    """
    logger.info(f"Executing fix for {finding.check_id}")

    # Initialize remediation tracking
    remediation = finding.init_remediation()
    remediation.provider = "aws"
    remediation.region = finding.region

    try:
        region = finding.region
        config_service = service_factory.get_service('config', region)

        if check_config_status(config_service, logger):
            finding.status = "PASS"
            finding.status_extended = f"AWS Config is already properly configured in region {region}"
            remediation.mark_as_success(
                details=f"AWS Config is already properly configured in region {region}",
                current_state={"status": "PASS"}
            )
        else:
            logger.info(f"Configuring AWS Config in region: {region}")
            try:
                bucket_name, topic_arn, role_arn = create_config_prerequisites(service_factory, region, logger)
                success, error_msg = configure_aws_config(config_service, bucket_name, topic_arn, role_arn, logger)
                
                if success:
                    finding.status = "PASS"
                    finding.status_extended = f"Successfully configured AWS Config in region {region}"
                    remediation.mark_as_success(
                        details=f"Successfully configured AWS Config in region {region}",
                        current_state={
                            "status": "PASS",
                            "bucket_name": bucket_name,
                            "topic_arn": topic_arn,
                            "role_arn": role_arn
                        }
                    )
                else:
                    finding.status_extended = error_msg
                    remediation.mark_as_failed(
                        error_message=error_msg,
                        details=f"Failed to configure AWS Config in region {region}"
                    )
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Failed during AWS Config setup: {error_msg}")
                finding.status_extended = error_msg
                remediation.mark_as_failed(
                    error_message=error_msg,
                    details=f"Failed to configure AWS Config in region {region}"
                )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"An unexpected error occurred while fixing {finding.check_id}: {error_msg}")
        finding.status_extended = f"Fix attempt failed: {error_msg}"
        remediation.mark_as_failed(
            error_message=error_msg,
            details=f"Exception occurred while configuring AWS Config in region {finding.region}"
        )

    return finding
