"""Fix implementation for CIS 3.9 control."""

import json
from botocore.exceptions import ClientError

from ...services.ec2_service import EC2Service
from ...services.iam_service import IAMService

def create_flow_log_role(iam_service, role_name):
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VPCFlowLogsAssumeRole",
                "Effect": "Allow",
                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        response = iam_service.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        if response['success']:
            return response['Role']['Arn']
        else:
            raise Exception(response['error_message'])
    except Exception as e:
        if 'EntityAlreadyExists' in str(e):
            # If the role already exists, try to get it
            get_role_response = iam_service.get_role(RoleName=role_name)
            if get_role_response['success']:
                return get_role_response['Role']['Arn']
            else:
                raise Exception(f"Failed to get existing role: {get_role_response['error_message']}")
        else:
            raise


def attach_flow_log_policy(iam_service, role_name):
    policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    iam_service.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

def create_log_group(logs_client, log_group_name):
    try:
        logs_client.create_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
            raise

def enable_flow_logging(ec2_service, vpc_id, log_group_name, role_arn):
    ec2_service.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType='VPC',
        TrafficType='REJECT',
        LogGroupName=log_group_name,
        DeliverLogsPermissionArn=role_arn,
    )

def execute(session, finding, logger, service_factory):
    """
    Execute the remediation for CIS 3.9 control by enabling VPC flow logging.

    This function attempts to create a VPC Flow Logs role and enable VPC flow logging
    for the specified VPC. It handles the process of creating the necessary IAM role
    and setting up the flow logs in CloudWatch.

    Args:
        session (boto3.Session): The boto3 session to use for AWS API calls.
        finding (Finding): The finding object containing information about the affected resource.
        logger (Logger): The logger object for logging messages.
        service_factory (ServiceFactory): A factory object for creating AWS service clients.

    Returns:
        Finding: The updated finding object with remediation results.

    Raises:
        Exception: If an error occurs during the remediation process, it's caught,
                   logged, and the finding is marked as failed.
    """
    ec2_service = service_factory.get_service('ec2')
    iam_service = service_factory.get_service('iam')

    vpc_id = finding.resource_id

    try:
        # Create or get the VPC Flow Logs role
        role_arn = create_flow_log_role(iam_service, 'VPCFlowLogsRole')

        # Enable VPC Flow Logs
        response = ec2_service.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType='VPC',
            TrafficType='ALL',
            LogDestinationType='cloud-watch-logs',
            DeliverLogsPermissionArn=role_arn,
            LogGroupName=f'/aws/vpc/flowlogs/{vpc_id}'
        )

        if response.get('success', False):
            success_message = f"VPC flow logging has been enabled for VPC {vpc_id}"
            finding.remediation_result.mark_as_success(details=success_message, current_state={"flow_logging_enabled": True})
            finding.status = "PASS"  # Update the finding status
            logger.info(f"Successfully enabled VPC flow logging for VPC {vpc_id}")
        else:
            error_message = response.get('error_message', 'Unknown error occurred')
            finding.remediation_result.mark_as_failed(error_message=error_message)
            finding.status = "FAIL"  # Update the finding status
            logger.error(f"Failed to enable VPC flow logging for VPC {vpc_id}: {error_message}")

    except Exception as e:
        error_message = f"An error occurred while enabling VPC flow logging: {str(e)}"
        finding.remediation_result.mark_as_failed(error_message=error_message)
        finding.status = "FAIL"  # Update the finding status
        logger.error(f"Error in CIS 3.9 fix for VPC {vpc_id}: {error_message}")

    return finding





