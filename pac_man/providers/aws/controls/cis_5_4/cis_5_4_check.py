from typing import List
from providers.aws.lib.check_result import CheckResult

# Constants
CHECK_ID = "cis_5_4"
CHECK_DESCRIPTION = "Ensure the default security group of every VPC restricts all traffic"

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 5.4 check.
    Ensure the default security group of every VPC restricts all traffic.

    Args:
        session: boto3 session
        logger: logging object
        service_factory: AWS service factory instance

    Returns:
        List[CheckResult]: List containing check results
    """
    # Initialize services using the factory
    ec2_service = service_factory.get_service('ec2')
    sts_service = service_factory.get_service('sts')

    findings = []
    try:
        # Get account ID
        logger.info("Attempting to get caller identity...")
        identity_response = sts_service.get_caller_identity()
        if not identity_response['success']:
            raise ValueError(f"Failed to get AWS Account ID: {identity_response.get('error_message', 'Unknown error')}")
        
        account_id = identity_response['account_id']
        logger.info(f"Successfully retrieved account ID: {account_id}")
        
        # Get all VPCs
        vpcs_response = ec2_service.describe_vpcs()
        if not vpcs_response['success']:
            raise ValueError(f"Failed to describe VPCs: {vpcs_response.get('error_message', 'Unknown error')}")

        vpcs = vpcs_response.get('Vpcs', [])

        if not vpcs:
            logger.warning("No VPCs found in the account.")
            result = CheckResult()
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            result.resource_id = "NoVPCs"
            result.resource_arn = f"arn:aws:ec2:{session.region_name}:{account_id}:vpc/*"
            result.region = session.region_name
            result.status = CheckResult.STATUS_PASS
            result.status_extended = "No VPCs found in the account, check is not applicable."
            findings.append(result)
            return findings

        for vpc in vpcs:
            vpc_id = vpc['VpcId']

            # Get the default security group for this VPC
            sg_response = ec2_service.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'group-name', 'Values': ['default']}
                ]
            )
            if not sg_response['success']:
                raise ValueError(f"Failed to describe security groups for VPC {vpc_id}: {sg_response.get('error_message', 'Unknown error')}")

            default_sg = sg_response.get('SecurityGroups', [])[0] if sg_response.get('SecurityGroups') else None

            if default_sg:
                result = CheckResult()
                result.check_id = CHECK_ID
                result.check_description = CHECK_DESCRIPTION
                result.resource_id = default_sg['GroupId']
                result.resource_arn = f"arn:aws:ec2:{session.region_name}:{account_id}:security-group/{default_sg['GroupId']}"
                result.region = session.region_name
                result.resource_tags = default_sg.get('Tags', [])

                if default_sg.get('IpPermissions') or default_sg.get('IpPermissionsEgress'):
                    result.status = CheckResult.STATUS_FAIL
                    result.status_extended = f"Default security group {default_sg['GroupId']} for VPC {vpc_id} has inbound or outbound rules."
                else:
                    result.status = CheckResult.STATUS_PASS
                    result.status_extended = f"Default security group {default_sg['GroupId']} for VPC {vpc_id} restricts all traffic."

                findings.append(result)
            else:
                logger.warning(f"No default security group found for VPC {vpc_id}")

    except Exception as e:
        logger.error(f"Error executing CIS 5.4 check: {str(e)}")
        result = CheckResult()
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        result.resource_id = "AllVPCs"
        result.resource_arn = f"arn:aws:ec2:{session.region_name}:*:vpc/*"  # Use wildcard for account ID
        result.region = session.region_name
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
        findings.append(result)

    return findings

