from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_3_9"
CHECK_DESCRIPTION = "Ensure VPC flow logging is enabled in all VPCs"

def check_vpc_flow_logging(ec2_service, vpc_id, logger) -> CheckResult:
    """Check if VPC flow logging is enabled for a specific VPC."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.resource_id = vpc_id
    result.resource_arn = f"arn:aws:ec2:*:*:vpc/{vpc_id}"

    try:
        flow_logs = ec2_service.describe_flow_logs(
            Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
        )
        if flow_logs['success'] and flow_logs['FlowLogs']:
            result.status = CheckResult.STATUS_PASS
            result.status_extended = f"VPC flow logging is enabled for VPC {vpc_id}."
        else:
            result.status = CheckResult.STATUS_FAIL
            result.status_extended = f"VPC flow logging is not enabled for VPC {vpc_id}."
    except Exception as e:
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error checking VPC flow logging for VPC {vpc_id}: {str(e)}"
        logger.error(f"Error in check_vpc_flow_logging: {str(e)}")

    return result


def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute the CIS 3.9 check for VPC flow logging.

    Args:
        session: boto3 session
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        List[CheckResult]: List containing check results
    """
    logger.info("Executing CIS 3.9 check for VPC flow logging")

    # Initialize services using the factory
    ec2_service = service_factory.get_service('ec2')

    try:
        # Get all VPCs
        vpcs_response = ec2_service.describe_vpcs()
        if not vpcs_response['success']:
            logger.error(f"Error describing VPCs: {vpcs_response['error_message']}")
            return [
                CheckResult(
                    check_id=CHECK_ID,
                    check_description=CHECK_DESCRIPTION,
                    resource_id="AllVPCs",
                    resource_arn="arn:aws:ec2:*:*:vpc/*"
                ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                    f"Unable to retrieve VPCs: {vpcs_response['error_message']}"
                )
            ]

        results = []
        for vpc in vpcs_response.get('Vpcs', []):
            vpc_id = vpc['VpcId']
            result = check_vpc_flow_logging(ec2_service, vpc_id, logger)
            results.append(result)

        return results

    except Exception as e:
        logger.error(f"Error executing CIS 3.9 check: {str(e)}")
        return [
            CheckResult(
                check_id=CHECK_ID,
                check_description=CHECK_DESCRIPTION,
                resource_id="AllVPCs",
                resource_arn="arn:aws:ec2:*:*:vpc/*"
            ).set_status(CheckResult.STATUS_ERROR).set_status_extended(
                f"Error executing CIS 3.9 check: {str(e)}"
            )
        ]