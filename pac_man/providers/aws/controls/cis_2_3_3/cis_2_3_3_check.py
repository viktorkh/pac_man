from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_2_3_3"
CHECK_DESCRIPTION = "Ensure that public access is not given to RDS Instance"

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 2.3.3 check.
    Ensure that public access is not given to RDS Instance.

    Args:
        session: boto3 session
        logger: logging object
        service_factory: AWS service factory instance

    Returns:
        List[CheckResult]: List containing check results
    """
    ec2_service = service_factory.get_service('ec2')

    findings = []
    try:
        regions_response = ec2_service.list_active_regions()
        if not regions_response['success']:
            raise Exception(f"Error listing active regions: {regions_response.get('error_message')}")

        regions = regions_response['regions']
        for region in regions:
            logger.info(f"Checking RDS instances in {region}")

            # Get a new RDS service instance for each region
            rds_service = service_factory.get_service('rds', region)

            rds_instances_response = rds_service.describe_db_instances()

            logger.debug(f"RDS instances response: {rds_instances_response}")

            if not rds_instances_response:
                logger.info(f"No RDS instances found in region {region}")
                continue

            if isinstance(rds_instances_response, list):
                rds_instances = rds_instances_response
            elif isinstance(rds_instances_response, dict):
                rds_instances = rds_instances_response.get('DBInstances', [])
            else:
                logger.warning(f"Unexpected response type from RDS service in region {region}: {type(rds_instances_response)}")
                continue

            for instance in rds_instances:
                result = CheckResult()
                result.status = CheckResult.STATUS_PASS
                result.resource_id = instance.get('DBInstanceIdentifier', 'Unknown')
                result.resource_arn = instance.get('DBInstanceArn', 'Unknown')
                result.region = region
                result.check_id = CHECK_ID
                result.check_description = CHECK_DESCRIPTION

                if instance.get('PubliclyAccessible', False):
                    result.status = CheckResult.STATUS_FAIL
                    result.status_extended = f"RDS instance {result.resource_id} is publicly accessible"
                else:
                    result.status_extended = f"RDS instance {result.resource_id} is not publicly accessible"

                findings.append(result)

        if not findings:
            logger.info("No RDS instances found in any region")
            result = CheckResult()
            result.status = CheckResult.STATUS_PASS
            result.status_extended = "No RDS instances found in any region"
            result.check_id = CHECK_ID
            result.check_description = CHECK_DESCRIPTION
            findings.append(result)
    except Exception as e:
        logger.error(f"Error executing check {CHECK_ID}: {str(e)}")
        result = CheckResult()
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing check: {str(e)}"
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        findings.append(result)

    return findings

