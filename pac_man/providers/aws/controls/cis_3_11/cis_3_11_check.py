from providers.aws.lib.check_result import CheckResult
from botocore.exceptions import ClientError

CHECK_ID = "cis_3_11"
CHECK_DESCRIPTION = "Ensure that Object-level logging for read events is enabled for S3 bucket"

def get_trails(cloudtrail_client, logger):
    """Retrieve a list of all CloudTrail trails in the account."""
    try:
        response = cloudtrail_client.describe_trails()
        return response['trailList']
    except ClientError as e:
        logger.error(f"Error retrieving CloudTrail trails: {e}")
        return []

def get_event_selectors(cloudtrail_client, trail_name, logger):
    """Retrieve the event selectors for a specific CloudTrail trail."""
    try:
        response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
        return response.get('EventSelectors', [])
    except ClientError as e:
        logger.error(f"Error retrieving event selectors for trail {trail_name}: {e}")
        return []

def check_s3_logging(cloudtrail_client, s3_client, bucket_name, logger):
    """Check if S3 object-level logging is enabled for a specific bucket."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.resource_id = bucket_name
    result.resource_arn = f"arn:aws:s3:::{bucket_name}"
    result.region = s3_client.meta.region_name

    trails = get_trails(cloudtrail_client, logger)
    logging_enabled = False

    for trail in trails:
        trail_name = trail['Name']
        event_selectors = get_event_selectors(cloudtrail_client, trail_name, logger)

        for selector in event_selectors:
            if selector.get('DataResources'):
                for resource in selector['DataResources']:
                    if resource['Type'] == 'AWS::S3::Object' and result.resource_arn in resource['Values']:
                        if selector.get('ReadWriteType') in ['ReadOnly', 'All']:
                            logging_enabled = True
                            break
                if logging_enabled:
                    break
        if logging_enabled:
            break

    if logging_enabled:
        result.status = "PASS"
        result.status_extended = f"S3 object-level logging is enabled for bucket {bucket_name}."
    else:
        result.status = "FAIL"
        result.status_extended = f"S3 object-level logging is not enabled for bucket {bucket_name}."

    return result

def execute(session, logger):
    """Execute the CIS 3.9 check for S3 object-level logging."""
    logger.info("Executing CIS 3.9 check for S3 object-level logging")

    cloudtrail_client = session.client('cloudtrail')
    s3_client = session.client('s3')

    try:
        buckets = s3_client.list_buckets()['Buckets']
        findings = []

        for bucket in buckets:
            bucket_name = bucket['Name']
            result = check_s3_logging(cloudtrail_client, s3_client, bucket_name, logger)
            findings.append(result)

        return findings

    except Exception as e:
        logger.error(f"An error occurred during the CIS 3.9 check: {str(e)}")
        result = CheckResult()
        result.check_id = CHECK_ID
        result.check_description = CHECK_DESCRIPTION
        result.status = "ERROR"
        result.status_extended = f"An error occurred during the check: {str(e)}"
        result.resource_id = "S3Buckets"
        result.resource_arn = "arn:aws:s3:::*"
        result.region = "global"
        return [result]