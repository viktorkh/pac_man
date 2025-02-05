from botocore.exceptions import ClientError

def get_trails(cloudtrail_client, logger):
    """
    Retrieve a list of all CloudTrail trails in the account.

    Args:
        cloudtrail_client: Boto3 CloudTrail client
        logger: Logger object for logging messages

    Returns:
        list: A list of dictionaries containing trail information.
    """
    try:
        response = cloudtrail_client.describe_trails()
        return response['trailList']
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f"Access Denied: {e}")
        else:
            logger.error(f"Error retrieving CloudTrail trails: {e}")
        return []

def enable_s3_object_logging(cloudtrail_client, trail_name, bucket_name, logger):
    """
    Enable S3 object-level logging for the specified trail and bucket.

    Args:
        cloudtrail_client: Boto3 CloudTrail client
        trail_name (str): The name of the CloudTrail trail.
        bucket_name (str): The name of the S3 bucket.
        logger: Logger object for logging messages

    Returns:
        bool: True if successful, False otherwise
    """
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    try:
        cloudtrail_client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "ReadOnly",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": "AWS::S3::Object",
                            "Values": [bucket_arn]
                        }
                    ]
                }
            ]
        )
        logger.info(f"S3 object-level logging enabled for bucket {bucket_arn} in trail {trail_name}.")
        return True
    except ClientError as e:
        logger.error(f"Error enabling S3 object-level logging for bucket {bucket_arn} in trail {trail_name}: {e}")
        return False

def execute(session, finding, logger):
    """
    Execute the fix for CIS 3.9 (Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket).

    Args:
        session (boto3.Session): The boto3 session to use for making AWS API calls.
        finding (CheckResult): The CheckResult object containing the finding details.
        logger: Logger object for logging messages.

    Returns:
        CheckResult: The updated CheckResult object after attempting the fix.
    """
    logger.info(f"Executing fix for {finding.check_id}")

    try:
        cloudtrail_client = session.client('cloudtrail')
        s3_client = session.client('s3')

        trails = get_trails(cloudtrail_client, logger)
        if not trails:
            finding.status = "FAIL"
            finding.status_extended = "No CloudTrail trails found or access denied."
            return finding

        bucket_name = finding.resource_id
        success = False

        for trail in trails:
            trail_name = trail['Name']
            if enable_s3_object_logging(cloudtrail_client, trail_name, bucket_name, logger):
                success = True
                break

        if success:
            finding.status = "PASS"
            finding.status_extended = f"Successfully enabled S3 object-level logging for bucket {bucket_name}."
        else:
            finding.status = "FAIL"
            finding.status_extended = f"Failed to enable S3 object-level logging for bucket {bucket_name} in any trail."

    except Exception as e:
        logger.error(f"An unexpected error occurred while fixing {finding.check_id}: {str(e)}")
        finding.status = "ERROR"
        finding.status_extended = f"An unexpected error occurred while attempting to fix: {str(e)}"

    return finding