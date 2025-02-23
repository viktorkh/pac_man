from pac_man.providers.aws.lib.check_result import CheckResult

def execute(session, finding, logger, service_factory):
    rds_service = service_factory.get_service('rds')
    db_instance_id = finding.resource_id

    try:
        # Describe the DB instance
        response = rds_service.describe_db_instances(DBInstanceIdentifier=db_instance_id)

        if not response or 'DBInstances' not in response or len(response['DBInstances']) == 0:
            result = CheckResult()
            result.set_status(CheckResult.STATUS_FAIL)
            result.status_extended = f"DB instance {db_instance_id} not found"
            result.resource_id = db_instance_id
            result.resource_arn = finding.resource_arn
            return result

        db_instance = response['DBInstances'][0]

        if not db_instance['PubliclyAccessible']:
            result = CheckResult()
            result.set_status(CheckResult.STATUS_PASS)
            result.status_extended = f"DB instance {db_instance_id} is already private"
            result.resource_id = db_instance_id
            result.resource_arn = finding.resource_arn
            return result

        # Modify the DB instance to make it private
        modify_response = rds_service.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            PubliclyAccessible=False
        )

        if modify_response.get('DBInstance', {}).get('PubliclyAccessible') is False:
            # Verify the change
            verify_response = rds_service.describe_db_instances(DBInstanceIdentifier=db_instance_id)
            if verify_response['DBInstances'][0]['PubliclyAccessible'] is False:
                result = CheckResult()
                result.set_status(CheckResult.STATUS_PASS)
                result.status_extended = f"Successfully made DB instance {db_instance_id} private"
                result.resource_id = db_instance_id
                result.resource_arn = finding.resource_arn
                return result
            else:
                result = CheckResult()
                result.set_status(CheckResult.STATUS_FAIL)
                result.status_extended = f"Failed to verify DB instance {db_instance_id} is private after modification"
                result.resource_id = db_instance_id
                result.resource_arn = finding.resource_arn
                return result
        else:
            result = CheckResult()
            result.set_status(CheckResult.STATUS_FAIL)
            result.status_extended = f"Failed to make DB instance {db_instance_id} private"
            result.resource_id = db_instance_id
            result.resource_arn = finding.resource_arn
            return result
    except Exception as e:
        logger.error(f"Error executing fix for CIS 2.3.3: {str(e)}")
        result = CheckResult()
        result.set_status(CheckResult.STATUS_ERROR)
        result.status_extended = f"Error executing fix for CIS 2.3.3: {str(e)}"
        result.resource_id = db_instance_id
        result.resource_arn = finding.resource_arn
        return result