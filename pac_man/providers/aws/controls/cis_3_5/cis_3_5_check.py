"""CIS 3.5 - Ensure AWS Config is enabled in all regions."""

from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_3_5"
CHECK_DESCRIPTION = "Ensure AWS Config is enabled in all regions"

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 3.5 check.
    Check if AWS Config is enabled and properly configured in all regions.
    
    Args:
        session: boto3 session
        logger: logging object
        service_factory: AWS service factory instance
        
    Returns:
        List[CheckResult]: List containing check results
    """
    findings = []
    
    try:
        # Get list of active regions using EC2 service
        ec2_service = service_factory.get_service('ec2')
        regions_response = ec2_service.list_active_regions()
        
        if not regions_response['success']:
            logger.error(f"Error listing active regions: {regions_response.get('error_message')}")
            return [create_error_result(f"Error listing active regions: {regions_response.get('error_message')}")]
        
        active_regions = regions_response['regions']
        logger.info(f"Found {len(active_regions)} active regions")
        
        # Check Config status in each region
        for region in active_regions:
            try:
                # Initialize Config service for the region
                config_service = service_factory.get_service('config', region)
                
                # Get configuration recorders
                recorders_response = config_service.describe_configuration_recorders()
                if not recorders_response['success']:
                    logger.error(f"Error checking Config recorders in region {region}: {recorders_response.get('error_message')}")
                    findings.append(create_region_error_result(region, recorders_response.get('error_message')))
                    continue
                
                # Get configuration recorder status
                status_response = config_service.describe_configuration_recorder_status()
                if not status_response['success']:
                    logger.error(f"Error checking Config recorder status in region {region}: {status_response.get('error_message')}")
                    findings.append(create_region_error_result(region, status_response.get('error_message')))
                    continue
                
                # Initialize check result for this region
                result = CheckResult()
                result.check_id = CHECK_ID
                result.check_description = CHECK_DESCRIPTION
                result.region = region
                result.resource_id = f"AWS Config Recorder - {region}"
                result.resource_arn = f"arn:aws:config:{region}:{session.client('sts').get_caller_identity()['Account']}:config-recorder"
                
                recorders = recorders_response['configuration_recorders']
                if not recorders:
                    result.status = "FAIL"
                    result.status_extended = f"AWS Config recorder is not configured in {region}."
                    findings.append(result)
                    continue
                
                recorder = recorders[0]
                recorder_status = status_response['recorder_statuses'][0]
                
                # Check if Config is properly configured
                is_recording = recorder_status.get('recording', False)
                all_supported = recorder.get('recordingGroup', {}).get('allSupported', False)
                include_global = recorder.get('recordingGroup', {}).get('includeGlobalResourceTypes', False)
                last_status = recorder_status.get('lastStatus', 'Unknown')
                
                if is_recording and all_supported and include_global and last_status == 'SUCCESS':
                    result.status = "PASS"
                    result.status_extended = f"AWS Config recorder is properly configured in {region}."
                else:
                    result.status = "FAIL"
                    result.status_extended = (
                        f"AWS Config recorder is not properly configured in {region}. "
                        f"Recording: {is_recording}, All Supported: {all_supported}, "
                        f"Include Global Resources: {include_global}, "
                        f"Last Status: {last_status}"
                    )
                
                findings.append(result)
                
            except Exception as e:
                logger.error(f"Error processing region {region}: {str(e)}")
                findings.append(create_region_error_result(region, str(e)))
        
        return findings
        
    except Exception as e:
        logger.error(f"Error executing CIS 3.5 check: {str(e)}")
        return [create_error_result(f"Error executing check: {str(e)}")]

def create_error_result(error_message: str) -> CheckResult:
    """Create an error check result."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.status = "ERROR"
    result.status_extended = error_message
    return result

def create_region_error_result(region: str, error_message: str) -> CheckResult:
    """Create a region-specific error check result."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.status = "ERROR"
    result.region = region
    result.resource_id = f"AWS Config Recorder - {region}"
    result.status_extended = f"Error checking AWS Config in {region}: {error_message}"
    return result
