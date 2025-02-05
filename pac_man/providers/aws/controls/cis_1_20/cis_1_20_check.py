"""CIS 1.20 - Ensure IAM Access Analyzer is enabled in all active regions."""

from typing import List
from providers.aws.lib.check_result import CheckResult

CHECK_ID = "cis_1_20"
CHECK_DESCRIPTION = "Ensure IAM Access Analyzer is enabled in all active regions"

def execute(session, logger, service_factory) -> List[CheckResult]:
    """
    Execute CIS 1.20 check.
    Check if IAM Access Analyzer is enabled in all active regions.
    
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
        
        # Store total regions checked for accurate percentage calculation
        total_regions = len(active_regions)
        
        # Check Access Analyzer status in each region
        for region in active_regions:
            try:
                # Initialize Access Analyzer service for the region
                access_analyzer_service = service_factory.get_service('access_analyzer', region)
                analyzers_response = access_analyzer_service.list_analyzers()
                
                # Initialize check result for this region
                result = CheckResult()
                result.check_id = CHECK_ID
                result.check_description = CHECK_DESCRIPTION
                result.region = region
                # Add total regions to resource_details for percentage calculation
                result.resource_details = {"total_regions": total_regions}
                
                if not analyzers_response['success']:
                    logger.error(f"Error checking analyzers in region {region}: {analyzers_response.get('error_message')}")
                    result.status = "ERROR"
                    result.status_extended = f"Error checking analyzers in region {region}: {analyzers_response.get('error_message')}"
                    findings.append(result)
                    continue
                
                analyzers = analyzers_response['analyzers']
                active_analyzer = next(
                    (analyzer for analyzer in analyzers if analyzer['status'] == 'ACTIVE'),
                    None
                )
                
                if active_analyzer:
                    result.status = "PASS"
                    result.resource_id = active_analyzer.get('name', 'N/A')
                    result.resource_arn = active_analyzer.get('arn', 'N/A')
                    result.resource_tags = active_analyzer.get('tags', [])
                    result.status_extended = f"IAM Access Analyzer {active_analyzer['name']} is enabled."
                    logger.info(f"Active analyzer found in region {region}: {active_analyzer['name']}")
                else:
                    result.status = "FAIL"
                    result.status_extended = f"No ACTIVE IAM Access Analyzer found in region {region}."
                    logger.warning(f"No active analyzer found in region {region}")
                
                findings.append(result)
                
            except Exception as e:
                logger.error(f"Error processing region {region}: {str(e)}")
                result = CheckResult()
                result.check_id = CHECK_ID
                result.check_description = CHECK_DESCRIPTION
                result.region = region
                result.status = "ERROR"
                result.status_extended = f"Error processing region {region}: {str(e)}"
                # Add total regions to resource_details for percentage calculation
                result.resource_details = {"total_regions": total_regions}
                findings.append(result)
        
        return findings
        
    except Exception as e:
        logger.error(f"Error executing CIS 1.20 check: {str(e)}")
        return [create_error_result(f"Error executing check: {str(e)}")]

def create_error_result(error_message: str) -> CheckResult:
    """Create an error check result."""
    result = CheckResult()
    result.check_id = CHECK_ID
    result.check_description = CHECK_DESCRIPTION
    result.status = "ERROR"
    result.status_extended = error_message
    return result
