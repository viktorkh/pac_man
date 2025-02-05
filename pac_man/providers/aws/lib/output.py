import json
import os
from datetime import datetime
from typing import List, Dict, Any
from colorama import Fore, Style, Back
from .check_result import CheckResult
from .remediation_result import RemediationResult

def format_overview_results(findings: List[CheckResult]) -> str:
    """
    Format findings into a user-friendly overview with colored bars and percentages.
    
    Args:
        findings: List of CheckResult objects
        
    Returns:
        Formatted string containing the overview results
    """
    # Count results by status
    total = len(findings)
    if total == 0:
        return "No findings to display"
    
    # For CIS 1.20, use the number of findings directly as total since each finding represents a region
    is_cis_1_20 = any(f.check_id == "cis_1_20" for f in findings)
    if is_cis_1_20:
        # Each finding represents a region check, so total should be the number of findings
        total = len([f for f in findings if f.status in ["PASS", "FAIL"]])
        
    counts = {
        "FAIL": len([f for f in findings if f.status == "FAIL"]),
        "PASS": len([f for f in findings if f.status == "PASS"]),
        "MUTED": len([f for f in findings if f.status == "MUTED"])
    }
    
    # Calculate percentages
    percentages = {
        status: (count / total * 100) if total > 0 else 0 
        for status, count in counts.items()
    }
    
    # Create the overview header
    result = f"\nAudit Results Overview:\n"
    
    # Create the status bar
    bar = "["
    
    # Add Failed section if there are any
    if counts["FAIL"] > 0:
        bar += f"{Back.RED}{Fore.WHITE} {percentages['FAIL']:.2f}% ({counts['FAIL']}) Risks Found {Style.RESET_ALL}"
        
    # Add Passed section if there are any
    if counts["PASS"] > 0:
        if counts["FAIL"] > 0:  # Add separator if needed
            bar += " | "
        bar += f"{Back.GREEN}{Fore.WHITE} {percentages['PASS']:.2f}% ({counts['PASS']}) Passed {Style.RESET_ALL}"
        
    # Add Muted section if there are any
    if counts["MUTED"] > 0:
        if counts["FAIL"] > 0 or counts["PASS"] > 0:  # Add separator if needed
            bar += " | "
        bar += f"{Back.YELLOW}{Fore.BLACK} {percentages['MUTED']:.2f}% ({counts['MUTED']}) Muted {Style.RESET_ALL}"
        
    bar += "]"
    
    return result + bar

def format_remediation_results(total_attempted: int, total_successful: int, total_failed: int) -> str:
    """
    Format remediation results into a user-friendly overview with colored bars and percentages.
    
    Args:
        total_attempted: Total number of remediation attempts
        total_successful: Number of successful remediations
        total_failed: Number of failed remediations
        
    Returns:
        Formatted string containing the remediation results overview
    """
    if total_attempted == 0:
        return "\nRemediation Results:\nNo remediation attempts to display"
        
    # Calculate percentages
    success_percent = (total_successful / total_attempted * 100) if total_attempted > 0 else 0
    failed_percent = (total_failed / total_attempted * 100) if total_attempted > 0 else 0
    
    # Create the overview header
    result = f"\nRemediation Results:\n"
    
    # Create the status bar
    bar = "["
    
    # Add Failed section if there are any
    if total_failed > 0:
        bar += f"{Back.RED}{Fore.WHITE} {failed_percent:.2f}% ({total_failed}) Failed {Style.RESET_ALL}"
        
    # Add Success section if there are any
    if total_successful > 0:
        if total_failed > 0:  # Add separator if needed
            bar += " | "
        bar += f"{Back.GREEN}{Fore.WHITE} {success_percent:.2f}% ({total_successful}) Successful {Style.RESET_ALL}"
    
    bar += "]"
    
    return result + bar

def get_findings_output(findings: List[CheckResult], logger) -> Dict[str, int]:
    """
    Extract findings statistics from a list of findings.
    
    Args:
        findings: List of CheckResult objects
        logger: Logger object for logging messages
        
    Returns:
        Dictionary containing aggregated statistics
    """
    logger.info("Extracting audit statistics...")
    stats = {}
    total_pass = 0
    total_fail = 0
    total_muted = 0
    resources = set()
    findings_count = 0

    for finding in findings:
        resources.add(finding.resource_id)
        
        if finding.status == "PASS":
            total_pass += 1
            findings_count += 1
        elif finding.status == "FAIL":
            total_fail += 1
            findings_count += 1
        elif finding.status == "MUTED":
            total_muted += 1

    stats["total_pass"] = total_pass
    stats["total_fail"] = total_fail
    stats["total_muted"] = total_muted
    stats["resources_count"] = len(resources)
    stats["findings_count"] = findings_count
    
    return stats

def export_remediation_to_json(findings: List[CheckResult], output_dir: str, logger) -> str:
    """
    Export remediation results to a JSON file in the specified output directory.
    
    Args:
        findings: List of CheckResult objects
        output_dir: Directory to save the JSON file
        logger: Logger object for logging messages
        
    Returns:
        Path to the created JSON file, or None if export fails
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"remediation_results_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        # Prepare data for JSON export
        export_data = {
            "timestamp": timestamp,
            "remediation_summary": {
                "total_attempted": 0,
                "total_successful": 0,
                "total_failed": 0,
                "not_attempted": 0,
                "muted": 0
            },
            "remediated_checks": {}
        }

        # Get findings with remediation attempts (both successful and failed)
        remediated_findings = [f for f in findings if f.remediation_result is not None]
        muted_findings = [f for f in findings if f.status == "MUTED"]
        
        # Update summary statistics
        export_data["remediation_summary"]["muted"] = len(muted_findings)
        
        # Count findings that needed remediation but weren't attempted
        failed_without_remediation = [f for f in findings if f.status == "FAIL" and f.remediation_result is None]
        export_data["remediation_summary"]["not_attempted"] = len(failed_without_remediation)
        
        for finding in remediated_findings:
            export_data["remediation_summary"]["total_attempted"] += 1
            if finding.remediation_result.status == "SUCCESS":
                export_data["remediation_summary"]["total_successful"] += 1
            elif finding.remediation_result.status == "FAILED":
                export_data["remediation_summary"]["total_failed"] += 1

            # Group findings by check_id
            if finding.check_id not in export_data["remediated_checks"]:
                export_data["remediated_checks"][finding.check_id] = {
                    "check_description": finding.check_description,
                    "remediation_attempts": []
                }

            # Add remediation details
            remediation_data = finding.remediation_result.to_dict()
            export_data["remediated_checks"][finding.check_id]["remediation_attempts"].append(remediation_data)

        # Format and print remediation results overview
        summary = export_data["remediation_summary"]
        print(format_remediation_results(
            summary["total_attempted"],
            summary["total_successful"],
            summary["total_failed"]
        ))

        # Write to JSON file
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Remediation results exported to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error exporting remediation results to JSON: {str(e)}")
        print(f"{Fore.RED}[FAILED] Error exporting remediation results to JSON: {str(e)}")
        return None

def export_to_json(findings: List[CheckResult], output_dir: str, logger) -> str:
    """
    Export findings to a JSON file in the specified output directory.
    
    Args:
        findings: List of CheckResult objects
        output_dir: Directory to save the JSON file
        logger: Logger object for logging messages
        
    Returns:
        Path to the created JSON file, or None if export fails
    """
    try:
        # Only validate obviously invalid paths (like UNC paths)
        if output_dir.startswith('\\\\'):
            raise ValueError(f"Invalid output directory path: {output_dir}")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_audit_results_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        # Prepare data for JSON export
        export_data = {
            "timestamp": timestamp,
            "summary": {
                "total_pass": len([f for f in findings if f.status == "PASS"]),
                "total_fail": len([f for f in findings if f.status == "FAIL"]),
                "total_muted": len([f for f in findings if f.status == "MUTED"]),
                "total_findings": len(findings)
            },
            "checks": {}
        }

        for finding in findings:
            finding_data = {
                "status": finding.status,
                "status_extended": finding.status_extended,
                "resource_id": finding.resource_id,
                "resource_arn": finding.resource_arn,
                "region": finding.region,
                "resource_details": finding.resource_details,
                "resource_tags": finding.resource_tags
            }
            
            # Add mute_reason if finding is muted
            if finding.status == "MUTED":
                finding_data["mute_reason"] = finding.mute_reason
                
            # Only add non-None and non-empty values
            finding_data = {k: v for k, v in finding_data.items() if v is not None and v != ""}

            # Group findings by check_id
            if finding.check_id not in export_data["checks"]:
                export_data["checks"][finding.check_id] = {
                    "check_description": finding.check_description,
                    "findings": {
                        "failed": [],
                        "passed": [],
                        "muted": []
                    }
                }
            
            # Add finding to appropriate status list
            if finding.status == "FAIL":
                export_data["checks"][finding.check_id]["findings"]["failed"].append(finding_data)
            elif finding.status == "PASS":
                export_data["checks"][finding.check_id]["findings"]["passed"].append(finding_data)
            elif finding.status == "MUTED":
                export_data["checks"][finding.check_id]["findings"]["muted"].append(finding_data)

        # Write to JSON file
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Results exported to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error exporting results to JSON: {str(e)}")
        print(f"{Fore.RED}[FAILED] Error exporting results to JSON: {str(e)}")
        return None
