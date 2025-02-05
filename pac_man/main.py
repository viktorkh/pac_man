import sys
import os
import logging
from config import Config
from datetime import datetime
from providers import get_provider
from colorama import init, Fore, Style
from providers.aws.lib.output import get_findings_output, export_to_json, export_remediation_to_json, format_overview_results
from utils.json_logger import setup_json_logging

# Initialize colorama
init(autoreset=True)

# Define the default output directory
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output')

def setup_logging(log_level, log_file=None):
    """
    Configure the logging settings.
    
    Args:
        log_level (str): The logging level to use (debug, info, warning, error, critical)
        log_file (str, optional): Path to the log file. If provided, logs will be written in JSON format
        
    Returns:
        logging.Logger: Configured logger instance
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Set up basic logging configuration for console output
    logging.basicConfig(level=log_level, format=log_format)
    
    # Get the logger instance
    logger = logging.getLogger(__name__)
    
    # If log file is specified, set up JSON logging
    if log_file:
        setup_json_logging(logger, log_file, log_level)
    
    return logger

def print_aws_credentials_info(provider, logger):
    """Print AWS credentials information in a formatted way."""
    try:
        sts = provider.session.client('sts')
        identity = sts.get_caller_identity()
        
        # Print date header
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Fore.CYAN}Date:{Style.RESET_ALL} {current_time}\n")
        
        # Print AWS credentials information
        print(f"{Fore.CYAN}-> Using the AWS credentials below:{Style.RESET_ALL}")
        print(f"  · {Fore.CYAN}AWS-CLI Profile:{Style.RESET_ALL} {provider.profile or 'default'}")
        print(f"  · {Fore.CYAN}AWS Regions:{Style.RESET_ALL} {provider.region}")
        print(f"  · {Fore.CYAN}AWS Account:{Style.RESET_ALL} {identity['Account']}")
        print(f"  · {Fore.CYAN}User Id:{Style.RESET_ALL} {identity['UserId']}")
        print(f"  · {Fore.CYAN}Caller Identity ARN:{Style.RESET_ALL} {identity['Arn']}\n")
        
        logger.info(f"AWS credentials info displayed for account {identity['Account']}")
    except Exception as e:
        logger.error(f"Error getting AWS credentials info: {str(e)}")
        print(f"{Fore.RED}[FAILED] Error getting AWS credentials info: {str(e)}")

def print_progress(message, status, logger):
    """Print a progress message with color-coded status and log it."""
    if status == 'start':
        print(f"{Fore.CYAN}[STARTING] {message}")
        logger.info(f"STARTING: {message}")
    elif status == 'success':
        print(f"{Fore.GREEN}[SUCCESS] {message}")
        logger.info(f"SUCCESS: {message}")
    elif status == 'fail':
        print(f"{Fore.RED}[FAILED] {message}")
        logger.error(f"FAILED: {message}")
    elif status == 'warning':
        print(f"{Fore.YELLOW}[WARNING] {message}")
        logger.warning(f"WARNING: {message}")
    else:
        print(f"{Fore.WHITE}[INFO] {message}")
        logger.info(f"INFO: {message}")

def fix_prompt() -> bool:
    try:
        user_input = input("\nApply fixes? (y/n): ").strip().lower()
        return user_input[0] == "y"
    except (KeyboardInterrupt, EOFError):
        print("Aborting...")
        return False

def main():
    """Main function that orchestrates the execution flow."""
    config = Config.from_args()

    # Setup logging
    logger = setup_logging(config.log_level, config.log_file)

    # Get the appropriate provider (AWS or GCP)
    try:
        region = config.regions[0] if config.regions else None # TODO: support multiple regions
        provider = get_provider(config.provider, config.profile, region)
    except ValueError as e:
        logger.error(f"Failed to initialize {config.provider} provider: {str(e)}")
        sys.exit(1)

    # Authenticate the provider
    try:
        provider.authenticate(logger)
        if config.provider.lower() == 'aws':
            print_aws_credentials_info(provider, logger)
    except Exception as e:
        print_progress(f"Authentication failed: {str(e)}", 'fail', logger)
        logger.error(f"Authentication failed: {str(e)}")
        sys.exit(1)

    # Load and execute checks
    checks_to_execute = provider.load_checks(checks=config.checks, logger=logger)

    try:
        # Execute checks
        findings = provider.execute_checks(checks_to_execute, logger)

        # Display formatted audit results
        print(format_overview_results(findings))

        # Get and store statistics
        stats = get_findings_output(findings, logger)

        # Export results to JSON
        json_filepath = export_to_json(findings, DEFAULT_OUTPUT_DIR, logger)
        if json_filepath:
            print(f"\nDetailed results have been exported to: {json_filepath}")

        # If fix request isn't explicitly set, prompt user
        if config.apply_fix is not None:
            fix = config.apply_fix
        elif any(finding.status == "FAIL" for finding in findings):
            fix = fix_prompt()
        else:
            fix = False

        # Check if fix is requested and there are any failures
        if fix and any(finding.status == "FAIL" for finding in findings):
            provider.execute_fixers(findings, logger)

            # Export remediation results to JSON
            remediation_filepath = export_remediation_to_json(findings, DEFAULT_OUTPUT_DIR, logger)
            if remediation_filepath:
                print(f"\nDetailed remediation results have been exported to: {remediation_filepath}")
                
                # Print summary of remediation results
                # failed_findings = [f for f in findings if f.status == "FAIL"]
                # successful_remediations = len([f for f in failed_findings if getattr(f, 'remediation_status', '') == 'SUCCESS'])
                # print(f"\nRemediation Summary:")
                # print(f"Total fixes attempted: {len(failed_findings)}")
                # print(f"Successful fixes: {successful_remediations}")
                # print(f"Failed fixes: {len(failed_findings) - successful_remediations}")
           
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")


if __name__ == "__main__":
    main()
