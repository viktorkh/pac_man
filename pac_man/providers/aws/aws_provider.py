"""AWS-specific implementation of the Provider class."""

import json
import boto3
import importlib
from typing import List, Dict, Any, Optional
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from providers.provider import Provider
from colorama import Fore, Style
from halo import Halo
from .lib.whitelist import initialize_whitelist
from .services import AWSServiceFactory

class AWSProvider(Provider):
    """AWS-specific implementation of the Provider class."""

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None, whitelist_file: Optional[str] = None):
        """
        Initialize the AWS provider with a specific AWS region and profile.
        If no region is provided, use the default region "il-central-1".
        If no profile is provided, default profile is used.
        
        Args:
            region: AWS region (e.g., 'il-central-1')
            profile: AWS profile to use (optional)
            whitelist_file: Path to custom whitelist YAML file (optional)
        """
        self.session = None
        self.profile = profile
        # Use il-central-1 as default if no region provided
        self.region = region if region else 'il-central-1'
        super().__init__(name='aws', region=self.region)
        self.checks = None
        self.service_factory = None

        # Initialize whitelist with custom file if provided
        try:
            initialize_whitelist(whitelist_file)            
            if whitelist_file:
                print(f"{Fore.GREEN}[SUCCESS] Using custom whitelist: {whitelist_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[SUCCESS] Using default AWS whitelist{Style.RESET_ALL}")
        except Exception as e:
            
            print(f"{Fore.RED}[FAILED] Error initializing whitelist: {str(e)}{Style.RESET_ALL}")
            raise

    def authenticate(self, logger):
        """Authenticate to AWS using Boto3. Uses specified profile or default credentials."""
        try:
            if self.profile:
                self.session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                self.session = boto3.Session(region_name=self.region)
            
            # Initialize service factory after session is created
            self.service_factory = AWSServiceFactory(self.session)
            
            # Use STS service to verify credentials
            sts_service = self.service_factory.get_service('sts')
            identity_response = sts_service.get_caller_identity()
            
            if not identity_response['success']:    
                raise Exception(identity_response.get('error_message', 'Failed to get caller identity'))
            
            logger.info(f"Authenticated as {identity_response['arn']} in region {self.region} using profile {self.profile or 'default'}")
            
        except NoCredentialsError:
            logger.error("AWS credentials not found.")
            print(f"{Fore.RED}[FAILED] AWS credentials not found.{Style.RESET_ALL}")
            raise
        except PartialCredentialsError:
            logger.error("Incomplete AWS credentials provided.")
            print(f"{Fore.RED}[FAILED] Incomplete AWS credentials provided.{Style.RESET_ALL}")
            raise
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            print(f"{Fore.RED}[FAILED] Authentication failed: {str(e)}{Style.RESET_ALL}")
            raise

    def load_checks(self, checks=None, logger=None):
        """Load AWS-specific security checks based on available services."""
        all_checks = self.get_checks(logger)
        
        if checks:
            logger.info("Loading specific security checks...")
            print(f"{Fore.CYAN}[STARTING] Loading specific security checks...{Style.RESET_ALL}")
            checks_to_execute = []
            for check_name in checks:
                if check_name in [check['id'] for check in all_checks]:
                    checks_to_execute.append(check_name)
                else:
                    logger.warning(f"Check '{check_name}' not found in available checks.")
                    print(f"{Fore.YELLOW}[WARNING] Check '{check_name}' not found in available checks.{Style.RESET_ALL}")
        else:
            logger.info("Loading all available security checks...")
            print(f"{Fore.CYAN}[STARTING] Loading all available security checks...{Style.RESET_ALL}")
            checks_to_execute = [check['id'] for check in all_checks]

        logger.info(f"Loaded {len(checks_to_execute)} security checks.")
        print(f"{Fore.GREEN}[SUCCESS] Loaded {len(checks_to_execute)} security checks.{Style.RESET_ALL}")

        return checks_to_execute

    def get_checks(self, logger):
        """Load AWS CIS controls from the provided JSON file."""
        try:
            with open('providers/aws/config/cis_controls.json', 'r') as f:
                return json.load(f)['controls']
        except FileNotFoundError:
            logger.critical("The 'cis_controls.json' file is missing.")
            print(f"{Fore.RED}[FAILED] The 'cis_controls.json' file is missing.{Style.RESET_ALL}")
            raise FileNotFoundError("The 'cis_controls.json' file is missing.")
        except json.JSONDecodeError:
            logger.critical("Error parsing 'cis_controls.json'.")
            print(f"{Fore.RED}[FAILED] Error parsing 'cis_controls.json'.{Style.RESET_ALL}")
            raise ValueError("Error parsing 'cis_controls.json'.")
    def _get_check_info(self, check_id):
        """Helper method to get check information from JSON file."""
        try:
            # Construct the path to the check's JSON file
            json_file_path = f'providers/aws/controls/{check_id}/{check_id}.json'
            with open(json_file_path, 'r') as f:
                check_info = json.load(f)
                return check_info.get('id', ''), check_info.get('title', '')
        except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
            return check_id, ''
        
    def execute_checks(self, checks_to_execute, logger):
        """Execute AWS-specific security checks."""
        logger.info("Executing AWS security checks...")
        print(f"{Fore.CYAN}[STARTING] Executing AWS security checks...{Style.RESET_ALL}")
        all_findings = []

        for check in checks_to_execute:
            # Get check details from JSON
            check_id, check_title = self._get_check_info(check)
            check_description = f"CIS {check_id}: {check_title}" if check_title else check
            
            logger.info(f"Running check: {check_description}")
            print(f"{Fore.CYAN}[STARTING] Running check: {check_description}{Style.RESET_ALL}")
            
            spinner = Halo(text=f'Processing {check_description}', spinner='line')
            spinner.start()
            
            try:
                import_path = f"providers.aws.controls.{check}.{check}_check"
                check_module = importlib.import_module(import_path)
                check_findings = check_module.execute(self.session, logger, self.service_factory)
                spinner.stop()
                logger.info(f"Completed check: {check_description}")
                print(f"{Fore.GREEN}[SUCCESS] Completed check {Style.RESET_ALL}")
                
                logger.debug(f"Findings for check {check_description}: {check_findings}")
                all_findings.extend(check_findings)

            except ImportError as ie:
                spinner.stop()
                logger.error(f"Error: Check module '{check}' not found. Details: {str(ie)}")
                print(f"{Fore.RED}[FAILED] Error: Check module '{check}' not found. Details: {str(ie)}{Style.RESET_ALL}")
            except AttributeError as ae:
                spinner.stop()
                logger.error(f"Error: Check module '{check}' does not have the required function. Details: {str(ae)}")
                print(f"{Fore.RED}[FAILED] Error: Check module '{check}' does not have the required function. Details: {str(ae)}{Style.RESET_ALL}")
            except Exception as e:
                spinner.stop()
                logger.error(f"Error executing check '{check_description}': {str(e)}")
                print(f"{Fore.RED}[FAILED] Error executing check '{check_description}': {str(e)}{Style.RESET_ALL}")
            finally:
                if spinner.spinner_id:
                    spinner.stop()

        logger.info("Completed all AWS security checks.")
        print(f"{Fore.GREEN}[SUCCESS] Completed all AWS security checks.{Style.RESET_ALL}")
        return all_findings

    def execute_fixers(self, findings, logger):
        """Execute fixers for failed checks."""
        logger.info("Executing AWS security check fixers...")
        print(f"{Fore.CYAN}[STARTING] Executing AWS security check fixers...{Style.RESET_ALL}")
        
        # Filter findings that need remediation
        findings_to_fix = [f for f in findings if f.needs_remediation()]
        
        for finding in findings_to_fix:
            # Get check details from JSON
            check_id, check_title = self._get_check_info(finding.check_id)
            check_description = f"CIS {check_id}: {check_title}" if check_title else finding.check_id
            
            logger.info(f"Attempting to fix: {check_description}")
            print(f"{Fore.YELLOW}[FIXING] Attempting to fix: {check_description}{Style.RESET_ALL}")
            
            spinner = Halo(text=f'Applying fix for {check_description}', spinner='line')
            spinner.start()
            
            # Initialize remediation result
            remediation = finding.init_remediation()
            remediation.provider = "aws"
            
            try:
                import_path = f"providers.aws.controls.{finding.check_id}.{finding.check_id}_fix"
                fixer_module = importlib.import_module(import_path)
                updated_finding = fixer_module.execute(self.session, finding, logger, self.service_factory)
                
                # Update finding status
                finding.status = updated_finding.status
                finding.status_extended = updated_finding.status_extended
                
                spinner.stop()
                
                # Update remediation result
                if updated_finding.status == "PASS":
                    logger.info(f"Fix successful for: {check_description}")
                    print(f"{Fore.GREEN}[SUCCESS] Fix successful for: {check_description}{Style.RESET_ALL}")
                    remediation.mark_as_success(
                        details=finding.status_extended,
                        current_state={"status": "PASS", "details": finding.status_extended}
                    )
                else:
                    logger.error(f"Fix attempt failed for: {check_description}")
                    print(f"{Fore.RED}[FAILED] Fix attempt failed for: {check_description}{Style.RESET_ALL}")
                    print(f"{Fore.RED}Details: {finding.status_extended}{Style.RESET_ALL}")
                    remediation.mark_as_failed(
                        error_message=finding.status_extended,
                        details=f"Fix attempt failed for {check_description}"
                    )

            except ImportError as ie:
                spinner.stop()
                error_msg = f"Error: Fixer module for '{check_description}' not found. Details: {str(ie)}"
                logger.error(error_msg)
                print(f"{Fore.RED}[FAILED] {error_msg}{Style.RESET_ALL}")
                remediation.mark_as_failed(error_message=error_msg)
            except AttributeError as ae:
                spinner.stop()
                error_msg = f"Error: Fixer module for '{check_description}' does not have the required function. Details: {str(ae)}"
                logger.error(error_msg)
                print(f"{Fore.RED}[FAILED] {error_msg}{Style.RESET_ALL}")
                remediation.mark_as_failed(error_message=error_msg)
            except Exception as e:
                spinner.stop()
                error_msg = f"Unexpected error during fix attempt: {str(e)}"
                logger.error(error_msg)
                print(f"{Fore.RED}[FAILED] {error_msg}{Style.RESET_ALL}")
                remediation.mark_as_failed(error_message=error_msg)
            finally:
                if spinner.spinner_id:
                    spinner.stop()