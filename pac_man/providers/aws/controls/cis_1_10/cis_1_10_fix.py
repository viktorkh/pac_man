"""CIS 1.10 - Fix for ensuring multi-factor authentication (MFA) is enabled for all IAM users that have a console password."""

import json
from typing import Dict, Any
from providers.aws.lib.check_result import CheckResult

CHECK_ID = 'cis_1_10'

def execute(session, finding, logger, service_factory) -> CheckResult:
    """
    Execute fix for CIS 1.10 finding.
    This fix will create and enable a virtual MFA device for users without MFA.

    Args:
        finding: The finding details
        logger: Logger object for logging messages
        service_factory: AWS service factory instance

    Returns:
        CheckResult: Result of the fix execution
    """
    result = CheckResult()
    result.check_id = CHECK_ID
    result.resource_id = finding.get('resource_id')
    result.resource_arn = finding.get('resource_arn')
    result.region = finding.get('region')
    result.set_status(CheckResult.STATUS_ERROR, "Execution started but failed to complete.")

    try:
        iam_service = service_factory.get_service('iam')
        users_without_mfa = json.loads(finding.get('resource_details', '{}'))

        if not users_without_mfa:
            result.set_status(CheckResult.STATUS_PASS, "No users found without MFA. No action needed.")
            return result

        fixed_users = []
        failed_users = []

        for user in users_without_mfa:
            username = user['user']
            try:
                # Create virtual MFA device
                mfa_response = iam_service.create_virtual_mfa_device(username)
                if not mfa_response['success']:
                    raise ValueError(
                        f"Failed to create virtual MFA device: {mfa_response.get('error_message', 'Unknown error')}"
                    )

                mfa_serial = mfa_response['serial_number']
                # Enable virtual MFA device for the user
                enable_response = iam_service.enable_mfa_device(username, mfa_serial, ['000000', '000000'])
                if not enable_response['success']:
                    raise ValueError(
                        f"Failed to enable MFA device: {enable_response.get('error_message', 'Unknown error')}"
                    )

                fixed_users.append(username)
                logger.info(f"Successfully enabled MFA for user: {username}")

            except Exception as e:
                logger.error(f"Failed to enable MFA for user {username}: {str(e)}")
                failed_users.append(username)

        if fixed_users:
            if failed_users:
                result.set_status(
                    CheckResult.STATUS_FAIL,
                    f"Successfully enabled MFA for {len(fixed_users)} user(s): {', '.join(fixed_users)}. "
                    f"Failed to enable MFA for {len(failed_users)} user(s): {', '.join(failed_users)}."
                )
            else:
                result.set_status(
                    CheckResult.STATUS_PASS,
                    f"Successfully enabled MFA for {len(fixed_users)} user(s): {', '.join(fixed_users)}."
                )
        else:
            result.set_status(CheckResult.STATUS_FAIL, f"Failed to enable MFA for all users: {', '.join(failed_users)}.")

    except Exception as e:
        logger.error(f"Error executing fix for CIS {CHECK_ID}: {str(e)}")
        # Explicitly reset the status to ERROR here
        result.status = CheckResult.STATUS_ERROR
        result.status_extended = f"Error executing fix: {str(e)}"

    return result
