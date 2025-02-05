# Cloud Security Audit and Remediation Tool

This project provides a command-line tool for conducting security audits and remediation on cloud environments, specifically for AWS and GCP. It includes functionality for authentication, security check execution, result exporting, and automated remediation of failed checks.

## Project Structure

- **`main.py`**: Entry point of the application. It parses command-line arguments, initializes the cloud provider, authenticates, and executes the specified security checks. It supports options for running specific checks, logging, and exporting results.
- **`__init__.py`**: Factory for initializing the appropriate provider (AWS or GCP) based on user input.
- **`provider.py`**: Base class for cloud providers, outlining the structure for authentication, check loading, check execution, and remediation functions. AWS and GCP provider classes inherit from this.
- **`aws_provider.py`**: AWS-specific implementation of the `Provider` base class. It handles AWS authentication, loading of AWS security checks, check execution, and remediation actions. It uses `boto3` for AWS operations.

## Prerequisites

- **Python 3.10+**
- **Dependencies**: Install required packages using the following command:

  ```bash
  pip install -r requirements.txt
  ```

  Ensure [AWS](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-configure-quickstart-precedence) credentials are configured if auditing AWS accounts. Use a profile with necessary permissions for the checks you intend to run.

## Usage

### Command-Line Arguments

Run the tool as follows:

```bash
python main.py --provider PROVIDER [--config-file CONFIG_FILE] [--profile PROFILE] [--regions REGIONS [REGIONS ...]] [--checks CHECKS [CHECKS ...]] [--output-format OUTPUT_FORMAT] [--log-level LOG_LEVEL] [--log-file LOG_FILE] [--whitelist-file WHITELIST_FILE] [--fix | --no-fix]
```

#### Arguments
- `--config-file`: Optional `JSON` file to import config arguments from
- `--provider`: Required. Cloud provider to audit (allowed: `AWS`, `GCP`)
- `--profile`: Cloud profile to use (defaults to the default profile)
- `--regions`: Cloud regions (one or more) to audit (defaults to the Israel region)
- `--checks`: Specific checks to run (defaults to run all checks)
- `--fix`: Attempt to fix issues found during the audit (defaults to prompt)
- `--no-fix`: Don't attempt to fix issues found during the audit (defaults to prompt)
- `--output-format`: Output format for findings (default: `JSON`, allowed: `CSV`, `JSON`, `HTML`)
- `--log-level`: Log level (default: `CRITICAL`, allowed: `CRITICAL`, `FATAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`)
- `--log-file`: Optional log file to store logs
- `--whitelist-file`: Custom whitelist `YAML` file (defaults to the default whitelist)

### Examples

Audit an AWS account using the default profile and whitelist:

```bash
python main.py --provider aws --checks cis_1_20 cis_3_5 --output-format json --log-level info
```

Audit using a config file:

```json
{
    "provider": "aws",
    "checks": ["cis_1_20", "cis_3_5"],
    "output_format": "json",
    "log_level": "INFO"
}
```
```bash
python main.py --config-file <file_name>.json
```

Audit using a custom whitelist file:

```bash
python main.py --provider aws --checks cis_1_16 --whitelist-file custom_whitelist.yaml
```

Attempt to fix issues in a GCP account and log output to a file:

```bash
python main.py --provider gcp --fix --log-file <file_name>.json
```

## Whitelist Configuration

The tool supports whitelisting resources that should be excluded from security checks. This is useful for essential system roles or resources that require specific privileges.

### Default Whitelist

A default whitelist is provided at `providers/aws/config/aws_default_whitelist.yaml` containing essential system roles that should not be modified.

### Custom Whitelist

You can create your own whitelist file to override or extend the default whitelist. Use the `--whitelist-file` parameter to specify your custom whitelist.

Example custom whitelist format:
```yaml
check_id:
  roles:        # List of role names/patterns to exclude
    - role_name1
    - role_pattern*  # Supports wildcards
  users:        # List of user names/patterns to exclude
    - user_name1
  policies:     # List of policy names/patterns to exclude
    - policy_name1
  reason: "Explanation of why these resources are whitelisted"
```

See `custom_whitelist_example.yaml` for a complete example with comments and explanations.

## Output

The tool generates two types of output files in the `output` directory:

### 1. Security Audit Results
- Generated for every run in `JSON`, `CSV`, or `HTML` format (based on `--output-format` flag)
- Contains detailed findings from all executed checks
- Includes three categories of findings:
  - PASS: Resources that meet security requirements
  - FAIL: Resources that need remediation
  - MUTED: Resources that are whitelisted and excluded from remediation

### 2. Remediation Results
- Generated when applying fixes
- JSON format containing remediation attempts and their outcomes
- Includes statistics about successful and failed remediation attempts
- Excludes whitelisted resources from remediation attempts

## Running Tests

The project includes a comprehensive test suite to ensure reliability and correctness. Tests are organized by module and functionality in the `tests/` directory.

### Running All Tests

To run the complete test suite:

```bash
python -m pytest
```

### Running Specific Test Categories

Run tests for a specific module:
```bash
python -m pytest tests/providers/aws/
```

Run tests for a specific control:
```bash
python -m pytest tests/providers/aws/controls/cis_2_1_2/
```

### Test Coverage

To run tests with coverage reporting:
```bash
python -m pytest --cov=pac_man tests/
```

Generate an HTML coverage report:
```bash
python -m pytest --cov=pac_man --cov-report=html tests/
```

The HTML report will be generated in the `htmlcov/` directory.




## Extending the Tool

To add custom checks or providers, you can:

1. Create new check modules under `providers/aws/controls` or `providers/gcp/controls`.
   - Each check should have both a `_check.py` and `_fix.py` file
   - The check file should return findings using the `CheckResult` class
   - The fix file should implement remediation logic and update the `RemediationResult`

2. Implement additional providers by extending the `Provider` class.

### Creating Custom Checks

Each check module should contain:

1. Check Implementation (`_check.py`):
   ```python
   def execute(session, logger):
       # Implement check logic
       finding = CheckResult()
       # Set finding attributes
       return [finding]
   ```

2. Fix Implementation (`_fix.py`):
   ```python
   def execute(session, finding, logger):
       # Initialize remediation tracking
       remediation = finding.init_remediation()
       try:
           # Implement fix logic
           remediation.mark_as_success(...)
       except Exception as e:
           remediation.mark_as_failed(...)
       return finding
