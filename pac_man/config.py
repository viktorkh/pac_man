import argparse
import json
import logging
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ValidationError, validate_call

_LogLevel = Literal["CRITICAL", "FATAL", "ERROR", "WARNING", "INFO", "DEBUG"]
_Provider = Literal["AWS", "GCP"]
# TODO: add text output format
_OutputFormat = Literal["CSV", "JSON", "HTML"]


@validate_call
def _validate_log_level(value: _LogLevel) -> int:
    """
    Map log level string to logging module's integer constants.
    """
    match value:
        case "CRITICAL":
            return logging.CRITICAL
        case "FATAL":
            return logging.FATAL
        case "ERROR":
            return logging.ERROR
        case "WARNING":
            return logging.WARNING
        case "INFO":
            return logging.INFO
        case "DEBUG":
            return logging.DEBUG


def _validate_upper(value: Any) -> Any:
    """
    Convert string values to uppercase for validation purposes.
    """
    return value.upper() if isinstance(value, str) else value


class Config(BaseModel):
    """
    Configuration class for the Cloud Security Audit Tool.
    """

    provider: Annotated[_Provider, BeforeValidator(_validate_upper)]
    profile: str | None = None
    regions: list[str] = []
    checks: list[str] | None = None
    apply_fix: bool | None = None
    output_format: Annotated[_OutputFormat, BeforeValidator(_validate_upper)] = "JSON"
    log_level: Annotated[
        int,
        BeforeValidator(_validate_log_level),
        BeforeValidator(_validate_upper),  # call order is bottom to top
    ] = logging.CRITICAL
    log_file: str | None = None
    whitelist_file: str | None = None

    @staticmethod
    def _parse_config_file() -> tuple[argparse.ArgumentParser, dict[str, Any]]:
        """
        Parse the optional configuration file argument and return its content.
        """

        def config_error(config_file: str, msg: str):
            parser.error(f"Failed to load config file '{config_file}': {msg}")

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument(
            "--config-file",
            type=str,
            help="Optional JSON file to import config arguments from",
        )

        config_arg, _ = parser.parse_known_args()
        config_data = {}
        if config_file := config_arg.config_file:
            try:
                with open(config_file, "r") as file:
                    config_data = json.load(file)
                    if not isinstance(config_data, dict):
                        raise TypeError("Config data must be an object")
            except FileNotFoundError:
                config_error(config_file, "File not found")
            except json.JSONDecodeError:
                config_error(config_file, "Invalid JSON")
            except Exception as e:
                config_error(config_file, str(e))
        return parser, config_data

    @staticmethod
    def _setup_arguments(parser: argparse.ArgumentParser):
        """
        Define the command-line arguments for the parser.
        """
        parser.add_argument(
            "--provider",
            help=f"Required. Cloud provider to audit (allowed: {list(_Provider.__args__)})",
        )
        parser.add_argument(
            "--profile",
            help="Cloud profile to use (defaults to the default profile)",
        )
        parser.add_argument(
            "--regions",
            nargs="+",
            help="Cloud regions (one or more) to audit (defaults to the Israel region)",
        )
        parser.add_argument(
            "--checks",
            nargs="+",
            help="Specific checks to run (defaults to run all checks)",
        )
        parser.add_argument(
            "--output-format",
            help=f"Output format for findings (default: 'JSON', allowed: {list(_OutputFormat.__args__)})",
        )
        parser.add_argument(
            "--log-level",
            help=f"Log level (default: 'CRITICAL', allowed: {list(_LogLevel.__args__)})",
        )
        parser.add_argument(
            "--log-file",
            help="Optional log file to store logs",
        )
        parser.add_argument(
            "--whitelist-file",
            help="Custom whitelist YAML file (defaults to the default whitelist)",
        )

        fix_group = parser.add_mutually_exclusive_group()
        fix_group.add_argument(
            "--fix",
            action="store_true",
            help="Attempt to fix issues found during the audit (defaults to prompt)",
        )
        fix_group.add_argument(
            "--no-fix",
            action="store_true",
            help="Don't attempt to fix issues found during the audit (defaults to prompt)",
        )

    @classmethod
    def from_args(cls):
        """
        Create a Config instance from command-line arguments and an optional config file.
        """
        config_file_parser, config_data = cls._parse_config_file()

        parser = argparse.ArgumentParser(
            parents=[config_file_parser],
            description="Cloud Security Audit Tool",
        )
        cls._setup_arguments(parser)

        parsed_args = vars(parser.parse_args())
        parsed_args.pop("config_file", None)
        parsed_args = {k: v for k, v in parsed_args.items() if v is not None}

        args = config_data | parsed_args

        fix = args.pop("fix", False)
        no_fix = args.pop("no_fix", False)
        args["apply_fix"] = True if fix else False if no_fix else None

        try:
            return cls(**args)
        except ValidationError as e:
            msg = ""
            for error in e.errors():
                argument = error["loc"][0]
                error_msg = error["msg"]
                input_prefix = (
                    f"'{error['input']}' - " if error["type"] != "missing" else ""
                )

                msg += f"\n    {argument}: {input_prefix}{error_msg}"
            parser.error(msg)
