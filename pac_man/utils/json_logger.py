"""
JSON Logger module for handling log output in JSON format.
This module provides a custom logging handler that formats log records as JSON.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, Any

class JsonFormatter(logging.Formatter):
    """
    Custom formatter that converts log records to JSON format.
    """
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record as a JSON string.
        
        Args:
            record (logging.LogRecord): The log record to format
            
        Returns:
            str: JSON formatted log entry
        """
        # Create the base log entry
        log_entry: Dict[str, Any] = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)

        # Add any extra attributes from the record
        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)

        return json.dumps(log_entry) + '\n'

class JsonFileHandler(logging.FileHandler):
    """
    Custom file handler that ensures each log entry is written as a separate JSON object.
    """
    def __init__(self, filename: str, mode: str = 'a', encoding: str = None, delay: bool = False):
        """
        Initialize the handler with JSON formatting.
        
        Args:
            filename (str): Path to the log file
            mode (str): File open mode ('a' for append)
            encoding (str): File encoding
            delay (bool): Delay file opening until first log
        """
        # Ensure directory exists
        dirname = os.path.dirname(filename)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        
        # Open in write mode to clear the file
        super().__init__(filename, 'w', encoding, delay)
        self.setFormatter(JsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a record, ensuring proper flushing.
        
        Args:
            record (logging.LogRecord): The log record to emit
        """
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)

def setup_json_logging(logger: logging.Logger, log_file: str, level: int = logging.INFO) -> JsonFileHandler:
    """
    Set up JSON logging for the given logger.
    
    Args:
        logger (logging.Logger): The logger instance to configure
        log_file (str): Path to the log file
        level (int): Logging level
        
    Returns:
        JsonFileHandler: The created handler for cleanup purposes
    """
    # Set logger level to allow all messages through
    logger.setLevel(logging.DEBUG)
    
    # Create and add the JSON handler with specified level
    json_handler = JsonFileHandler(log_file)
    json_handler.setLevel(level)
    logger.addHandler(json_handler)
    
    return json_handler
