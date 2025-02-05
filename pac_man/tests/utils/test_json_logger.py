"""
Unit tests for the JSON logging functionality.
"""

import json
import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch
from pac_man.utils.json_logger import JsonFormatter, JsonFileHandler, setup_json_logging

class TestJsonFormatter(unittest.TestCase):
    """Test cases for the JsonFormatter class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.formatter = JsonFormatter()
        self.logger = logging.getLogger('test_logger')
        self.logger.setLevel(logging.INFO)
    
    def test_basic_log_format(self):
        """Test basic log message formatting."""
        record = logging.LogRecord(
            name='test_logger',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg='Test message',
            args=(),
            exc_info=None
        )
        
        formatted = self.formatter.format(record)
        parsed = json.loads(formatted)
        
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed['level'], 'INFO')
        self.assertEqual(parsed['logger'], 'test_logger')
        self.assertEqual(parsed['message'], 'Test message')
        self.assertIn('timestamp', parsed)
    
    def test_exception_logging(self):
        """Test logging with exception information."""
        try:
            raise ValueError("Test exception")
        except ValueError:
            record = logging.LogRecord(
                name='test_logger',
                level=logging.ERROR,
                pathname='test.py',
                lineno=1,
                msg='Error occurred',
                args=(),
                exc_info=sys.exc_info()
            )
            
            formatted = self.formatter.format(record)
            parsed = json.loads(formatted)
            
            self.assertIn('exception', parsed)
            self.assertIn('ValueError: Test exception', parsed['exception'])
    
    def test_extra_data_logging(self):
        """Test logging with extra contextual data."""
        record = logging.LogRecord(
            name='test_logger',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg='Test message',
            args=(),
            exc_info=None
        )
        record.extra_data = {'user': 'test_user', 'action': 'login'}
        
        formatted = self.formatter.format(record)
        parsed = json.loads(formatted)
        
        self.assertEqual(parsed['user'], 'test_user')
        self.assertEqual(parsed['action'], 'login')

class TestJsonFileHandler(unittest.TestCase):
    """Test cases for the JsonFileHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, 'test.log')
        self.logger = logging.getLogger('test_logger')
        
        # Remove any existing handlers and disable propagation
        self.logger.handlers = []
        self.logger.propagate = False
        
        # Set up handler and logger
        self.handler = JsonFileHandler(self.log_file)
        self.handler.setLevel(logging.INFO)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.INFO)
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Close and remove handler
        if self.handler:
            self.handler.close()
            self.logger.removeHandler(self.handler)
        
        # Remove all files in temp directory
        for filename in os.listdir(self.temp_dir):
            filepath = os.path.join(self.temp_dir, filename)
            try:
                if os.path.isfile(filepath):
                    os.remove(filepath)
            except Exception:
                pass
        
        # Remove directory
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass
    
    def test_file_writing(self):
        """Test that logs are properly written to file."""
        test_message = "Test log message"
        self.logger.info(test_message)
        
        with open(self.log_file, 'r') as f:
            log_content = f.read().strip()
            parsed = json.loads(log_content)
            
            self.assertEqual(parsed['message'], test_message)
            self.assertEqual(parsed['level'], 'INFO')
    
    def test_multiple_logs(self):
        """Test writing multiple log entries."""
        messages = ["First message", "Second message", "Third message"]  # Properly formatted list
        
        for msg in messages:
            self.logger.info(msg)
        
        with open(self.log_file, 'r') as f:
            log_lines = f.readlines()
            
            self.assertEqual(len(log_lines), len(messages))
            
            for line, expected_msg in zip(log_lines, messages):
                parsed = json.loads(line.strip())
                self.assertEqual(parsed['message'], expected_msg)
    
    def test_emit_error_handling(self):
        """Test error handling in emit method."""
        def mock_write(*args, **kwargs):
            raise IOError("Test IO error")
        
        # Create a record that will trigger an error
        record = logging.LogRecord(
            name='test_logger',
            level=logging.ERROR,
            pathname='test.py',
            lineno=1,
            msg='Test error handling',
            args=(),
            exc_info=None
        )
        
        # Patch the stream's write method to raise an error
        with patch.object(self.handler.stream, 'write', side_effect=mock_write):
            # This should not raise an exception
            self.handler.emit(record)

class TestSetupJsonLogging(unittest.TestCase):
    """Test cases for the setup_json_logging function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, 'test.log')
        self.logger = logging.getLogger('test_setup_logger')
        
        # Remove any existing handlers and disable propagation
        self.logger.handlers = []
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)  # Set base logger level
        
        self.handlers = []
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Close and remove all handlers
        for handler in self.handlers:
            try:
                handler.close()
                self.logger.removeHandler(handler)
            except Exception:
                pass
        
        # Remove all files in temp directory
        for filename in os.listdir(self.temp_dir):
            filepath = os.path.join(self.temp_dir, filename)
            try:
                if os.path.isfile(filepath):
                    os.remove(filepath)
            except Exception:
                pass
        
        # Remove directory
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass
    
    def test_setup_integration(self):
        """Test the complete setup of JSON logging."""
        handler = setup_json_logging(self.logger, self.log_file, logging.INFO)
        self.handlers.append(handler)
        
        test_message = "Integration test message"
        self.logger.info(test_message)
        
        with open(self.log_file, 'r') as f:
            log_content = f.read().strip()
            parsed = json.loads(log_content)
            
            self.assertEqual(parsed['message'], test_message)
            self.assertEqual(parsed['level'], 'INFO')
            self.assertEqual(parsed['logger'], 'test_setup_logger')
    
    def test_multiple_handlers(self):
        """Test that multiple handlers can be added without conflicts."""
        # Add first JSON handler with INFO level
        handler1 = setup_json_logging(self.logger, self.log_file, logging.INFO)
        self.handlers.append(handler1)
        
        # Add second JSON handler with ERROR level
        second_log_file = os.path.join(self.temp_dir, 'test2.log')
        handler2 = setup_json_logging(self.logger, second_log_file, logging.ERROR)
        self.handlers.append(handler2)
        
        # Log messages at different levels
        test_message_info = "Info level message"
        test_message_error = "Error level message"
        
        # Log messages
        self.logger.info(test_message_info)
        self.logger.error(test_message_error)
        
        # Check first log file (INFO level)
        with open(self.log_file, 'r') as f:
            log_lines = f.readlines()
            self.assertEqual(len(log_lines), 2)  # Should contain both messages
            
            parsed = json.loads(log_lines[0].strip())
            self.assertEqual(parsed['message'], test_message_info)
            
            parsed = json.loads(log_lines[1].strip())
            self.assertEqual(parsed['message'], test_message_error)
        
        # Check second log file (ERROR level)
        with open(second_log_file, 'r') as f:
            log_lines = f.readlines()
            self.assertEqual(len(log_lines), 1)  # Should only contain error message
            
            parsed = json.loads(log_lines[0].strip())
            self.assertEqual(parsed['message'], test_message_error)

if __name__ == '__main__':
    unittest.main()
