"""
Global pytest configuration and shared fixtures.
This module handles common test setup like Python path configuration.
"""
import os
import sys

# Add the project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, project_root)
