"""
Text Scanner module for detecting vulnerabilities in various text files.
This module provides functionality for scanning both plain text files for sensitive information
and dependency files for vulnerable dependencies.
"""

import logging
import os
import re
from typing import List

from core.scanners.sast_scanner import Vulnerability

# Make sure this module is initialized properly
__all__ = ['TextVulnerabilityScanner', 'scan_text_files', 'scan_file', 'SENSITIVE_PATTERNS', 'TEXT_FILE_EXTENSIONS']

# Patterns to look for in text files
SENSITIVE_PATTERNS = {
    'API_KEY': {
        'pattern': r'(?i)(api[_-]?key|apikey|access[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})["\']\s*',
        'description': 'API key found in text file',
        'severity': 'HIGH'
    },
    'PASSWORD': {
        'pattern': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]{8,})["\']\s*',
        'description': 'Password found in text file',
        'severity': 'HIGH'
    },
    'SECRET_KEY': {
        'pattern': r'(?i)(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})["\']\s*',
        'description': 'Secret key found in text file',
        'severity': 'HIGH'
    },
    'ACCESS_TOKEN': {
        'pattern': r'(?i)(access[_-]?token|accesstoken|auth[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-.]{16,})["\']\s*',
        'description': 'Access token found in text file',
        'severity': 'HIGH'
    },
    'PRIVATE_KEY': {
        'pattern': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        'description': 'Private key found in text file',
        'severity': 'HIGH'
    }
}

# File extensions to scan
TEXT_FILE_EXTENSIONS = [
    '.txt', '.log', '.cfg', '.conf', '.config', '.ini', '.env', '.properties',
    '.yaml', '.yml', '.toml', '.md', '.csv', '.tsv', '.json', '.xml', '.html',
    '.htm', '.css', '.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java',
    '.c', '.cpp', '.cs', '.go', '.rs', '.sh', '.bat', '.ps1', '.sql'
]

class TextVulnerabilityScanner:
    """Scanner for text-related vulnerabilities."""

    def __init__(self):
        """Initialize the text scanner."""
        self.vulnerabilities = []

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a text file for vulnerabilities.

        Args:
            file_path (str): Path to the file to scan.

        Returns:
            List[Vulnerability]: List of detected vulnerabilities.
        """
        self.vulnerabilities = []

        # Only scan text files
        _, ext = os.path.splitext(file_path)
        if ext.lower() not in TEXT_FILE_EXTENSIONS:
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    content = f.read()
                    lines = content.split('\n')

                    # Check for sensitive patterns
                    for pattern_name, pattern_info in SENSITIVE_PATTERNS.items():
                        matches = re.finditer(pattern_info['pattern'], content)
                        for match in matches:
                            # Find the line number
                            line_number = content[:match.start()].count('\n') + 1

                            # Get the matched line
                            matched_line = lines[line_number - 1] if line_number <= len(lines) else ""

                            # Create vulnerability
                            vuln = Vulnerability(
                                id=f"TEXT-SENSITIVE-{pattern_name}",
                                severity=pattern_info['severity'],
                                confidence="MEDIUM",
                                file_path=file_path,
                                line_number=line_number,
                                description=pattern_info['description'],
                                code=matched_line,
                                fix_suggestion="Remove sensitive information from text files or use environment variables or a secure vault instead."
                            )
                            self.vulnerabilities.append(vuln)
                            logging.info(f"Found {pattern_name} in {file_path}:{line_number}")
                except Exception as e:
                    logging.warning(f"Error processing text file {file_path}: {e}")
        except Exception as e:
            logging.error(f"Error scanning text file {file_path}: {e}")

        return self.vulnerabilities


def scan_text_files(directory: str) -> List[Vulnerability]:
    """
    Scan text files in a directory for vulnerabilities.

    Args:
        directory (str): Directory to scan.

    Returns:
        List[Vulnerability]: List of detected vulnerabilities.
    """
    scanner = TextVulnerabilityScanner()
    vulnerabilities = []

    for root, _, files in os.walk(directory):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() in TEXT_FILE_EXTENSIONS:
                file_path = os.path.join(root, file)
                try:
                    file_vulns = scanner.scan_file(file_path)
                    vulnerabilities.extend(file_vulns)
                except Exception as e:
                    logging.error(f"Error scanning {file_path}: {e}")

    return vulnerabilities

# For backward compatibility
scan_file = TextVulnerabilityScanner().scan_file
