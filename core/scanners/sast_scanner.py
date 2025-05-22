"""
This module provides SAST (Static Application Security Testing) scanning capabilities.
It integrates with Bandit for Python code scanning.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

@dataclass
class Vulnerability:
    """
    Represents a security vulnerability found in code.
    """
    id: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    description: str
    code: str
    cwe: Optional[str] = None
    fix_suggestion: Optional[str] = None


class SASTScanner:
    """
    Base class for SAST scanners.
    """

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for security vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        raise NotImplementedError("Subclasses must implement this method")


class BanditScanner(SASTScanner):
    """
    SAST scanner that uses Bandit for Python code.
    """

    def __init__(self):
        """
        Initialize the Bandit scanner.
        """
        self._check_bandit_installed()

    def _check_bandit_installed(self):
        """
        Check if Bandit is installed, and install it if not.
        """
        try:
            import bandit
            logging.info("Bandit is already installed")
        except ImportError:
            logging.info("Installing Bandit...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "bandit"])
                logging.info("Bandit installed successfully")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install Bandit: {e}")
                raise RuntimeError("Failed to install Bandit. Please install it manually with 'pip install bandit'.")

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for security vulnerabilities using Bandit.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning directory {directory} with Bandit...")

        # Create a temporary file to store the JSON output
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Use bandit as a Python module instead of command line
            import bandit.cli.main as bandit_main
            import sys

            # Save the original sys.argv
            original_argv = sys.argv.copy()

            # Set up the arguments for bandit
            sys.argv = [
                'bandit',
                '-r',  # Recursive
                '-f', 'json',  # JSON output format
                '-o', temp_path,  # Output file
                directory  # Directory to scan
            ]

            try:
                # Run bandit
                bandit_main.main()
            except SystemExit:
                # Bandit calls sys.exit(), which we need to catch
                pass
            finally:
                # Restore the original sys.argv
                sys.argv = original_argv

            # Parse the JSON output
            with open(temp_path, 'r') as f:
                results = json.load(f)

            # Convert Bandit results to Vulnerability objects
            vulnerabilities = self._parse_bandit_results(results, directory)

            logging.info(f"Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            logging.error(f"Error running Bandit: {e}")
            # Try to parse any output that might have been produced
            try:
                with open(temp_path, 'r') as f:
                    results = json.load(f)
                vulnerabilities = self._parse_bandit_results(results, directory)
                logging.info(f"Found {len(vulnerabilities)} vulnerabilities despite error")
                return vulnerabilities
            except (json.JSONDecodeError, FileNotFoundError):
                logging.error("No valid output from Bandit")
                return []
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _parse_bandit_results(self, results: Dict[str, Any], base_dir: str) -> List[Vulnerability]:
        """
        Parse Bandit JSON results into Vulnerability objects.

        Args:
            results (Dict[str, Any]): Bandit JSON results.
            base_dir (str): Base directory of the scan.

        Returns:
            List[Vulnerability]: List of parsed vulnerabilities.
        """
        vulnerabilities = []

        for result in results.get('results', []):
            # Make file path relative to base directory
            file_path = result.get('filename', '')
            if file_path.startswith(base_dir):
                file_path = os.path.relpath(file_path, base_dir)

            vuln = Vulnerability(
                id=f"BANDIT-{result.get('test_id', 'UNKNOWN')}",
                severity=result.get('issue_severity', 'UNKNOWN').upper(),
                confidence=result.get('issue_confidence', 'UNKNOWN').upper(),
                file_path=file_path,
                line_number=result.get('line_number', 0),
                description=result.get('issue_text', 'No description available'),
                code=result.get('code', 'No code available'),
                cwe=result.get('cwe', None)
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


class CustomScanner(SASTScanner):
    """
    Custom SAST scanner that uses pattern matching for various file types.
    """

    def __init__(self):
        """
        Initialize the custom scanner with patterns for different vulnerabilities.
        """
        self.patterns = {
            # Hardcoded credentials
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'auth\s*=\s*["\'][^"\']+["\']',
            ],
            # SQL Injection
            'sql_injection': [
                r'execute\s*\(\s*["\'][^"\']*\s*\+',
                r'query\s*\(\s*["\'][^"\']*\s*\+',
                r'executeQuery\s*\(\s*["\'][^"\']*\s*\+',
            ],
            # Command Injection
            'command_injection': [
                r'exec\s*\(\s*["\'][^"\']*\s*\+',
                r'spawn\s*\(\s*["\'][^"\']*\s*\+',
                r'system\s*\(\s*["\'][^"\']*\s*\+',
                r'popen\s*\(\s*["\'][^"\']*\s*\+',
                r'subprocess\.call\s*\(\s*["\'][^"\']*\s*\+',
                r'subprocess\.Popen\s*\(\s*["\'][^"\']*\s*\+',
                r'os\.system\s*\(\s*["\'][^"\']*\s*\+',
            ],
            # XSS
            'xss': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'\.html\s*\(',
            ],
            # Path Traversal
            'path_traversal': [
                r'open\s*\(\s*["\'][^"\']*\s*\+',
                r'readFile\s*\(\s*["\'][^"\']*\s*\+',
                r'fs\.readFile\s*\(\s*["\'][^"\']*\s*\+',
            ],
        }

        # CWE mapping
        self.cwe_mapping = {
            'hardcoded_credentials': 'CWE-798',
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'xss': 'CWE-79',
            'path_traversal': 'CWE-22',
        }

        # Description mapping
        self.description_mapping = {
            'hardcoded_credentials': 'Hardcoded credentials detected. This is a security risk as credentials should not be stored in code.',
            'sql_injection': 'Potential SQL injection vulnerability detected. User input should be properly sanitized before being used in SQL queries.',
            'command_injection': 'Potential command injection vulnerability detected. User input should be properly sanitized before being used in system commands.',
            'xss': 'Potential cross-site scripting (XSS) vulnerability detected. User input should be properly sanitized before being used in HTML output.',
            'path_traversal': 'Potential path traversal vulnerability detected. User input should be properly validated before being used in file operations.',
        }

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for security vulnerabilities using pattern matching.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        import re
        import os

        vulnerabilities = []

        # Walk through all files in the directory
        for root, _, files in os.walk(directory):
            for file in files:
                # Skip binary files and certain directories
                if self._should_skip_file(file, root):
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, directory)

                try:
                    # Read the file content
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check each pattern
                    for vuln_type, patterns in self.patterns.items():
                        for pattern in patterns:
                            # Find all matches
                            for match in re.finditer(pattern, content):
                                # Get the line number
                                line_number = content[:match.start()].count('\n') + 1

                                # Get the line of code
                                lines = content.split('\n')
                                code = lines[line_number - 1] if line_number <= len(lines) else "Code not available"

                                # Create a vulnerability
                                vuln = Vulnerability(
                                    id=f"CUSTOM-{vuln_type.upper()}",
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    file_path=rel_path,
                                    line_number=line_number,
                                    description=self.description_mapping.get(vuln_type, f"Potential {vuln_type} vulnerability detected"),
                                    code=code,
                                    cwe=self.cwe_mapping.get(vuln_type, None)
                                )
                                vulnerabilities.append(vuln)
                except Exception as e:
                    logging.warning(f"Error scanning file {file_path}: {e}")

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities with custom scanner")
        return vulnerabilities

    def _should_skip_file(self, file: str, root: str) -> bool:
        """
        Check if a file should be skipped during scanning.

        Args:
            file (str): File name.
            root (str): Directory containing the file.

        Returns:
            bool: True if the file should be skipped, False otherwise.
        """
        # Skip binary files
        if file.endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar.gz', '.exe', '.dll', '.so', '.pyc')):
            return True

        # Skip certain directories
        skip_dirs = ['node_modules', 'venv', '.git', '.idea', '__pycache__', 'dist', 'build']
        for skip_dir in skip_dirs:
            if skip_dir in root.split(os.path.sep):
                return True

        return False


# Factory function to get the appropriate scanner based on file type
def get_scanner_for_file_type(file_type: str) -> SASTScanner:
    """
    Get the appropriate scanner for a given file type.

    Args:
        file_type (str): File extension (e.g., 'py', 'js').

    Returns:
        SASTScanner: Appropriate scanner for the file type.
    """
    if file_type.lower() == 'py':
        return BanditScanner()
    # Add more scanners for other file types here
    else:
        logging.info(f"Using custom scanner for file type '{file_type}'.")
        return CustomScanner()


# Function to scan a directory with the appropriate scanner based on file types
def scan_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory with the appropriate scanner based on file types.

    Args:
        directory (str): Path to the directory to scan.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    # Use both Bandit and custom scanner
    vulnerabilities = []

    # Use Bandit for Python files
    try:
        bandit_scanner = BanditScanner()
        bandit_vulnerabilities = bandit_scanner.scan_directory(directory)
        vulnerabilities.extend(bandit_vulnerabilities)
        logging.info(f"Found {len(bandit_vulnerabilities)} vulnerabilities with Bandit")
    except Exception as e:
        logging.error(f"Error running Bandit scanner: {e}")

    # Use custom scanner for all files
    try:
        custom_scanner = CustomScanner()
        custom_vulnerabilities = custom_scanner.scan_directory(directory)
        vulnerabilities.extend(custom_vulnerabilities)
    except Exception as e:
        logging.error(f"Error running custom scanner: {e}")

    return vulnerabilities
