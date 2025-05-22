"""
This module provides a JavaScript SAST scanner for detecting security vulnerabilities.
"""

import os
import json
import logging
import tempfile
import subprocess
import sys
from typing import List, Dict, Any, Optional

from core.scanners.sast_scanner import Vulnerability

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# ESLint security rules
ESLINT_CONFIG = {
    "env": {
        "node": True,
        "browser": True,
        "es6": True
    },
    "extends": [
        "eslint:recommended",
        "plugin:security/recommended"
    ],
    "plugins": [
        "security"
    ],
    "rules": {
        "security/detect-unsafe-regex": "error",
        "security/detect-non-literal-regexp": "error",
        "security/detect-non-literal-require": "error",
        "security/detect-eval-with-expression": "error",
        "security/detect-pseudoRandomBytes": "error",
        "security/detect-possible-timing-attacks": "error",
        "security/detect-no-csrf-before-method-override": "error",
        "security/detect-buffer-noassert": "error",
        "security/detect-child-process": "error",
        "security/detect-disable-mustache-escape": "error",
        "security/detect-object-injection": "error",
        "security/detect-new-buffer": "error",
        "security/detect-sql-injection": "error"
    }
}

# Custom rules for SQL injection detection
SQL_INJECTION_PATTERNS = [
    r"connection\.query\([^,]*\+",
    r"db\.query\([^,]*\+",
    r"sql\s*=\s*['\"][^'\"]*\s*\+",
    r"query\s*=\s*['\"][^'\"]*\s*\+"
]

class JavaScriptScanner:
    """
    Scanner for JavaScript files to detect security vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the JavaScript scanner.
        """
        self._check_dependencies_installed()
    
    def _check_dependencies_installed(self):
        """
        Check if ESLint and required plugins are installed, and install them if not.
        """
        try:
            # Check if npm is installed
            subprocess.check_output(["npm", "--version"], stderr=subprocess.STDOUT)
            logging.info("npm is already installed")
            
            # Create a temporary directory for ESLint setup
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)
                
                # Initialize package.json
                subprocess.check_call(["npm", "init", "-y"], stdout=subprocess.DEVNULL)
                
                # Install ESLint and security plugin
                subprocess.check_call(
                    ["npm", "install", "eslint", "eslint-plugin-security", "--save-dev"],
                    stdout=subprocess.DEVNULL
                )
                
                logging.info("ESLint and security plugin installed successfully")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"Failed to install dependencies: {e}")
            raise RuntimeError(
                "Failed to install required dependencies. Please make sure npm is installed and try again."
            )
    
    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a JavaScript file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the JavaScript file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []
        
        if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            logging.info(f"Skipping non-JavaScript file: {file_path}")
            return []
        
        vulnerabilities = []
        
        # Run ESLint scan
        eslint_vulnerabilities = self._run_eslint_scan(file_path)
        vulnerabilities.extend(eslint_vulnerabilities)
        
        # Run custom pattern matching for SQL injection
        custom_vulnerabilities = self._run_custom_scan(file_path)
        vulnerabilities.extend(custom_vulnerabilities)
        
        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in {file_path}")
        return vulnerabilities
    
    def _run_eslint_scan(self, file_path: str) -> List[Vulnerability]:
        """
        Run ESLint scan on a JavaScript file.
        
        Args:
            file_path (str): Path to the JavaScript file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        try:
            # Create a temporary ESLint config file
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                temp_config_path = temp_file.name
                json.dump(ESLINT_CONFIG, temp_file)
            
            # Run ESLint
            cmd = [
                "npx", "eslint",
                "--no-eslintrc",
                "-c", temp_config_path,
                "--format", "json",
                file_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse ESLint output
            if result.stdout:
                try:
                    eslint_results = json.loads(result.stdout)
                    
                    for file_result in eslint_results:
                        for message in file_result.get('messages', []):
                            if message.get('ruleId', '').startswith('security/'):
                                severity = self._map_eslint_severity(message.get('severity', 1))
                                
                                vuln = Vulnerability(
                                    file_path=file_path,
                                    line_number=message.get('line', 0),
                                    vulnerability_type=f"ESLINT-{message.get('ruleId', 'UNKNOWN')}",
                                    severity=severity,
                                    description=message.get('message', 'Unknown ESLint issue'),
                                    confidence="HIGH",
                                    code_snippet=self._get_code_snippet(file_path, message.get('line', 0)),
                                    fix_suggestion=self._generate_fix_suggestion(message.get('ruleId', ''), file_path, message.get('line', 0))
                                )
                                
                                vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse ESLint output: {result.stdout}")
            
            # Clean up the temporary config file
            os.unlink(temp_config_path)
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running ESLint: {e}")
        
        return vulnerabilities
    
    def _run_custom_scan(self, file_path: str) -> List[Vulnerability]:
        """
        Run custom pattern matching for vulnerabilities not covered by ESLint.
        
        Args:
            file_path (str): Path to the JavaScript file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check for SQL injection vulnerabilities
                for i, line in enumerate(lines):
                    for pattern in SQL_INJECTION_PATTERNS:
                        if self._match_pattern(line, pattern):
                            # Found a potential SQL injection
                            vuln = Vulnerability(
                                file_path=file_path,
                                line_number=i + 1,
                                vulnerability_type="CUSTOM-SQL-INJECTION",
                                severity="HIGH",
                                description="Potential SQL injection vulnerability detected. User input is directly concatenated into SQL query.",
                                confidence="HIGH",
                                code_snippet=self._get_code_snippet(file_path, i + 1),
                                fix_suggestion=self._generate_sql_injection_fix(file_path, i + 1)
                            )
                            
                            vulnerabilities.append(vuln)
        except Exception as e:
            logging.error(f"Error in custom scan: {e}")
        
        return vulnerabilities
    
    def _match_pattern(self, line: str, pattern: str) -> bool:
        """
        Check if a line matches a regex pattern.
        
        Args:
            line (str): Line to check.
            pattern (str): Regex pattern to match.
            
        Returns:
            bool: True if the line matches the pattern, False otherwise.
        """
        import re
        return bool(re.search(pattern, line))
    
    def _map_eslint_severity(self, severity: int) -> str:
        """
        Map ESLint severity to our severity levels.
        
        Args:
            severity (int): ESLint severity (0=off, 1=warn, 2=error).
            
        Returns:
            str: Severity level (LOW, MEDIUM, HIGH).
        """
        if severity == 2:
            return "HIGH"
        elif severity == 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_code_snippet(self, file_path: str, line_number: int, context: int = 2) -> str:
        """
        Get a code snippet from a file.
        
        Args:
            file_path (str): Path to the file.
            line_number (int): Line number to center the snippet on.
            context (int): Number of lines of context to include.
            
        Returns:
            str: Code snippet.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                start_line = max(0, line_number - context - 1)
                end_line = min(len(lines), line_number + context)
                
                snippet_lines = lines[start_line:end_line]
                snippet = ''.join(snippet_lines).rstrip()
                
                return snippet
        except Exception as e:
            logging.error(f"Error getting code snippet: {e}")
            return ""
    
    def _generate_fix_suggestion(self, rule_id: str, file_path: str, line_number: int) -> str:
        """
        Generate a fix suggestion for a vulnerability.
        
        Args:
            rule_id (str): ESLint rule ID.
            file_path (str): Path to the file.
            line_number (int): Line number of the vulnerability.
            
        Returns:
            str: Fix suggestion.
        """
        if rule_id == "security/detect-sql-injection":
            return self._generate_sql_injection_fix(file_path, line_number)
        elif rule_id == "security/detect-eval-with-expression":
            return "Avoid using eval() with dynamic expressions. Consider using safer alternatives like Function constructor or JSON.parse()."
        elif rule_id == "security/detect-non-literal-require":
            return "Avoid using require() with dynamic expressions. Use a static string literal instead."
        elif rule_id == "security/detect-object-injection":
            return "Validate user input before using it as an object property name. Consider using a whitelist of allowed properties."
        else:
            return "Fix this security vulnerability by following secure coding practices."
    
    def _generate_sql_injection_fix(self, file_path: str, line_number: int) -> str:
        """
        Generate a fix suggestion for SQL injection vulnerabilities.
        
        Args:
            file_path (str): Path to the file.
            line_number (int): Line number of the vulnerability.
            
        Returns:
            str: Fix suggestion.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                vulnerable_line = lines[line_number - 1] if line_number <= len(lines) else ""
                
                if "connection.query" in vulnerable_line:
                    if "+" in vulnerable_line:
                        # Direct string concatenation
                        if "{" in vulnerable_line and "sql" in vulnerable_line:
                            # Object with sql property
                            return "Use parameterized queries instead of string concatenation:\n\n```javascript\nlet query = {\n    sql: \"SELECT * FROM users WHERE id = ?\",\n    values: [userId]\n};\nconnection.query(query, (err, result) => {\n    // Handle result\n});\n```"
                        else:
                            # Direct query
                            return "Use parameterized queries instead of string concatenation:\n\n```javascript\nconnection.query(\"SELECT * FROM users WHERE id = ?\", [userId], (err, result) => {\n    // Handle result\n});\n```"
                
                # Generic fix for other cases
                return "Use parameterized queries instead of string concatenation. Replace concatenated values with placeholders (?) and pass the values as an array in a separate parameter."
        except Exception as e:
            logging.error(f"Error generating SQL injection fix: {e}")
            return "Use parameterized queries instead of string concatenation to prevent SQL injection."

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for JavaScript security vulnerabilities.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities


def scan_javascript_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for JavaScript security vulnerabilities.
    
    Args:
        directory (str): Path to the directory to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = JavaScriptScanner()
    return scanner.scan_directory(directory)


def scan_javascript_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a JavaScript file for security vulnerabilities.
    
    Args:
        file_path (str): Path to the JavaScript file to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = JavaScriptScanner()
    return scanner.scan_file(file_path)
