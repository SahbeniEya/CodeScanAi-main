"""
This module provides enhanced validation for security vulnerability fixes.
"""

import logging
import os
import tempfile
import shutil
import re
import json
from typing import List, Dict, Any, Tuple, Optional

from core.scanners.sast_scanner import Vulnerability, scan_directory
from core.validation.fix_validator import FixValidator


class EnhancedFixValidator(FixValidator):
    """
    Enhanced validator for security vulnerability fixes.
    """
    
    def __init__(self, directory: str):
        """
        Initialize the enhanced fix validator.
        
        Args:
            directory (str): The directory containing the code to validate.
        """
        super().__init__(directory)
        self.test_cases = {}
        self.load_test_cases()
    
    def load_test_cases(self):
        """Load test cases for different vulnerability types."""
        # Define test cases for different vulnerability types
        self.test_cases = {
            "sql_injection": [
                {"input": "1", "expected_safe": True},
                {"input": "1; DROP TABLE users;", "expected_safe": False},
                {"input": "1 OR 1=1", "expected_safe": False},
                {"input": "1' OR '1'='1", "expected_safe": False}
            ],
            "xss": [
                {"input": "Hello World", "expected_safe": True},
                {"input": "<script>alert(1)</script>", "expected_safe": False},
                {"input": "javascript:alert(1)", "expected_safe": False},
                {"input": "<img src=x onerror=alert(1)>", "expected_safe": False}
            ],
            "command_injection": [
                {"input": "file.txt", "expected_safe": True},
                {"input": "file.txt; rm -rf /", "expected_safe": False},
                {"input": "$(cat /etc/passwd)", "expected_safe": False},
                {"input": "`cat /etc/passwd`", "expected_safe": False}
            ],
            "path_traversal": [
                {"input": "file.txt", "expected_safe": True},
                {"input": "../../../etc/passwd", "expected_safe": False},
                {"input": "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "expected_safe": False},
                {"input": "..\\..\\Windows\\System32\\config\\SAM", "expected_safe": False}
            ]
        }
    
    def create_test_file(self, vulnerability: Vulnerability, fix: str) -> Tuple[str, str]:
        """
        Create a test file with the fixed code.
        
        Args:
            vulnerability (Vulnerability): The vulnerability with a fix.
            fix (str): The fix to apply.
            
        Returns:
            Tuple[str, str]: The path to the temporary directory and the path to the test file.
        """
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Determine the file extension based on the vulnerability file path
        file_ext = os.path.splitext(vulnerability.file_path)[1] or ".js"
        
        # Create a test file with the fixed code
        test_file_path = os.path.join(temp_dir, f"test_fix{file_ext}")
        
        with open(test_file_path, 'w', encoding='utf-8') as f:
            f.write(fix)
        
        return temp_dir, test_file_path
    
    def get_vulnerability_type(self, vulnerability: Vulnerability) -> str:
        """
        Determine the type of vulnerability.
        
        Args:
            vulnerability (Vulnerability): The vulnerability to check.
            
        Returns:
            str: The vulnerability type.
        """
        vuln_id = vulnerability.id.lower()
        vuln_desc = vulnerability.description.lower()
        
        if 'sql' in vuln_id or 'sql injection' in vuln_desc:
            return "sql_injection"
        elif 'xss' in vuln_id or 'cross-site scripting' in vuln_desc:
            return "xss"
        elif 'command' in vuln_id or 'command injection' in vuln_desc:
            return "command_injection"
        elif 'path' in vuln_id or 'path traversal' in vuln_desc:
            return "path_traversal"
        else:
            return "unknown"
    
    def static_analysis_check(self, vulnerability: Vulnerability, fix: str) -> Dict[str, Any]:
        """
        Perform static analysis on the fix.
        
        Args:
            vulnerability (Vulnerability): The vulnerability to check.
            fix (str): The fix to analyze.
            
        Returns:
            Dict[str, Any]: The analysis results.
        """
        vuln_type = self.get_vulnerability_type(vulnerability)
        results = {
            "type": vuln_type,
            "passed": False,
            "details": []
        }
        
        # SQL Injection checks
        if vuln_type == "sql_injection":
            # Check for parameterized queries
            if '?' in fix and '[' in fix and ']' in fix:
                results["details"].append("Uses parameterized queries with placeholders")
                results["passed"] = True
            elif 'prepare' in fix.lower() and 'execute' in fix.lower():
                results["details"].append("Uses prepared statements")
                results["passed"] = True
            else:
                results["details"].append("Does not use parameterized queries or prepared statements")
        
        # XSS checks
        elif vuln_type == "xss":
            # Check for proper escaping
            if 'escapeHtml' in fix or 'escape(' in fix or 'encodeURIComponent' in fix:
                results["details"].append("Uses proper HTML escaping")
                results["passed"] = True
            elif 'textContent' in fix and not 'innerHTML' in fix:
                results["details"].append("Uses textContent instead of innerHTML")
                results["passed"] = True
            else:
                results["details"].append("Does not use proper HTML escaping")
        
        # Command Injection checks
        elif vuln_type == "command_injection":
            # Check for proper command execution
            if 'execFile' in fix and not 'exec(' in fix:
                results["details"].append("Uses execFile instead of exec")
                results["passed"] = True
            elif 'shell: false' in fix and not 'shell: true' in fix:
                results["details"].append("Uses shell: false")
                results["passed"] = True
            elif re.search(r'test\([^)]+\)', fix) and 'return res.status(400)' in fix:
                results["details"].append("Validates user input before execution")
                results["passed"] = True
            else:
                results["details"].append("Does not use safe command execution methods")
        
        # Path Traversal checks
        elif vuln_type == "path_traversal":
            # Check for proper path handling
            if 'path.join' in fix and 'path.resolve' in fix:
                results["details"].append("Uses path.join and path.resolve")
                results["passed"] = True
            elif 'startsWith' in fix and 'baseDir' in fix:
                results["details"].append("Validates path is within base directory")
                results["passed"] = True
            elif re.search(r'test\([^)]+\)', fix) and 'return res.status(400)' in fix:
                results["details"].append("Validates user input before file operations")
                results["passed"] = True
            else:
                results["details"].append("Does not use safe path handling methods")
        
        return results
    
    def test_case_validation(self, vulnerability: Vulnerability, fix: str) -> Dict[str, Any]:
        """
        Validate the fix against test cases.
        
        Args:
            vulnerability (Vulnerability): The vulnerability to check.
            fix (str): The fix to validate.
            
        Returns:
            Dict[str, Any]: The validation results.
        """
        vuln_type = self.get_vulnerability_type(vulnerability)
        results = {
            "type": vuln_type,
            "passed": False,
            "test_results": []
        }
        
        # Skip if we don't have test cases for this vulnerability type
        if vuln_type not in self.test_cases or vuln_type == "unknown":
            results["details"] = "No test cases available for this vulnerability type"
            return results
        
        # Get test cases for this vulnerability type
        test_cases = self.test_cases[vuln_type]
        
        # Create a test file with the fixed code
        temp_dir, test_file_path = self.create_test_file(vulnerability, fix)
        
        try:
            # For each test case, check if the fix handles it correctly
            for i, test_case in enumerate(test_cases):
                input_value = test_case["input"]
                expected_safe = test_case["expected_safe"]
                
                # Perform static analysis on the test case
                is_safe = self.is_input_safe_for_fix(fix, input_value, vuln_type)
                
                # Record the test result
                results["test_results"].append({
                    "test_case": i + 1,
                    "input": input_value,
                    "expected_safe": expected_safe,
                    "actual_safe": is_safe,
                    "passed": is_safe == expected_safe
                })
            
            # Check if all test cases passed
            all_passed = all(result["passed"] for result in results["test_results"])
            results["passed"] = all_passed
            
            return results
        finally:
            # Clean up the temporary directory
            shutil.rmtree(temp_dir)
    
    def is_input_safe_for_fix(self, fix: str, input_value: str, vuln_type: str) -> bool:
        """
        Check if the input is safe for the fix.
        
        Args:
            fix (str): The fix to check.
            input_value (str): The input value to test.
            vuln_type (str): The vulnerability type.
            
        Returns:
            bool: True if the input is safe, False otherwise.
        """
        # SQL Injection
        if vuln_type == "sql_injection":
            # Check if the fix uses parameterized queries
            if '?' in fix and '[' in fix and ']' in fix:
                return True
            # Check if the input contains SQL injection patterns
            return not any(pattern in input_value.lower() for pattern in [
                "select", "insert", "update", "delete", "drop", "alter", "create",
                "1=1", "'='", "or 1", "or true", "--", "/*", "*/"
            ])
        
        # XSS
        elif vuln_type == "xss":
            # Check if the fix uses proper escaping
            if 'escapeHtml' in fix or 'escape(' in fix or 'encodeURIComponent' in fix:
                return True
            # Check if the input contains XSS patterns
            return not any(pattern in input_value.lower() for pattern in [
                "<script", "javascript:", "onerror=", "onload=", "onclick=", "alert(",
                "<img", "<iframe", "<svg", "<a href"
            ])
        
        # Command Injection
        elif vuln_type == "command_injection":
            # Check if the fix validates input
            if re.search(r'test\([^)]+\)', fix) and 'return res.status(400)' in fix:
                return True
            # Check if the input contains command injection patterns
            return not any(pattern in input_value for pattern in [
                ";", "|", "&", "$(", "`", "$(", ")", "rm ", "cat ", "/etc", "\\Windows"
            ])
        
        # Path Traversal
        elif vuln_type == "path_traversal":
            # Check if the fix validates paths
            if 'startsWith' in fix and 'baseDir' in fix:
                return True
            # Check if the input contains path traversal patterns
            return not any(pattern in input_value for pattern in [
                "..", "../", "..\\", "%2e", "/etc", "\\Windows", "System32"
            ])
        
        # Default: assume unsafe
        return False
    
    def enhanced_validate_fix(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """
        Perform enhanced validation of a fix.
        
        Args:
            vulnerability (Vulnerability): The vulnerability with a fix suggestion.
            
        Returns:
            Dict[str, Any]: Enhanced validation results.
        """
        if not vulnerability.fix_suggestion:
            return {
                "success": False,
                "message": "No fix suggestion available",
                "original_vulnerability": vulnerability,
                "static_analysis": None,
                "test_cases": None,
                "scanner_validation": None
            }
        
        try:
            # 1. Static Analysis
            static_analysis = self.static_analysis_check(vulnerability, vulnerability.fix_suggestion)
            
            # 2. Test Case Validation
            test_cases = self.test_case_validation(vulnerability, vulnerability.fix_suggestion)
            
            # 3. Scanner Validation (using the original validator)
            scanner_validation = super().validate_fix(vulnerability)
            
            # Combine results
            success = static_analysis["passed"] and test_cases["passed"] and scanner_validation["success"]
            
            return {
                "success": success,
                "message": "Enhanced fix validation completed",
                "original_vulnerability": vulnerability,
                "static_analysis": static_analysis,
                "test_cases": test_cases,
                "scanner_validation": scanner_validation
            }
        except Exception as e:
            logging.error(f"Error in enhanced validation: {e}")
            return {
                "success": False,
                "message": f"Error in enhanced validation: {e}",
                "original_vulnerability": vulnerability,
                "static_analysis": None,
                "test_cases": None,
                "scanner_validation": None
            }
    
    def enhanced_validate_fixes(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """
        Perform enhanced validation of multiple fixes.
        
        Args:
            vulnerabilities (List[Vulnerability]): The vulnerabilities with fix suggestions.
            
        Returns:
            List[Dict[str, Any]]: Enhanced validation results for each vulnerability.
        """
        results = []
        for vuln in vulnerabilities:
            if vuln.fix_suggestion:
                results.append(self.enhanced_validate_fix(vuln))
        
        return results
