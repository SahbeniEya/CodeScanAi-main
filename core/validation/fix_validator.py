"""
This module provides functionality to validate fixes for security vulnerabilities.
"""

import logging
import os
import tempfile
import shutil
from typing import List, Dict, Any, Tuple

from core.scanners.sast_scanner import Vulnerability, scan_directory

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class FixValidator:
    """
    Validates fixes for security vulnerabilities.
    """
    
    def __init__(self, directory: str):
        """
        Initialize the fix validator.
        
        Args:
            directory (str): The directory containing the code to validate.
        """
        self.directory = directory
    
    def apply_fix_to_temp_file(self, vulnerability: Vulnerability) -> Tuple[str, str]:
        """
        Apply a fix to a temporary copy of the file.
        
        Args:
            vulnerability (Vulnerability): The vulnerability with a fix suggestion.
            
        Returns:
            Tuple[str, str]: The path to the temporary directory and the path to the modified file.
        """
        if not vulnerability.fix_suggestion:
            raise ValueError("Vulnerability does not have a fix suggestion")
        
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Copy the directory structure
        for root, dirs, files in os.walk(self.directory):
            for directory in dirs:
                os.makedirs(os.path.join(temp_dir, os.path.relpath(os.path.join(root, directory), self.directory)), exist_ok=True)
        
        # Copy all files
        for root, _, files in os.walk(self.directory):
            for file in files:
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, self.directory)
                dst_path = os.path.join(temp_dir, rel_path)
                
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
        
        # Get the path to the file with the vulnerability
        file_path = os.path.join(temp_dir, vulnerability.file_path)
        
        # Read the file
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Extract the vulnerable code lines
        vulnerable_code = vulnerability.code.strip()
        
        # Find the vulnerable code in the file
        found = False
        start_line = max(0, vulnerability.line_number - 5)
        end_line = min(len(lines), vulnerability.line_number + 5)
        
        for i in range(start_line, end_line):
            # Check if this line contains the start of the vulnerable code
            if vulnerable_code.split('\n')[0] in lines[i]:
                # Check if the next lines match the rest of the vulnerable code
                vulnerable_lines = vulnerable_code.split('\n')
                if all(j + i < len(lines) and vulnerable_lines[j] in lines[i + j] for j in range(len(vulnerable_lines))):
                    # Replace the vulnerable code with the fix
                    for j in range(len(vulnerable_lines)):
                        lines[i + j] = lines[i + j].replace(vulnerable_lines[j], vulnerability.fix_suggestion.split('\n')[j] if j < len(vulnerability.fix_suggestion.split('\n')) else '')
                    found = True
                    break
        
        if not found:
            # If we couldn't find the exact code, just replace the line
            if 0 <= vulnerability.line_number - 1 < len(lines):
                lines[vulnerability.line_number - 1] = vulnerability.fix_suggestion + '\n'
        
        # Write the modified file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        return temp_dir, file_path
    
    def validate_fix(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """
        Validate a fix for a vulnerability.
        
        Args:
            vulnerability (Vulnerability): The vulnerability with a fix suggestion.
            
        Returns:
            Dict[str, Any]: Validation results.
        """
        if not vulnerability.fix_suggestion:
            return {
                "success": False,
                "message": "No fix suggestion available",
                "original_vulnerability": vulnerability,
                "remaining_vulnerabilities": []
            }
        
        try:
            # Apply the fix to a temporary copy of the file
            temp_dir, _ = self.apply_fix_to_temp_file(vulnerability)
            
            try:
                # Scan the temporary directory
                new_vulnerabilities = scan_directory(temp_dir)
                
                # Check if the vulnerability still exists
                remaining_vulnerabilities = []
                for vuln in new_vulnerabilities:
                    if (vuln.id == vulnerability.id and 
                        vuln.file_path == vulnerability.file_path and 
                        vuln.line_number == vulnerability.line_number):
                        remaining_vulnerabilities.append(vuln)
                
                return {
                    "success": len(remaining_vulnerabilities) == 0,
                    "message": "Fix validation completed",
                    "original_vulnerability": vulnerability,
                    "remaining_vulnerabilities": remaining_vulnerabilities
                }
            finally:
                # Clean up the temporary directory
                shutil.rmtree(temp_dir)
        except Exception as e:
            logging.error(f"Error validating fix: {e}")
            return {
                "success": False,
                "message": f"Error validating fix: {e}",
                "original_vulnerability": vulnerability,
                "remaining_vulnerabilities": []
            }
    
    def validate_fixes(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """
        Validate fixes for multiple vulnerabilities.
        
        Args:
            vulnerabilities (List[Vulnerability]): The vulnerabilities with fix suggestions.
            
        Returns:
            List[Dict[str, Any]]: Validation results for each vulnerability.
        """
        results = []
        for vuln in vulnerabilities:
            if vuln.fix_suggestion:
                results.append(self.validate_fix(vuln))
        
        return results
