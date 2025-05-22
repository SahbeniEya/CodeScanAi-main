"""
This module provides a Software Composition Analysis (SCA) scanner for detecting vulnerable dependencies.
"""

import os
import json
import logging
import tempfile
import subprocess
import sys
from typing import List, Dict, Any, Optional
import requests

from core.scanners.sast_scanner import Vulnerability

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

class DependencyScanner:
    """
    Scanner for detecting vulnerable dependencies in projects.
    """
    
    def __init__(self):
        """
        Initialize the dependency scanner.
        """
        self._check_dependencies_installed()
    
    def _check_dependencies_installed(self):
        """
        Check if npm is installed, and install it if not.
        """
        try:
            # Check if npm is installed
            subprocess.check_output(["npm", "--version"], stderr=subprocess.STDOUT)
            logging.info("npm is already installed")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"npm is not installed: {e}")
            raise RuntimeError(
                "npm is required for dependency scanning. Please install Node.js and npm."
            )
    
    def scan_project(self, directory: str) -> List[Vulnerability]:
        """
        Scan a project for vulnerable dependencies.
        
        Args:
            directory (str): Path to the project directory.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        # Check for package.json
        package_json_path = os.path.join(directory, 'package.json')
        if not os.path.exists(package_json_path):
            logging.info(f"No package.json found in {directory}, skipping dependency scan")
            return vulnerabilities
        
        # Run npm audit
        npm_audit_vulnerabilities = self._run_npm_audit(directory)
        vulnerabilities.extend(npm_audit_vulnerabilities)
        
        # Check for outdated dependencies
        outdated_vulnerabilities = self._check_outdated_dependencies(directory)
        vulnerabilities.extend(outdated_vulnerabilities)
        
        logging.info(f"Found {len(vulnerabilities)} vulnerable dependencies in {directory}")
        return vulnerabilities
    
    def _run_npm_audit(self, directory: str) -> List[Vulnerability]:
        """
        Run npm audit to find vulnerable dependencies.
        
        Args:
            directory (str): Path to the project directory.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        try:
            # Change to the project directory
            original_dir = os.getcwd()
            os.chdir(directory)
            
            # Run npm audit
            cmd = ["npm", "audit", "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Change back to the original directory
            os.chdir(original_dir)
            
            # Parse npm audit output
            if result.stdout:
                try:
                    audit_results = json.loads(result.stdout)
                    
                    # Extract vulnerabilities from npm audit results
                    if 'vulnerabilities' in audit_results:
                        for package_name, vuln_info in audit_results['vulnerabilities'].items():
                            severity = self._map_npm_severity(vuln_info.get('severity', 'low'))
                            
                            # Create a vulnerability for each vulnerable dependency
                            vuln = Vulnerability(
                                file_path=os.path.join(directory, 'package.json'),
                                line_number=0,  # Line number not applicable for dependencies
                                vulnerability_type=f"SCA-VULNERABLE-DEPENDENCY",
                                severity=severity,
                                description=f"Vulnerable dependency: {package_name} ({vuln_info.get('version', 'unknown')}). {vuln_info.get('title', '')}",
                                confidence="HIGH",
                                code_snippet=f"Package: {package_name}\\nVersion: {vuln_info.get('version', 'unknown')}\\nVulnerability: {vuln_info.get('title', '')}",
                                fix_suggestion=self._generate_dependency_fix(package_name, vuln_info)
                            )
                            
                            vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse npm audit output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running npm audit: {e}")
        except Exception as e:
            logging.error(f"Error in npm audit scan: {e}")
        
        return vulnerabilities
    
    def _check_outdated_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Check for outdated dependencies.
        
        Args:
            directory (str): Path to the project directory.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        try:
            # Change to the project directory
            original_dir = os.getcwd()
            os.chdir(directory)
            
            # Run npm outdated
            cmd = ["npm", "outdated", "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Change back to the original directory
            os.chdir(original_dir)
            
            # Parse npm outdated output
            if result.stdout:
                try:
                    outdated_results = json.loads(result.stdout)
                    
                    # Extract outdated dependencies
                    for package_name, package_info in outdated_results.items():
                        current = package_info.get('current', 'unknown')
                        latest = package_info.get('latest', 'unknown')
                        
                        # Only consider major version differences as medium severity
                        severity = "LOW"
                        if self._is_major_version_difference(current, latest):
                            severity = "MEDIUM"
                        
                        # Create a vulnerability for each outdated dependency
                        vuln = Vulnerability(
                            file_path=os.path.join(directory, 'package.json'),
                            line_number=0,  # Line number not applicable for dependencies
                            vulnerability_type=f"SCA-OUTDATED-DEPENDENCY",
                            severity=severity,
                            description=f"Outdated dependency: {package_name} (current: {current}, latest: {latest})",
                            confidence="MEDIUM",
                            code_snippet=f"Package: {package_name}\\nCurrent: {current}\\nLatest: {latest}",
                            fix_suggestion=f"Update {package_name} to the latest version ({latest}) by running:\\n\\n```\\nnpm install {package_name}@latest --save\\n```"
                        )
                        
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse npm outdated output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running npm outdated: {e}")
        except Exception as e:
            logging.error(f"Error in outdated dependencies scan: {e}")
        
        return vulnerabilities
    
    def _map_npm_severity(self, severity: str) -> str:
        """
        Map npm severity to our severity levels.
        
        Args:
            severity (str): npm severity (low, moderate, high, critical).
            
        Returns:
            str: Severity level (LOW, MEDIUM, HIGH).
        """
        severity = severity.lower()
        if severity == 'critical':
            return "HIGH"
        elif severity in ('high', 'moderate'):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _is_major_version_difference(self, current: str, latest: str) -> bool:
        """
        Check if there is a major version difference between current and latest.
        
        Args:
            current (str): Current version.
            latest (str): Latest version.
            
        Returns:
            bool: True if there is a major version difference, False otherwise.
        """
        try:
            # Extract major version numbers
            current_major = int(current.split('.')[0])
            latest_major = int(latest.split('.')[0])
            
            return latest_major > current_major
        except (ValueError, IndexError):
            return False
    
    def _generate_dependency_fix(self, package_name: str, vuln_info: Dict[str, Any]) -> str:
        """
        Generate a fix suggestion for a vulnerable dependency.
        
        Args:
            package_name (str): Name of the vulnerable package.
            vuln_info (Dict[str, Any]): Vulnerability information from npm audit.
            
        Returns:
            str: Fix suggestion.
        """
        if 'fixAvailable' in vuln_info and vuln_info['fixAvailable']:
            if isinstance(vuln_info['fixAvailable'], bool):
                return f"Update {package_name} to a non-vulnerable version by running:\\n\\n```\\nnpm update {package_name} --save\\n```"
            else:
                fix_version = vuln_info['fixAvailable'].get('version', 'latest')
                return f"Update {package_name} to version {fix_version} by running:\\n\\n```\\nnpm install {package_name}@{fix_version} --save\\n```"
        else:
            return f"No direct fix available for {package_name}. Consider finding an alternative package or checking for patches."


def scan_dependencies(directory: str) -> List[Vulnerability]:
    """
    Scan a project for vulnerable dependencies.
    
    Args:
        directory (str): Path to the project directory.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = DependencyScanner()
    return scanner.scan_project(directory)
