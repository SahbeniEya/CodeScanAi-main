"""
This module provides JSON report generation for security scan results.
"""

import os
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

class JSONReporter:
    """
    JSON reporter for security scan results.
    """
    
    def __init__(self, input_file: str, output_file: str):
        """
        Initialize the JSON reporter.
        
        Args:
            input_file (str): Path to the input JSON file.
            output_file (str): Path to the output JSON file.
        """
        self.input_file = input_file
        self.output_file = output_file
    
    def generate_report(self) -> None:
        """
        Generate a JSON report from the scan results.
        """
        try:
            # Read the scan results
            with open(self.input_file, 'r', encoding='utf-8') as f:
                scan_results = json.load(f)
            
            # Extract vulnerabilities
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            # Count vulnerabilities by severity
            high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
            medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
            low_count = len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
            total_count = len(vulnerabilities)
            
            # Count vulnerabilities by type
            vulnerability_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('id', '').split('-')[0]
                if vuln_type not in vulnerability_types:
                    vulnerability_types[vuln_type] = 0
                vulnerability_types[vuln_type] += 1
            
            # Group vulnerabilities by file
            vulnerabilities_by_file = {}
            for vuln in vulnerabilities:
                file_path = vuln.get('file_path', 'unknown')
                if file_path not in vulnerabilities_by_file:
                    vulnerabilities_by_file[file_path] = []
                vulnerabilities_by_file[file_path].append(vuln)
            
            # Create the report
            report = {
                'summary': {
                    'high_count': high_count,
                    'medium_count': medium_count,
                    'low_count': low_count,
                    'total_count': total_count,
                    'vulnerability_types': vulnerability_types
                },
                'vulnerabilities': vulnerabilities,
                'vulnerabilities_by_file': vulnerabilities_by_file,
                'generated_at': datetime.now().isoformat(),
                'scan_results': scan_results
            }
            
            # Write the JSON report
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            
            logging.info(f"JSON report generated: {self.output_file}")
        except Exception as e:
            logging.error(f"Error generating JSON report: {e}")


def main():
    """
    Main function to generate a JSON report from the command line.
    """
    parser = argparse.ArgumentParser(description='Generate a JSON report from security scan results.')
    parser.add_argument('--input-file', '-i', required=True, help='Path to the input JSON file')
    parser.add_argument('--output-file', '-o', required=True, help='Path to the output JSON file')
    
    args = parser.parse_args()
    
    reporter = JSONReporter(args.input_file, args.output_file)
    reporter.generate_report()


if __name__ == '__main__':
    main()
