"""
Dependency Scanner module for detecting vulnerabilities in dependency files.
Supports various text-based dependency files including requirements.txt, build.gradle, etc.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Tuple

from core.scanners.sast_scanner import Vulnerability
from core.scanners.nvd_connector import get_vulnerabilities_for_package

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Known vulnerable dependencies for direct checking
KNOWN_VULNERABILITIES = {
    "pypi": {
        "django": {
            "1.11.0": {
                "id": "CVE-2019-19844",
                "severity": "HIGH",
                "description": "Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover via password reset form.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-19844",
                    "https://www.djangoproject.com/weblog/2019/dec/18/security-releases/",
                    "https://github.com/django/django/commit/d63e2b0e9a02ec644c0a6afc9c6c292f5e16b607"
                ]
            }
        },
        "flask": {
            "0.12.0": {
                "id": "CVE-2019-1010083",
                "severity": "HIGH",
                "description": "Flask before 1.0 allows attackers to cause a denial of service via a cookie that is too large.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-1010083",
                    "https://github.com/pallets/flask/pull/2695",
                    "https://github.com/pallets/flask/issues/2691"
                ]
            }
        }
    },
    "maven": {
        "org.apache.struts:struts2-core": {
            "2.3.30": {
                "id": "CVE-2017-5638",
                "severity": "CRITICAL",
                "description": "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling that allows remote attackers to execute arbitrary commands.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
                    "https://cwiki.apache.org/confluence/display/WW/S2-045",
                    "https://github.com/apache/struts/pull/107"
                ]
            }
        }
    },
    "npm": {
        "lodash": {
            "4.17.15": {
                "id": "CVE-2019-10744",
                "severity": "HIGH",
                "description": "Versions of lodash prior to 4.17.16 are vulnerable to Prototype Pollution.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
                    "https://github.com/lodash/lodash/pull/4336",
                    "https://snyk.io/vuln/SNYK-JS-LODASH-450202"
                ]
            }
        }
    }
}

class TextVulnerabilityScanner:
    """Scanner for text-based dependency file vulnerabilities."""

    def __init__(self, nvd_api_key=None):
        """
        Initialize the dependency scanner.

        Args:
            nvd_api_key (str, optional): API key for the NVD API.
        """
        self.nvd_api_key = nvd_api_key
        self.vulnerabilities = []

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a text file for dependency vulnerabilities.

        Args:
            file_path (str): Path to the file to scan.

        Returns:
            List[Vulnerability]: List of detected vulnerabilities.
        """
        self.vulnerabilities = []

        try:
            # Check if file exists
            if not os.path.isfile(file_path):
                logging.error(f"File not found: {file_path}")
                return []

            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Skip empty files
            if not content.strip():
                return []

            # Determine file type based on extension and content
            file_name = os.path.basename(file_path).lower()

            # Python requirements.txt
            if file_name == 'requirements.txt' or self._is_python_requirements(content):
                self._scan_python_requirements(file_path, content)

            # Gradle build files
            elif file_name.endswith('.gradle') or 'dependencies {' in content:
                self._scan_gradle_file(file_path, content)

            # Maven pom.properties
            elif file_name == 'pom.properties':
                self._scan_maven_properties(file_path, content)

            # .NET packages.config
            elif file_name == 'packages.config':
                self._scan_dotnet_packages(file_path, content)

            # Ruby Gemfile
            elif file_name == 'gemfile' or file_name == 'gemfile.lock':
                self._scan_ruby_gemfile(file_path, content)

            # Package.json for npm
            elif file_name == 'package.json':
                self._scan_npm_package(file_path, content)

            # Maven pom.xml
            elif file_name == 'pom.xml':
                self._scan_maven_pom(file_path, content)

        except Exception as e:
            logging.error(f"Error scanning dependency file {file_path}: {e}")

        return self.vulnerabilities

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for dependency vulnerabilities.

        Args:
            directory (str): Directory to scan.

        Returns:
            List[Vulnerability]: List of detected vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_vulns = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulns)
                except Exception as e:
                    logging.error(f"Error scanning {file_path}: {e}")
                    
        return vulnerabilities

    def _is_python_requirements(self, content: str) -> bool:
        """
        Check if the content looks like a Python requirements.txt file.

        Args:
            content (str): File content.

        Returns:
            bool: True if it looks like a requirements.txt file.
        """
        # Look for common patterns in requirements.txt files
        lines = content.split('\n')
        package_lines = 0

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check for package==version pattern
            if re.match(r'^[a-zA-Z0-9\._-]+(==|>=|<=|~=|!=|>|<)[0-9\.]+', line):
                package_lines += 1

        # If more than 50% of non-empty lines look like package requirements, it's likely a requirements file
        non_empty_lines = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        return non_empty_lines > 0 and package_lines / non_empty_lines > 0.5

    def _scan_python_requirements(self, file_path: str, content: str):
        """
        Scan a Python requirements.txt file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            content (str): File content.
        """
        logging.info(f"Scanning Python requirements file: {file_path}")

        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Extract package name and version
            match = re.match(r'^([a-zA-Z0-9\._-]+)(==|>=|<=|~=|!=|>|<)([0-9\.]+)', line)
            if match:
                package = match.group(1).lower()
                version = match.group(3)

                # First check known vulnerabilities
                if package in KNOWN_VULNERABILITIES.get('pypi', {}):
                    pkg_vulns = KNOWN_VULNERABILITIES['pypi'][package]
                    if version in pkg_vulns:
                        vuln_info = pkg_vulns[version]
                        vuln = Vulnerability(
                            id=f"SCA-PYTHON-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                            code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {package} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                        logging.info(f"Found known vulnerability {vuln_info['id']} in {package}:{version}")
                        continue

                # Then check NVD
                try:
                    nvd_vulns = get_vulnerabilities_for_package(package, version, "pypi")
                    if nvd_vulns:
                        # Use the first vulnerability found
                        vuln_info = nvd_vulns[0]
                        vuln = Vulnerability(
                            id=f"SCA-PYTHON-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                            code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {package} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logging.error(f"Error checking NVD for {package} ({version}): {e}")
