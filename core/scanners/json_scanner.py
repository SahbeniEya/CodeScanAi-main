"""
JSON Scanner module for detecting vulnerabilities in JSON files.
Supports various JSON-based dependency files including package.json, composer.json, etc.
"""

import os
import re
import json
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
            },
            "4.17.11": {
                "id": "CVE-2019-10744",
                "severity": "HIGH",
                "description": "Versions of lodash prior to 4.17.16 are vulnerable to Prototype Pollution.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
                    "https://github.com/lodash/lodash/pull/4336",
                    "https://snyk.io/vuln/SNYK-JS-LODASH-450202"
                ]
            }
        },
        "jquery": {
            "3.4.1": {
                "id": "CVE-2020-11023",
                "severity": "MEDIUM",
                "description": "jQuery before 3.5.0 is vulnerable to Cross-Site Scripting.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
                    "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/",
                    "https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6"
                ]
            },
            "3.3.1": {
                "id": "CVE-2019-11358",
                "severity": "MEDIUM",
                "description": "jQuery before 3.4.0 is vulnerable to Prototype Pollution.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-11358",
                    "https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/",
                    "https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b"
                ]
            }
        }
    },
    "composer": {
        "symfony/symfony": {
            "4.2.0": {
                "id": "CVE-2019-10909",
                "severity": "HIGH",
                "description": "Symfony before 4.2.7 has an information disclosure vulnerability.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-10909",
                    "https://symfony.com/blog/cve-2019-10909-information-disclosure-in-the-httpfoundation-component",
                    "https://github.com/symfony/symfony/security/advisories/GHSA-xhh6-956q-4q69"
                ]
            }
        },
        "laravel/framework": {
            "5.8.0": {
                "id": "CVE-2021-21263",
                "severity": "HIGH",
                "description": "Laravel before 8.22.1, 7.30.3, 6.20.12 is vulnerable to SQL injection.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-21263",
                    "https://blog.laravel.com/security-laravel-62012-7303-8221-released",
                    "https://github.com/laravel/framework/security/advisories/GHSA-3p32-j457-pg5j"
                ]
            }
        }
    }
}

class JSONVulnerabilityScanner:
    """Scanner for JSON-related vulnerabilities and dependencies."""

    def __init__(self, nvd_api_key=None):
        """
        Initialize the JSON scanner.

        Args:
            nvd_api_key (str, optional): API key for the NVD API.
        """
        self.nvd_api_key = nvd_api_key
        self.vulnerabilities = []

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a JSON file for vulnerabilities.

        Args:
            file_path (str): Path to the file to scan.

        Returns:
            List[Vulnerability]: List of detected vulnerabilities.
        """
        self.vulnerabilities = []

        # Only scan JSON files
        if not file_path.lower().endswith('.json'):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    file_name = os.path.basename(file_path).lower()

                    # Check for different types of JSON files
                    if file_name == 'package.json' or 'dependencies' in data or 'devDependencies' in data:
                        self._scan_npm_package(file_path, data)
                    elif file_name == 'package-lock.json' and 'dependencies' in data:
                        self._scan_npm_lock(file_path, data)
                    elif file_name == 'composer.json' or 'require' in data:
                        self._scan_composer_package(file_path, data)
                    elif file_name == 'composer.lock' and 'packages' in data:
                        self._scan_composer_lock(file_path, data)
                    elif file_name == 'bower.json' and 'dependencies' in data:
                        self._scan_bower_package(file_path, data)
                    elif file_name == 'project.json' and 'dependencies' in data:
                        self._scan_dotnet_project(file_path, data)

                    # Generic scan for any JSON file
                    self._scan_generic_json(file_path, data)

                except json.JSONDecodeError:
                    logging.warning(f"Invalid JSON file: {file_path}")
        except Exception as e:
            logging.error(f"Error scanning JSON file {file_path}: {e}")

        return self.vulnerabilities

    def _scan_npm_package(self, file_path: str, data: dict):
        """
        Scan a package.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        # Process dependencies
        deps = []
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            for pkg, ver in data['dependencies'].items():
                deps.append((pkg, ver))

        # Process devDependencies
        if 'devDependencies' in data and isinstance(data['devDependencies'], dict):
            for pkg, ver in data['devDependencies'].items():
                deps.append((pkg, ver))

        # Process peerDependencies
        if 'peerDependencies' in data and isinstance(data['peerDependencies'], dict):
            for pkg, ver in data['peerDependencies'].items():
                deps.append((pkg, ver))

        # Process optionalDependencies
        if 'optionalDependencies' in data and isinstance(data['optionalDependencies'], dict):
            for pkg, ver in data['optionalDependencies'].items():
                deps.append((pkg, ver))

        # Check each dependency
        for dep_name, dep_version in deps:
            # Clean version string
            clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

            # First check known vulnerabilities
            if dep_name in KNOWN_VULNERABILITIES.get('npm', {}):
                pkg_vulns = KNOWN_VULNERABILITIES['npm'][dep_name]
                if clean_version in pkg_vulns:
                    vuln_info = pkg_vulns[clean_version]
                    vuln = Vulnerability(
                        id=f"SCA-JS-{vuln_info['id']}",
                        severity=vuln_info['severity'],
                        confidence="HIGH",
                        file_path=file_path,
                        line_number=0,  # Line number not applicable for dependencies
                        description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                        code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                        fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                    )
                    self.vulnerabilities.append(vuln)
                    logging.info(f"Found known vulnerability {vuln_info['id']} in {dep_name}:{clean_version}")
                    continue

            # Then check NVD
            try:
                nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "npm")
                if nvd_vulns:
                    # Use the first vulnerability found
                    vuln_info = nvd_vulns[0]
                    vuln = Vulnerability(
                        id=f"SCA-JS-{vuln_info['id']}",
                        severity=vuln_info['severity'],
                        confidence="HIGH",
                        file_path=file_path,
                        line_number=0,  # Line number not applicable for dependencies
                        description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                        code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                        fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                    )
                    self.vulnerabilities.append(vuln)
            except Exception as e:
                logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

    def _scan_npm_lock(self, file_path: str, data: dict):
        """
        Scan a package-lock.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            self._process_npm_lock_deps(file_path, data['dependencies'])

    def _process_npm_lock_deps(self, file_path: str, dependencies: dict):
        """
        Process dependencies from package-lock.json recursively.

        Args:
            file_path (str): Path to the package-lock.json file.
            dependencies (dict): Dependencies object from package-lock.json.
        """
        for dep_name, dep_info in dependencies.items():
            if isinstance(dep_info, dict) and 'version' in dep_info:
                # Clean version string
                clean_version = dep_info['version'].replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

                # First check known vulnerabilities
                if dep_name in KNOWN_VULNERABILITIES.get('npm', {}):
                    pkg_vulns = KNOWN_VULNERABILITIES['npm'][dep_name]
                    if clean_version in pkg_vulns:
                        vuln_info = pkg_vulns[clean_version]
                        vuln = Vulnerability(
                            id=f"SCA-JS-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                        logging.info(f"Found known vulnerability {vuln_info['id']} in {dep_name}:{clean_version}")
                        continue

                # Then check NVD
                try:
                    nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "npm")
                    if nvd_vulns:
                        # Use the first vulnerability found
                        vuln_info = nvd_vulns[0]
                        vuln = Vulnerability(
                            id=f"SCA-JS-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

                # Process nested dependencies
                if 'dependencies' in dep_info and isinstance(dep_info['dependencies'], dict):
                    self._process_npm_lock_deps(file_path, dep_info['dependencies'])

    def _scan_composer_package(self, file_path: str, data: dict):
        """
        Scan a composer.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        # Process require dependencies
        if 'require' in data and isinstance(data['require'], dict):
            for dep_name, dep_version in data['require'].items():
                # Skip PHP version constraint
                if dep_name == 'php':
                    continue
                # Clean version string
                clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

                # First check known vulnerabilities
                if dep_name in KNOWN_VULNERABILITIES.get('composer', {}):
                    pkg_vulns = KNOWN_VULNERABILITIES['composer'][dep_name]
                    if clean_version in pkg_vulns:
                        vuln_info = pkg_vulns[clean_version]
                        vuln = Vulnerability(
                            id=f"SCA-PHP-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                        logging.info(f"Found known vulnerability {vuln_info['id']} in {dep_name}:{clean_version}")
                        continue

                # Then check NVD
                try:
                    nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "composer")
                    if nvd_vulns:
                        # Use the first vulnerability found
                        vuln_info = nvd_vulns[0]
                        vuln = Vulnerability(
                            id=f"SCA-PHP-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

        # Process require-dev dependencies
        if 'require-dev' in data and isinstance(data['require-dev'], dict):
            for dep_name, dep_version in data['require-dev'].items():
                # Skip PHP version constraint
                if dep_name == 'php':
                    continue
                # Clean version string
                clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

                # Check for vulnerabilities
                try:
                    nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "composer")
                    if nvd_vulns:
                        # Use the first vulnerability found
                        vuln_info = nvd_vulns[0]
                        vuln = Vulnerability(
                            id=f"SCA-PHP-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

    def _scan_composer_lock(self, file_path: str, data: dict):
        """
        Scan a composer.lock file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        if 'packages' in data and isinstance(data['packages'], list):
            for package in data['packages']:
                if 'name' in package and 'version' in package:
                    dep_name = package['name']
                    dep_version = package['version']

                    # Clean version string
                    clean_version = dep_version.replace('v', '')

                    # Check for vulnerabilities
                    try:
                        nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "composer")
                        if nvd_vulns:
                            # Use the first vulnerability found
                            vuln_info = nvd_vulns[0]
                            vuln = Vulnerability(
                                id=f"SCA-PHP-{vuln_info['id']}",
                                severity=vuln_info['severity'],
                                confidence="HIGH",
                                file_path=file_path,
                                line_number=0,  # Line number not applicable for dependencies
                                description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                                code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                                fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                            )
                            self.vulnerabilities.append(vuln)
                    except Exception as e:
                        logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

    def _scan_bower_package(self, file_path: str, data: dict):
        """
        Scan a bower.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            for dep_name, dep_version in data['dependencies'].items():
                # Clean version string
                clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

                # Check for vulnerabilities
                try:
                    nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "npm")  # Use npm ecosystem for Bower
                    if nvd_vulns:
                        # Use the first vulnerability found
                        vuln_info = nvd_vulns[0]
                        vuln = Vulnerability(
                            id=f"SCA-BOWER-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

    def _scan_dotnet_project(self, file_path: str, data: dict):
        """
        Scan a project.json (.NET Core) file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            for dep_name, dep_version in data['dependencies'].items():
                # Handle version as string or object
                if isinstance(dep_version, str):
                    clean_version = dep_version.replace('*', '').replace('^', '').replace('~', '')
                elif isinstance(dep_version, dict) and 'version' in dep_version:
                    clean_version = dep_version['version'].replace('*', '').replace('^', '').replace('~', '')
                else:
                    continue

                # Check for vulnerabilities
                try:
                    nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "nuget")
                    if nvd_vulns:
                        # Use the first vulnerability found
                        vuln_info = nvd_vulns[0]
                        vuln = Vulnerability(
                            id=f"SCA-DOTNET-{vuln_info['id']}",
                            severity=vuln_info['severity'],
                            confidence="HIGH",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                            code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                            fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                        )
                        self.vulnerabilities.append(vuln)
                except Exception as e:
                    logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

    def _scan_generic_json(self, file_path: str, data: dict):
        """
        Scan a generic JSON file for dependencies.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
        """
        # Look for any key that might indicate a dependency
        dependency_keys = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies',
                          'requires', 'imports', 'packages', 'libraries', 'modules', 'components']

        for key in dependency_keys:
            if key in data and isinstance(data[key], dict):
                logging.info(f"Found potential dependencies in key '{key}' in {file_path}")
                for dep_name, dep_version in data[key].items():
                    if isinstance(dep_version, str):
                        # Clean version string
                        clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

                        # Check for vulnerabilities in npm
                        try:
                            nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "npm")
                            if nvd_vulns:
                                # Use the first vulnerability found
                                vuln_info = nvd_vulns[0]
                                vuln = Vulnerability(
                                    id=f"SCA-JSON-{vuln_info['id']}",
                                    severity=vuln_info['severity'],
                                    confidence="HIGH",
                                    file_path=file_path,
                                    line_number=0,  # Line number not applicable for dependencies
                                    description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                                    code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                                    fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                                )
                                self.vulnerabilities.append(vuln)
                        except Exception as e:
                            logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

                        # Also check for vulnerabilities in maven
                        try:
                            nvd_vulns = get_vulnerabilities_for_package(dep_name, clean_version, "maven")
                            if nvd_vulns:
                                # Use the first vulnerability found
                                vuln_info = nvd_vulns[0]
                                vuln = Vulnerability(
                                    id=f"SCA-JSON-{vuln_info['id']}",
                                    severity=vuln_info['severity'],
                                    confidence="HIGH",
                                    file_path=file_path,
                                    line_number=0,  # Line number not applicable for dependencies
                                    description=f"Vulnerable dependency: {dep_name} ({clean_version}). {vuln_info['description']}",
                                    code=f"Package: {dep_name}\nVersion: {clean_version}\nVulnerability: {vuln_info['id']}",
                                    fix_suggestion=f"Update {dep_name} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                                )
                                self.vulnerabilities.append(vuln)
                        except Exception as e:
                            logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

        # Recursively check nested objects
        for key, value in data.items():
            if isinstance(value, dict):
                self._scan_generic_json(file_path, value)


def scan_json_files(directory: str, nvd_api_key=None) -> List[Vulnerability]:
    """
    Scan JSON files in a directory for vulnerabilities.

    Args:
        directory (str): Path to the directory to scan.
        nvd_api_key (str, optional): API key for the NVD API.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    vulnerabilities = []

    # Create scanner with available API keys
    json_scanner = JSONVulnerabilityScanner(nvd_api_key=nvd_api_key)

    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    file_vulns = json_scanner.scan_file(file_path)
                    vulnerabilities.extend(file_vulns)
                except Exception as e:
                    logging.error(f"Error scanning JSON file {file_path}: {e}")

    return vulnerabilities
