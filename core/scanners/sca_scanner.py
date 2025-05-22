"""
This module provides Software Composition Analysis (SCA) capabilities to detect vulnerable dependencies.
"""

import os
import json
import logging
import re
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Tuple

from core.scanners.nvd_connector import get_vulnerabilities_for_package, get_vulnerability_details
from core.scanners.sast_scanner import Vulnerability
from core.providers.huggingface_provider import HuggingFaceProvider

# Import scanner functions
from core.scanners import xml_scanner

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Dependency file patterns
DEPENDENCY_FILES = {
    'python': ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py', 'pyproject.toml', 'poetry.lock', 'conda.yaml', 'environment.yml'],
    'javascript': ['package.json', 'package-lock.json', 'yarn.lock', 'npm-shrinkwrap.json', 'bower.json', '.npmrc', '.yarnrc'],
    'java': ['pom.xml', 'build.gradle', 'build.gradle.kts', '.classpath', 'ivy.xml', 'gradle.properties', 'maven-wrapper.properties'],
    'ruby': ['Gemfile', 'Gemfile.lock', '.gemspec'],
    'php': ['composer.json', 'composer.lock'],
    'go': ['go.mod', 'go.sum', 'Gopkg.toml', 'Gopkg.lock', 'glide.yaml', 'glide.lock'],
    'dotnet': ['*.csproj', '*.fsproj', '*.vbproj', 'packages.config', 'project.json', 'project.assets.json', 'project.lock.json'],
    'docker': ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.dockerignore'],
    'kubernetes': ['*.yaml', '*.yml', 'Chart.yaml', 'values.yaml'],
    'shell': ['*.sh', '*.bash', '*.zsh', '*.fish'],
    'config': ['*.conf', '*.cfg', '*.ini', '*.properties', '*.env', '.env*'],
    'generic': ['*.txt', '*.xml', '*.json', '*.yaml', '*.yml', '*.lock', '*.config', '*.properties', '*.ini', '*.toml'],
}

# Known vulnerable dependencies (simplified database)
# In a real implementation, this would be fetched from a vulnerability database
KNOWN_VULNERABILITIES = {
    'python': {
        'django': {
            '1.11.0': {
                'id': 'CVE-2019-19844',
                'severity': 'HIGH',
                'description': 'Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover through password reset.',
                'fix_version': '1.11.27'
            },
            '2.0.0': {
                'id': 'CVE-2019-19844',
                'severity': 'HIGH',
                'description': 'Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover through password reset.',
                'fix_version': '2.2.9'
            }
        },
        'flask': {
            '0.12.0': {
                'id': 'CVE-2019-1010083',
                'severity': 'MEDIUM',
                'description': 'Flask before 1.0 allows attackers to cause a denial of service via a cookie that is handled by the Werkzeug before_request function.',
                'fix_version': '1.0.0'
            }
        }
    },
    'javascript': {
        'lodash': {
            '4.17.0': {
                'id': 'CVE-2019-10744',
                'severity': 'HIGH',
                'description': 'Versions of lodash prior to 4.17.12 are vulnerable to Prototype Pollution.',
                'fix_version': '4.17.12'
            }
        },
        'jquery': {
            '1.9.0': {
                'id': 'CVE-2019-11358',
                'severity': 'MEDIUM',
                'description': 'jQuery before 3.4.0 mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution.',
                'fix_version': '3.4.0'
            }
        }
    },
    'java': {
        'org.apache.struts:struts2-core': {
            '2.3.0': {
                'id': 'CVE-2017-5638',
                'severity': 'HIGH',
                'description': 'The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 has a remote code execution vulnerability.',
                'fix_version': '2.3.32'
            }
        },
        'com.fasterxml.jackson.core:jackson-databind': {
            '2.9.0': {
                'id': 'CVE-2019-12384',
                'severity': 'HIGH',
                'description': 'A deserialization vulnerability in FasterXML jackson-databind before 2.9.9.1 allows attackers to execute arbitrary code.',
                'fix_version': '2.9.9.1'
            }
        }
    }
}

class SCAScanner:
    """
    Scanner for detecting vulnerable dependencies in projects.
    """

    def __init__(self, model_name=None):
        """
        Initialize the SCA scanner.

        Args:
            model_name (str, optional): Name of the AI model to use for scanning.
                                       Defaults to None, which will use the default model.
        """
        self.model_name = model_name or "mistralai/Mistral-7B-Instruct-v0.3"
        self.ai_provider = None

        # Try to initialize the AI provider
        try:
            self.ai_provider = HuggingFaceProvider(self.model_name)
            logging.info(f"Initialized AI provider with model: {self.model_name}")
        except Exception as e:
            logging.warning(f"Failed to initialize AI provider: {e}. Will use traditional scanning methods only.")
            self.ai_provider = None

    def scan_directory(self, directory: str, nvd_api_key=None, huggingface_token=None, use_ai_scan=True) -> List[Vulnerability]:
        """
        Scan a directory for vulnerable dependencies.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.
            huggingface_token (str, optional): Token for Hugging Face API.
            use_ai_scan (bool, optional): Whether to use AI-based scanning. Defaults to True.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(directory):
            logging.error(f"Directory not found: {directory}")
            return []

        vulnerabilities = []

        # Log the NVD API key status
        if nvd_api_key:
            logging.info("NVD API key provided for SCA scanning")
        else:
            logging.warning("No NVD API key provided for SCA scanning. Some vulnerabilities may not be detected.")
            # Try to get from environment variable
            nvd_api_key = os.environ.get("NVD_API_KEY")
            if nvd_api_key:
                logging.info("Found NVD API key in environment variables")

        # If AI scanning is enabled and we have an AI provider, use it
        if use_ai_scan and self.ai_provider:
            logging.info(f"Using AI-based scanning with model: {self.model_name}")
            ai_vulns = self._scan_with_ai(directory)
            if ai_vulns:
                logging.info(f"Found {len(ai_vulns)} vulnerabilities using AI-based scanning")
                return ai_vulns

        # Scan for Python dependencies
        logging.info("Scanning for Python dependencies...")
        python_vulns = self._scan_python_dependencies(directory)
        vulnerabilities.extend(python_vulns)
        logging.info(f"Found {len(python_vulns)} Python dependency vulnerabilities")

        # Scan for JavaScript dependencies
        logging.info("Scanning for JavaScript dependencies...")
        js_vulns = self._scan_javascript_dependencies(directory)
        vulnerabilities.extend(js_vulns)
        logging.info(f"Found {len(js_vulns)} JavaScript dependency vulnerabilities")

        # Scan for Java dependencies
        logging.info("Scanning for Java dependencies...")
        java_vulns = self._scan_java_dependencies(directory)
        vulnerabilities.extend(java_vulns)
        logging.info(f"Found {len(java_vulns)} Java dependency vulnerabilities")

        # Scan for Ruby dependencies
        logging.info("Scanning for Ruby dependencies...")
        ruby_vulns = self._scan_ruby_dependencies(directory)
        vulnerabilities.extend(ruby_vulns)
        logging.info(f"Found {len(ruby_vulns)} Ruby dependency vulnerabilities")

        # Scan for PHP dependencies
        logging.info("Scanning for PHP dependencies...")
        php_vulns = self._scan_php_dependencies(directory)
        vulnerabilities.extend(php_vulns)
        logging.info(f"Found {len(php_vulns)} PHP dependency vulnerabilities")

        # Scan for Go dependencies
        logging.info("Scanning for Go dependencies...")
        go_vulns = self._scan_go_dependencies(directory)
        vulnerabilities.extend(go_vulns)
        logging.info(f"Found {len(go_vulns)} Go dependency vulnerabilities")

        # Scan XML files for vulnerabilities
        logging.info("Scanning XML files for vulnerabilities...")
        xml_vulns = self._scan_xml_files(directory, nvd_api_key, huggingface_token)
        vulnerabilities.extend(xml_vulns)
        logging.info(f"Found {len(xml_vulns)} XML vulnerabilities")

        # Scan JSON files for vulnerabilities
        logging.info("Scanning JSON files for vulnerabilities...")
        json_vulns = self._scan_json_files(directory, nvd_api_key)
        vulnerabilities.extend(json_vulns)
        logging.info(f"Found {len(json_vulns)} JSON vulnerabilities")

        # Scan Docker files for dependencies
        logging.info("Scanning Docker files for dependencies...")
        docker_vulns = self._scan_docker_files(directory, nvd_api_key)
        vulnerabilities.extend(docker_vulns)
        logging.info(f"Found {len(docker_vulns)} vulnerabilities in Docker files")

        # Scan Kubernetes files for dependencies
        logging.info("Scanning Kubernetes files for dependencies...")
        k8s_vulns = self._scan_kubernetes_files(directory, nvd_api_key)
        vulnerabilities.extend(k8s_vulns)
        logging.info(f"Found {len(k8s_vulns)} vulnerabilities in Kubernetes files")

        # Scan shell scripts for dependencies
        logging.info("Scanning shell scripts for dependencies...")
        shell_vulns = self._scan_shell_scripts(directory, nvd_api_key)
        vulnerabilities.extend(shell_vulns)
        logging.info(f"Found {len(shell_vulns)} vulnerabilities in shell scripts")

        # Scan configuration files for dependencies
        logging.info("Scanning configuration files for dependencies...")
        config_vulns = self._scan_config_files(directory, nvd_api_key)
        vulnerabilities.extend(config_vulns)
        logging.info(f"Found {len(config_vulns)} vulnerabilities in configuration files")

        # Scan generic text files for dependencies
        logging.info("Scanning generic text files for dependencies...")
        generic_vulns = self._scan_generic_files(directory, nvd_api_key)
        vulnerabilities.extend(generic_vulns)
        logging.info(f"Found {len(generic_vulns)} vulnerabilities in generic files")

        logging.info(f"Found {len(vulnerabilities)} vulnerable dependencies in {directory}")
        return vulnerabilities

    def _find_dependency_files(self, directory: str, file_patterns: List[str]) -> List[str]:
        """
        Find dependency files in a directory.

        Args:
            directory (str): Path to the directory to scan.
            file_patterns (List[str]): List of file patterns to look for.

        Returns:
            List[str]: List of found dependency files.
        """
        dependency_files = []

        for root, _, files in os.walk(directory):
            for file in files:
                for pattern in file_patterns:
                    if pattern.startswith('*'):
                        # Handle wildcard patterns like *.csproj
                        if file.endswith(pattern[1:]):
                            dependency_files.append(os.path.join(root, file))
                    elif file == pattern:
                        dependency_files.append(os.path.join(root, file))

        return dependency_files

    def _scan_python_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Scan Python dependencies for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []

        # Find Python dependency files
        dependency_files = self._find_dependency_files(directory, DEPENDENCY_FILES['python'])

        for file_path in dependency_files:
            if file_path.endswith('requirements.txt'):
                # Parse requirements.txt
                deps = self._parse_requirements_txt(file_path)
                for dep_name, dep_version in deps:
                    vuln = self._check_python_vulnerability(file_path, dep_name, dep_version)
                    if vuln:
                        vulnerabilities.append(vuln)
            elif file_path.endswith('setup.py'):
                # Parse setup.py
                deps = self._parse_setup_py(file_path)
                for dep_name, dep_version in deps:
                    vuln = self._check_python_vulnerability(file_path, dep_name, dep_version)
                    if vuln:
                        vulnerabilities.append(vuln)
            # Add support for other Python dependency files as needed

        return vulnerabilities

    def _parse_requirements_txt(self, file_path: str) -> List[Tuple[str, str]]:
        """
        Parse a requirements.txt file.

        Args:
            file_path (str): Path to the requirements.txt file.

        Returns:
            List[Tuple[str, str]]: List of (package_name, version) tuples.
        """
        dependencies = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Handle different version specifiers
                    if '==' in line:
                        parts = line.split('==')
                        package = parts[0].strip()
                        version = parts[1].strip().split(';')[0].strip()
                        dependencies.append((package, version))
                    elif '>=' in line:
                        parts = line.split('>=')
                        package = parts[0].strip()
                        version = parts[1].strip().split(';')[0].strip()
                        dependencies.append((package, version))
                    elif '<=' in line:
                        parts = line.split('<=')
                        package = parts[0].strip()
                        version = parts[1].strip().split(';')[0].strip()
                        dependencies.append((package, version))
        except Exception as e:
            logging.error(f"Error parsing requirements.txt: {e}")

        return dependencies

    def _parse_setup_py(self, file_path: str) -> List[Tuple[str, str]]:
        """
        Parse a setup.py file.

        Args:
            file_path (str): Path to the setup.py file.

        Returns:
            List[Tuple[str, str]]: List of (package_name, version) tuples.
        """
        dependencies = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # Look for install_requires
                install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if install_requires_match:
                    install_requires = install_requires_match.group(1)
                    for line in install_requires.split(','):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        # Remove quotes
                        line = line.strip('\'"')

                        # Handle different version specifiers
                        if '==' in line:
                            parts = line.split('==')
                            package = parts[0].strip()
                            version = parts[1].strip().split(';')[0].strip()
                            dependencies.append((package, version))
                        elif '>=' in line:
                            parts = line.split('>=')
                            package = parts[0].strip()
                            version = parts[1].strip().split(';')[0].strip()
                            dependencies.append((package, version))
                        elif '<=' in line:
                            parts = line.split('<=')
                            package = parts[0].strip()
                            version = parts[1].strip().split(';')[0].strip()
                            dependencies.append((package, version))
        except Exception as e:
            logging.error(f"Error parsing setup.py: {e}")

        return dependencies

    def _check_python_vulnerability(self, file_path: str, package: str, version: str) -> Optional[Vulnerability]:
        """
        Check if a Python package has known vulnerabilities.

        Args:
            file_path (str): Path to the dependency file.
            package (str): Package name.
            version (str): Package version.

        Returns:
            Optional[Vulnerability]: Vulnerability if found, None otherwise.
        """
        # First check local database
        if package.lower() in KNOWN_VULNERABILITIES.get('python', {}):
            vulns = KNOWN_VULNERABILITIES['python'][package.lower()]
            for vuln_version, vuln_info in vulns.items():
                if self._is_vulnerable_version(version, vuln_version):
                    return Vulnerability(
                        id=f"SCA-PYTHON-{vuln_info['id']}",
                        severity=vuln_info['severity'],
                        confidence="HIGH",
                        file_path=file_path,
                        line_number=0,  # Line number not applicable for dependencies
                        description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                        code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                        fix_suggestion=f"Update {package} to version {vuln_info['fix_version']} or later."
                    )

        # Then check NVD database
        try:
            nvd_vulns = get_vulnerabilities_for_package(package, version, "pypi")
            if nvd_vulns:
                # Use the first vulnerability found
                vuln_info = nvd_vulns[0]
                return Vulnerability(
                    id=f"SCA-PYTHON-{vuln_info['id']}",
                    severity=vuln_info['severity'],
                    confidence="HIGH",
                    file_path=file_path,
                    line_number=0,  # Line number not applicable for dependencies
                    description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                    code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                    fix_suggestion=f"Update {package} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                )
        except Exception as e:
            logging.error(f"Error checking NVD for {package} ({version}): {e}")

        return None

    def _scan_javascript_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Scan JavaScript dependencies for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []

        # Find JavaScript dependency files
        dependency_files = self._find_dependency_files(directory, DEPENDENCY_FILES['javascript'])

        for file_path in dependency_files:
            if file_path.endswith('package.json'):
                # Parse package.json
                deps = self._parse_package_json(file_path)
                for dep_name, dep_version in deps:
                    vuln = self._check_javascript_vulnerability(file_path, dep_name, dep_version)
                    if vuln:
                        vulnerabilities.append(vuln)
            # Add support for other JavaScript dependency files as needed

        return vulnerabilities

    def _parse_package_json(self, file_path: str) -> List[Tuple[str, str]]:
        """
        Parse a package.json file.

        Args:
            file_path (str): Path to the package.json file.

        Returns:
            List[Tuple[str, str]]: List of (package_name, version) tuples.
        """
        dependencies = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # Get dependencies
                deps = data.get('dependencies', {})
                for package, version in deps.items():
                    # Remove version specifiers
                    if version.startswith('^') or version.startswith('~'):
                        version = version[1:]
                    dependencies.append((package, version))

                # Get devDependencies
                dev_deps = data.get('devDependencies', {})
                for package, version in dev_deps.items():
                    # Remove version specifiers
                    if version.startswith('^') or version.startswith('~'):
                        version = version[1:]
                    dependencies.append((package, version))
        except Exception as e:
            logging.error(f"Error parsing package.json: {e}")

        return dependencies

    def _check_javascript_vulnerability(self, file_path: str, package: str, version: str) -> Optional[Vulnerability]:
        """
        Check if a JavaScript package has known vulnerabilities.

        Args:
            file_path (str): Path to the dependency file.
            package (str): Package name.
            version (str): Package version.

        Returns:
            Optional[Vulnerability]: Vulnerability if found, None otherwise.
        """
        # First check local database
        if package.lower() in KNOWN_VULNERABILITIES.get('javascript', {}):
            vulns = KNOWN_VULNERABILITIES['javascript'][package.lower()]
            for vuln_version, vuln_info in vulns.items():
                if self._is_vulnerable_version(version, vuln_version):
                    return Vulnerability(
                        id=f"SCA-JS-{vuln_info['id']}",
                        severity=vuln_info['severity'],
                        confidence="HIGH",
                        file_path=file_path,
                        line_number=0,  # Line number not applicable for dependencies
                        description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                        code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                        fix_suggestion=f"Update {package} to version {vuln_info['fix_version']} or later."
                    )

        # Then check NVD database
        try:
            nvd_vulns = get_vulnerabilities_for_package(package, version, "npm")
            if nvd_vulns:
                # Use the first vulnerability found
                vuln_info = nvd_vulns[0]
                return Vulnerability(
                    id=f"SCA-JS-{vuln_info['id']}",
                    severity=vuln_info['severity'],
                    confidence="HIGH",
                    file_path=file_path,
                    line_number=0,  # Line number not applicable for dependencies
                    description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                    code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                    fix_suggestion=f"Update {package} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                )
        except Exception as e:
            logging.error(f"Error checking NVD for {package} ({version}): {e}")

        return None

    def _scan_java_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Scan Java dependencies for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []

        # Find Java dependency files
        dependency_files = self._find_dependency_files(directory, DEPENDENCY_FILES['java'])

        for file_path in dependency_files:
            if file_path.endswith('pom.xml'):
                # Parse pom.xml
                deps = self._parse_pom_xml(file_path)
                for dep_name, dep_version in deps:
                    vuln = self._check_java_vulnerability(file_path, dep_name, dep_version)
                    if vuln:
                        vulnerabilities.append(vuln)
            # Add support for other Java dependency files as needed

        return vulnerabilities

    def _parse_pom_xml(self, file_path: str) -> List[Tuple[str, str]]:
        """
        Parse a pom.xml file.

        Args:
            file_path (str): Path to the pom.xml file.

        Returns:
            List[Tuple[str, str]]: List of (package_name, version) tuples.
        """
        dependencies = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # Extract dependencies using regex
                dependency_matches = re.finditer(r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>', content, re.DOTALL)

                for match in dependency_matches:
                    group_id = match.group(1).strip()
                    artifact_id = match.group(2).strip()
                    version = match.group(3).strip()

                    # Combine group_id and artifact_id
                    package = f"{group_id}:{artifact_id}"
                    dependencies.append((package, version))
        except Exception as e:
            logging.error(f"Error parsing pom.xml: {e}")

        return dependencies

    def _check_java_vulnerability(self, file_path: str, package: str, version: str) -> Optional[Vulnerability]:
        """
        Check if a Java package has known vulnerabilities.

        Args:
            file_path (str): Path to the dependency file.
            package (str): Package name.
            version (str): Package version.

        Returns:
            Optional[Vulnerability]: Vulnerability if found, None otherwise.
        """
        # First check local database
        if package.lower() in KNOWN_VULNERABILITIES.get('java', {}):
            vulns = KNOWN_VULNERABILITIES['java'][package.lower()]
            for vuln_version, vuln_info in vulns.items():
                if self._is_vulnerable_version(version, vuln_version):
                    return Vulnerability(
                        id=f"SCA-JAVA-{vuln_info['id']}",
                        severity=vuln_info['severity'],
                        confidence="HIGH",
                        file_path=file_path,
                        line_number=0,  # Line number not applicable for dependencies
                        description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                        code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                        fix_suggestion=f"Update {package} to version {vuln_info['fix_version']} or later."
                    )

        # Then check NVD database
        try:
            # Extract group and artifact IDs from package name (format: group:artifact)
            parts = package.split(':')
            if len(parts) >= 2:
                group_id = parts[0]
                artifact_id = parts[1]
                nvd_vulns = get_vulnerabilities_for_package(artifact_id, version, "maven")
                if nvd_vulns:
                    # Use the first vulnerability found
                    vuln_info = nvd_vulns[0]
                    return Vulnerability(
                        id=f"SCA-JAVA-{vuln_info['id']}",
                        severity=vuln_info['severity'],
                        confidence="HIGH",
                        file_path=file_path,
                        line_number=0,  # Line number not applicable for dependencies
                        description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                        code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                        fix_suggestion=f"Update {package} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                    )
        except Exception as e:
            logging.error(f"Error checking NVD for {package} ({version}): {e}")

        return None

    def _scan_ruby_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Scan Ruby dependencies for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        # Placeholder for Ruby dependency scanning
        return []

    def _scan_php_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Scan PHP dependencies for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        # Placeholder for PHP dependency scanning
        return []

    def _scan_go_dependencies(self, directory: str) -> List[Vulnerability]:
        """
        Scan Go dependencies for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        # Placeholder for Go dependency scanning
        return []

    def _scan_xml_files(self, directory: str, nvd_api_key=None, huggingface_token=None) -> List[Vulnerability]:
        """
        Scan XML files for vulnerabilities like XXE.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.
            huggingface_token (str, optional): Token for Hugging Face API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning XML files in {directory} for vulnerabilities...")

        # Use the XML scanner to scan for vulnerabilities
        vulnerabilities = xml_scanner.scan_xml_files(directory, nvd_api_key, huggingface_token)

        if vulnerabilities:
            logging.info(f"Found {len(vulnerabilities)} XML vulnerabilities in {directory}")

        return vulnerabilities

    def _scan_json_files(self, directory: str, nvd_api_key=None) -> List[Vulnerability]:
        """
        Scan JSON files for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning JSON files in {directory} for vulnerabilities...")

        # Use our own JSON scanner implementation
        vulnerabilities = self._scan_json_files_impl(directory, nvd_api_key)

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in JSON files")
        return vulnerabilities

    def _scan_json_files_impl(self, directory: str, nvd_api_key: Optional[str] = None) -> List[Vulnerability]:
        """
        Implementation of JSON file scanning.

        Args:
            directory (str): Directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of detected vulnerabilities.
        """
        vulnerabilities = []

        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.json'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            try:
                                data = json.load(f)

                                # Determine the type of JSON file
                                if os.path.basename(file_path).lower() == 'package.json':
                                    self._scan_npm_package_json(file_path, data, vulnerabilities)
                                elif os.path.basename(file_path).lower() == 'package-lock.json':
                                    self._scan_npm_lock_json(file_path, data, vulnerabilities)
                                elif os.path.basename(file_path).lower() == 'composer.json':
                                    self._scan_composer_json(file_path, data, vulnerabilities)
                                elif os.path.basename(file_path).lower() == 'composer.lock':
                                    self._scan_composer_lock_json(file_path, data, vulnerabilities)
                                elif os.path.basename(file_path).lower() == 'bower.json':
                                    self._scan_bower_json(file_path, data, vulnerabilities)
                                elif os.path.basename(file_path).lower() == 'project.json':
                                    self._scan_dotnet_json(file_path, data, vulnerabilities)
                                else:
                                    # Generic JSON file - look for sensitive data
                                    self._scan_generic_json_for_sensitive_data(file_path, data, vulnerabilities)

                            except json.JSONDecodeError:
                                logging.warning(f"Invalid JSON in {file_path}")
                    except Exception as e:
                        logging.error(f"Error scanning JSON file {file_path}: {e}")

        return vulnerabilities

    def _scan_npm_package_json(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a package.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        # Process dependencies
        deps = []
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            for pkg, ver in data['dependencies'].items():
                deps.append((pkg, ver))

        # Process dev dependencies
        if 'devDependencies' in data and isinstance(data['devDependencies'], dict):
            for pkg, ver in data['devDependencies'].items():
                deps.append((pkg, ver))

        # Check each dependency
        for dep_name, dep_version in deps:
            # Clean version string
            clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

            # Check for vulnerabilities
            self._check_dependency_vulnerability(file_path, dep_name, clean_version, "npm", vulnerabilities)

    def _scan_npm_lock_json(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a package-lock.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        # Process dependencies
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            self._process_npm_lock_deps_json(file_path, data['dependencies'], vulnerabilities)

    def _process_npm_lock_deps_json(self, file_path: str, dependencies: dict, vulnerabilities: List[Vulnerability]):
        """
        Process dependencies from package-lock.json.

        Args:
            file_path (str): Path to the file.
            dependencies (dict): Dependencies object from package-lock.json.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        for dep_name, dep_info in dependencies.items():
            if isinstance(dep_info, dict) and 'version' in dep_info:
                dep_version = dep_info['version']

                # Check for vulnerabilities
                self._check_dependency_vulnerability(file_path, dep_name, dep_version, "npm", vulnerabilities)

                # Process nested dependencies
                if 'dependencies' in dep_info and isinstance(dep_info['dependencies'], dict):
                    self._process_npm_lock_deps_json(file_path, dep_info['dependencies'], vulnerabilities)

    def _scan_composer_json(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a composer.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        # Process dependencies
        deps = []
        if 'require' in data and isinstance(data['require'], dict):
            for pkg, ver in data['require'].items():
                deps.append((pkg, ver))

        # Process dev dependencies
        if 'require-dev' in data and isinstance(data['require-dev'], dict):
            for pkg, ver in data['require-dev'].items():
                deps.append((pkg, ver))

        # Check each dependency
        for dep_name, dep_version in deps:
            # Clean version string
            clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

            # Check for vulnerabilities
            self._check_dependency_vulnerability(file_path, dep_name, clean_version, "composer", vulnerabilities)

    def _scan_composer_lock_json(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a composer.lock file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        if 'packages' in data and isinstance(data['packages'], list):
            for package in data['packages']:
                if isinstance(package, dict) and 'name' in package and 'version' in package:
                    dep_name = package['name']
                    dep_version = package['version']

                    # Check for vulnerabilities
                    self._check_dependency_vulnerability(file_path, dep_name, dep_version, "composer", vulnerabilities)

    def _scan_bower_json(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a bower.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        # Process dependencies
        deps = []
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            for pkg, ver in data['dependencies'].items():
                deps.append((pkg, ver))

        # Process dev dependencies
        if 'devDependencies' in data and isinstance(data['devDependencies'], dict):
            for pkg, ver in data['devDependencies'].items():
                deps.append((pkg, ver))

        # Check each dependency (using npm ecosystem as Bower uses similar packages)
        for dep_name, dep_version in deps:
            # Clean version string
            clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

            # Check for vulnerabilities
            self._check_dependency_vulnerability(file_path, dep_name, clean_version, "npm", vulnerabilities)

    def _scan_dotnet_json(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a .NET project.json file for vulnerabilities.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        # Process dependencies
        deps = []
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            for pkg, ver in data['dependencies'].items():
                if isinstance(ver, str):
                    deps.append((pkg, ver))
                elif isinstance(ver, dict) and 'version' in ver:
                    deps.append((pkg, ver['version']))

        # Check each dependency
        for dep_name, dep_version in deps:
            # Clean version string
            clean_version = dep_version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

            # Check for vulnerabilities
            self._check_dependency_vulnerability(file_path, dep_name, clean_version, "nuget", vulnerabilities)

    def _scan_generic_json_for_sensitive_data(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability]):
        """
        Scan a generic JSON file for potential security issues.

        Args:
            file_path (str): Path to the file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        # Look for sensitive information in keys
        sensitive_keys = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'auth',
            'credential', 'api_key', 'apikey', 'access_token', 'accesstoken'
        ]

        self._check_sensitive_keys_json(file_path, data, sensitive_keys, "", vulnerabilities)

    def _check_sensitive_keys_json(self, file_path: str, data: Any, sensitive_keys: List[str], path: str = "", vulnerabilities: List[Vulnerability] = None):
        """
        Recursively check for sensitive keys in JSON data.

        Args:
            file_path (str): Path to the file.
            data (Any): JSON data to check.
            sensitive_keys (List[str]): List of sensitive key names.
            path (str): Current path in the JSON structure.
            vulnerabilities (List[Vulnerability]): List to add vulnerabilities to.
        """
        if vulnerabilities is None:
            vulnerabilities = []

        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key

                # Check if key is sensitive
                for sensitive_key in sensitive_keys:
                    if sensitive_key.lower() in key.lower():
                        # Don't flag if value is a reference or placeholder
                        if isinstance(value, str) and (
                            value.startswith('${') or
                            value.startswith('{{') or
                            value == "" or
                            value.lower() in ['null', 'undefined']
                        ):
                            continue

                        vuln = Vulnerability(
                            id="SCA-JSON-SENSITIVE-DATA",
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            file_path=file_path,
                            line_number=0,  # Line number not available without parsing the file line by line
                            description=f"Potentially sensitive data found in JSON file: '{new_path}'",
                            code=f"Key: {new_path}\nValue type: {type(value).__name__}",
                            fix_suggestion="Remove sensitive data from the JSON file or use environment variables or a secure vault instead."
                        )
                        vulnerabilities.append(vuln)
                        break

                # Recursively check nested structures
                self._check_sensitive_keys_json(file_path, value, sensitive_keys, new_path, vulnerabilities)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                self._check_sensitive_keys_json(file_path, item, sensitive_keys, new_path, vulnerabilities)

    def _scan_json_for_dependencies(self, file_path: str, data: dict, vulnerabilities: List[Vulnerability], nvd_api_key=None):
        """
        Scan a JSON object for any dependencies.

        Args:
            file_path (str): Path to the JSON file.
            data (dict): Parsed JSON data.
            vulnerabilities (List[Vulnerability]): List to add found vulnerabilities to.
            nvd_api_key (str, optional): API key for the NVD API.
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
                                vulnerabilities.append(vuln)
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
                                vulnerabilities.append(vuln)
                        except Exception as e:
                            logging.error(f"Error checking NVD for {dep_name} ({clean_version}): {e}")

        # Recursively check nested objects
        for key, value in data.items():
            if isinstance(value, dict):
                self._scan_json_for_dependencies(file_path, value, vulnerabilities, nvd_api_key)

    def _scan_generic_files(self, directory: str, nvd_api_key=None) -> List[Vulnerability]:
        """
        Scan generic text files for dependencies.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning generic text files in {directory} for dependencies...")

        # Use our own text scanner implementation
        vulnerabilities = self._scan_text_files_impl(directory)

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in generic text files")
        return vulnerabilities

    def _scan_text_files_impl(self, directory: str) -> List[Vulnerability]:
        """
        Implementation of text file scanning.

        Args:
            directory (str): Directory to scan.

        Returns:
            List[Vulnerability]: List of detected vulnerabilities.
        """
        vulnerabilities = []

        # File extensions to scan
        text_file_extensions = [
            '.txt', '.log', '.cfg', '.conf', '.config', '.ini', '.env', '.properties',
            '.yaml', '.yml', '.toml', '.md', '.csv', '.tsv', '.json', '.xml', '.html',
            '.htm', '.css', '.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java',
            '.c', '.cpp', '.cs', '.go', '.rs', '.sh', '.bat', '.ps1', '.sql'
        ]

        # Patterns to look for in text files
        sensitive_patterns = {
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
            'CONNECTION_STRING': {
                'pattern': r'(?i)(connection[_-]?string|connectionstring)["\']?\s*[:=]\s*["\']?([^"\'\s]{16,})["\']\s*',
                'description': 'Connection string found in text file',
                'severity': 'MEDIUM'
            },
            'PRIVATE_KEY': {
                'pattern': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                'description': 'Private key found in text file',
                'severity': 'HIGH'
            },
            'AWS_KEY': {
                'pattern': r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+]{16,})["\']\s*',
                'description': 'AWS key found in text file',
                'severity': 'HIGH'
            },
            'GOOGLE_KEY': {
                'pattern': r'(?i)(google[_-]?api[_-]?key|google[_-]?cloud[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-.]{16,})["\']\s*',
                'description': 'Google API key found in text file',
                'severity': 'HIGH'
            },
            'AZURE_KEY': {
                'pattern': r'(?i)(azure[_-]?storage[_-]?account[_-]?key|azure[_-]?connection[_-]?string)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{16,})["\']\s*',
                'description': 'Azure key found in text file',
                'severity': 'HIGH'
            },
            'IP_ADDRESS': {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'description': 'IP address found in text file',
                'severity': 'LOW'
            }
        }

        for root, _, files in os.walk(directory):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in text_file_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            try:
                                content = f.read()
                                lines = content.split('\n')

                                # Check for sensitive patterns
                                for pattern_name, pattern_info in sensitive_patterns.items():
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
                                        vulnerabilities.append(vuln)
                                        logging.info(f"Found {pattern_name} in {file_path}:{line_number}")
                            except Exception as e:
                                logging.warning(f"Error processing text file {file_path}: {e}")
                    except Exception as e:
                        logging.error(f"Error scanning text file {file_path}: {e}")

        return vulnerabilities

    def _scan_docker_files(self, directory: str, nvd_api_key=None) -> List[Vulnerability]:
        """
        Scan Docker files for dependencies.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning Docker files in {directory} for dependencies...")
        vulnerabilities = []

        # Find all Docker files
        docker_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower() == 'dockerfile' or file.lower().endswith('.dockerfile'):
                    docker_files.append(os.path.join(root, file))
                elif file.lower() in ['docker-compose.yml', 'docker-compose.yaml']:
                    docker_files.append(os.path.join(root, file))

        logging.info(f"Found {len(docker_files)} Docker files to scan")

        # Common base image patterns
        base_image_patterns = [
            r'FROM\s+([a-zA-Z0-9\.\-_/]+):([a-zA-Z0-9\.\-_]+)',  # FROM image:tag
            r'FROM\s+([a-zA-Z0-9\.\-_/]+)@sha256:[a-f0-9]+',  # FROM image@sha256:digest
        ]

        # Common package installation patterns
        package_patterns = [
            r'apt-get\s+install\s+(.+)',  # apt-get install packages
            r'apk\s+add\s+(.+)',  # apk add packages
            r'yum\s+install\s+(.+)',  # yum install packages
            r'dnf\s+install\s+(.+)',  # dnf install packages
            r'pip\s+install\s+(.+)',  # pip install packages
            r'npm\s+install\s+(.+)',  # npm install packages
            r'gem\s+install\s+(.+)',  # gem install packages
        ]

        # Scan each Docker file
        for file_path in docker_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Check for base images
                    for pattern in base_image_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, tuple) and len(match) >= 2:
                                image, tag = match
                                # Check for known vulnerable base images
                                self._check_docker_base_image(file_path, image, tag, vulnerabilities)
                            elif isinstance(match, str):
                                # Handle case where regex returns a string
                                image = match
                                tag = 'latest'
                                self._check_docker_base_image(file_path, image, tag, vulnerabilities)

                    # Check for package installations
                    for pattern in package_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            # Parse package names and versions
                            packages = self._parse_package_list(match)
                            for package, version in packages:
                                # Check for vulnerabilities based on package manager
                                if 'apt-get' in pattern or 'apt' in pattern:
                                    self._check_dependency_vulnerability(file_path, package, version, "debian", vulnerabilities)
                                elif 'apk' in pattern:
                                    self._check_dependency_vulnerability(file_path, package, version, "alpine", vulnerabilities)
                                elif 'yum' in pattern or 'dnf' in pattern:
                                    self._check_dependency_vulnerability(file_path, package, version, "rhel", vulnerabilities)
                                elif 'pip' in pattern:
                                    self._check_dependency_vulnerability(file_path, package, version, "pypi", vulnerabilities)
                                elif 'npm' in pattern:
                                    self._check_dependency_vulnerability(file_path, package, version, "npm", vulnerabilities)
                                elif 'gem' in pattern:
                                    self._check_dependency_vulnerability(file_path, package, version, "gem", vulnerabilities)

            except Exception as e:
                logging.error(f"Error scanning Docker file {file_path}: {e}")

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in Docker files")
        return vulnerabilities

    def _scan_kubernetes_files(self, directory: str, nvd_api_key=None) -> List[Vulnerability]:
        """
        Scan Kubernetes files for dependencies.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning Kubernetes files in {directory} for dependencies...")
        vulnerabilities = []

        # Find all Kubernetes YAML files
        k8s_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(('.yaml', '.yml')):
                    # Check if it's likely a Kubernetes file
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if any(keyword in content.lower() for keyword in ['apiversion', 'kind', 'metadata', 'spec', 'deployment', 'service', 'pod']):
                                k8s_files.append(file_path)
                    except Exception:
                        pass

        logging.info(f"Found {len(k8s_files)} Kubernetes files to scan")

        # Container image patterns in Kubernetes YAML
        image_patterns = [
            r'image:\s*([a-zA-Z0-9\.\-_/]+):([a-zA-Z0-9\.\-_]+)',  # image: image:tag
            r'image:\s*([a-zA-Z0-9\.\-_/]+)@sha256:[a-f0-9]+',  # image: image@sha256:digest
        ]

        # Scan each Kubernetes file
        for file_path in k8s_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Check for container images
                    for pattern in image_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, tuple) and len(match) >= 2:
                                image, tag = match
                                # Check for known vulnerable container images
                                self._check_docker_base_image(file_path, image, tag, vulnerabilities)
                            elif isinstance(match, str):
                                # Handle case where regex returns a string
                                image = match
                                tag = 'latest'
                                self._check_docker_base_image(file_path, image, tag, vulnerabilities)

            except Exception as e:
                logging.error(f"Error scanning Kubernetes file {file_path}: {e}")

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in Kubernetes files")
        return vulnerabilities

    def _scan_shell_scripts(self, directory: str, nvd_api_key=None) -> List[Vulnerability]:
        """
        Scan shell scripts for dependencies.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning shell scripts in {directory} for dependencies...")
        vulnerabilities = []

        # Find all shell script files
        shell_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(('.sh', '.bash', '.zsh', '.fish')):
                    shell_files.append(os.path.join(root, file))
                # Also check for files with shebang
                elif not file.lower().endswith(('.md', '.txt', '.html', '.css', '.js', '.py', '.java', '.c', '.cpp', '.h', '.hpp')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            first_line = f.readline().strip()
                            if first_line.startswith('#!') and any(shell in first_line for shell in ['/bin/sh', '/bin/bash', '/bin/zsh', '/bin/fish']):
                                shell_files.append(file_path)
                    except Exception:
                        pass

        logging.info(f"Found {len(shell_files)} shell script files to scan")

        # Common package installation patterns in shell scripts
        package_patterns = [
            r'apt-get\s+install\s+(.+)',  # apt-get install packages
            r'apt\s+install\s+(.+)',  # apt install packages
            r'apk\s+add\s+(.+)',  # apk add packages
            r'yum\s+install\s+(.+)',  # yum install packages
            r'dnf\s+install\s+(.+)',  # dnf install packages
            r'pip\s+install\s+(.+)',  # pip install packages
            r'pip3\s+install\s+(.+)',  # pip3 install packages
            r'npm\s+install\s+(.+)',  # npm install packages
            r'gem\s+install\s+(.+)',  # gem install packages
            r'go\s+get\s+(.+)',  # go get packages
            r'docker\s+pull\s+([a-zA-Z0-9\.\-_/]+):([a-zA-Z0-9\.\-_]+)',  # docker pull image:tag
        ]

        # Scan each shell script file
        for file_path in shell_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Check for package installations
                    for pattern in package_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if 'docker pull' in pattern and isinstance(match, tuple) and len(match) >= 2:
                                # Handle docker pull pattern
                                image, tag = match
                                self._check_docker_base_image(file_path, image, tag, vulnerabilities)
                            else:
                                # Parse package names and versions
                                packages = self._parse_package_list(match)
                                for package, version in packages:
                                    # Check for vulnerabilities based on package manager
                                    if 'apt-get' in pattern or 'apt' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "debian", vulnerabilities)
                                    elif 'apk' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "alpine", vulnerabilities)
                                    elif 'yum' in pattern or 'dnf' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "rhel", vulnerabilities)
                                    elif 'pip' in pattern or 'pip3' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "pypi", vulnerabilities)
                                    elif 'npm' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "npm", vulnerabilities)
                                    elif 'gem' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "gem", vulnerabilities)
                                    elif 'go get' in pattern:
                                        self._check_dependency_vulnerability(file_path, package, version, "golang", vulnerabilities)

            except Exception as e:
                logging.error(f"Error scanning shell script {file_path}: {e}")

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in shell scripts")
        return vulnerabilities

    def _scan_config_files(self, directory: str, nvd_api_key=None) -> List[Vulnerability]:
        """
        Scan configuration files for dependencies.

        Args:
            directory (str): Path to the directory to scan.
            nvd_api_key (str, optional): API key for the NVD API.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        logging.info(f"Scanning configuration files in {directory} for dependencies...")
        vulnerabilities = []

        # Find all configuration files
        config_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(('.conf', '.cfg', '.ini', '.properties', '.env')) or file.lower().startswith('.env'):
                    config_files.append(os.path.join(root, file))

        logging.info(f"Found {len(config_files)} configuration files to scan")

        # Common dependency patterns in configuration files
        dependency_patterns = [
            r'version\s*[=:]\s*[\'"]?([0-9\.]+)[\'"]?',  # version = "1.2.3"
            r'([a-zA-Z0-9\.-]+)[=:]([0-9\.]+)',  # package=1.2.3 or package:1.2.3
            r'([a-zA-Z0-9\.-]+)_VERSION\s*[=:]\s*[\'"]?([0-9\.]+)[\'"]?',  # PACKAGE_VERSION = "1.2.3"
            r'image\s*[=:]\s*[\'"]?([a-zA-Z0-9\.\-_/]+):([a-zA-Z0-9\.\-_]+)[\'"]?',  # image = "image:tag"
        ]

        # Common library names to check
        common_libraries = [
            'spring', 'log4j', 'logback', 'slf4j', 'jackson', 'gson', 'fastjson',
            'struts', 'hibernate', 'mysql', 'postgresql', 'mongodb', 'redis',
            'nginx', 'apache', 'tomcat', 'jetty', 'undertow',
            'jquery', 'react', 'angular', 'vue', 'bootstrap',
            'django', 'flask', 'rails', 'express', 'laravel', 'symfony',
            'tensorflow', 'pytorch', 'scikit-learn', 'pandas', 'numpy',
            'openssl', 'curl', 'libxml', 'libxslt', 'libpng', 'libjpeg',
            'kubernetes', 'docker', 'containerd', 'etcd', 'consul', 'vault',
            'elasticsearch', 'kibana', 'logstash', 'grafana', 'prometheus'
        ]

        # Scan each configuration file
        for file_path in config_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Check for dependencies
                    for pattern in dependency_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, tuple) and len(match) >= 2:
                                if 'image' in pattern:
                                    # Handle image pattern
                                    image, tag = match
                                    self._check_docker_base_image(file_path, image, tag, vulnerabilities)
                                else:
                                    # Handle package pattern
                                    package, version = match
                                    # Only check common libraries to reduce false positives
                                    if any(lib.lower() in package.lower() for lib in common_libraries):
                                        # Try multiple ecosystems
                                        for ecosystem in ["maven", "npm", "pypi", "composer", "gem", "golang"]:
                                            self._check_dependency_vulnerability(file_path, package, version, ecosystem, vulnerabilities)
                            elif isinstance(match, str) and 'version' in pattern:
                                # Handle version pattern
                                version = match
                                # Look for package name in nearby lines
                                package = self._find_package_name_in_context(content, match)
                                if package and any(lib.lower() in package.lower() for lib in common_libraries):
                                    # Try multiple ecosystems
                                    for ecosystem in ["maven", "npm", "pypi", "composer", "gem", "golang"]:
                                        self._check_dependency_vulnerability(file_path, package, version, ecosystem, vulnerabilities)

            except Exception as e:
                logging.error(f"Error scanning configuration file {file_path}: {e}")

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in configuration files")
        return vulnerabilities

    def _parse_package_list(self, package_list: str) -> List[Tuple[str, str]]:
        """
        Parse a list of packages from a command line.

        Args:
            package_list (str): Package list string from a command line.

        Returns:
            List[Tuple[str, str]]: List of (package_name, version) tuples.
        """
        packages = []

        # Remove common command line options
        cleaned_list = re.sub(r'-[a-zA-Z]+\s+\S+', '', package_list)
        cleaned_list = re.sub(r'--[a-zA-Z\-]+=\S+', '', cleaned_list)
        cleaned_list = re.sub(r'--[a-zA-Z\-]+', '', cleaned_list)

        # Split by whitespace or commas
        items = re.split(r'[\s,]+', cleaned_list)

        for item in items:
            item = item.strip()
            if not item:
                continue

            # Check for version specification
            if '=' in item:
                # Format: package=version
                parts = item.split('=', 1)
                package = parts[0].strip()
                version = parts[1].strip()
                packages.append((package, version))
            elif '@' in item and not item.startswith('@'):
                # Format: package@version
                parts = item.split('@', 1)
                package = parts[0].strip()
                version = parts[1].strip()
                packages.append((package, version))
            elif ':' in item and not item.startswith(':'):
                # Format: package:version
                parts = item.split(':', 1)
                package = parts[0].strip()
                version = parts[1].strip()
                packages.append((package, version))
            else:
                # No version specified, assume latest
                packages.append((item, 'latest'))

        return packages

    def _check_docker_base_image(self, file_path: str, image: str, tag: str, vulnerabilities: List[Vulnerability]):
        """
        Check if a Docker base image has known vulnerabilities.

        Args:
            file_path (str): Path to the file being scanned.
            image (str): Docker image name.
            tag (str): Docker image tag.
            vulnerabilities (List[Vulnerability]): List to add found vulnerabilities to.
        """
        # Known vulnerable base images
        vulnerable_images = {
            'debian': {
                '8': 'CVE-2021-33574',  # Example CVE for Debian 8
                '9': 'CVE-2021-33574',  # Example CVE for Debian 9
            },
            'ubuntu': {
                '16.04': 'CVE-2021-33574',  # Example CVE for Ubuntu 16.04
                '18.04': 'CVE-2021-33574',  # Example CVE for Ubuntu 18.04
            },
            'alpine': {
                '3.9': 'CVE-2021-36159',  # Example CVE for Alpine 3.9
                '3.10': 'CVE-2021-36159',  # Example CVE for Alpine 3.10
            },
            'node': {
                '14': 'CVE-2021-44531',  # Example CVE for Node.js 14
                '16': 'CVE-2021-44531',  # Example CVE for Node.js 16
            },
            'python': {
                '2.7': 'CVE-2021-3177',  # Example CVE for Python 2.7
                '3.6': 'CVE-2021-3177',  # Example CVE for Python 3.6
            },
            'php': {
                '7.3': 'CVE-2021-21703',  # Example CVE for PHP 7.3
                '7.4': 'CVE-2021-21703',  # Example CVE for PHP 7.4
            },
            'nginx': {
                '1.18': 'CVE-2021-23017',  # Example CVE for Nginx 1.18
                '1.19': 'CVE-2021-23017',  # Example CVE for Nginx 1.19
            },
        }

        # Extract the base image name without registry or namespace
        base_image = image.split('/')[-1]

        # Check if the base image is in our list of known vulnerable images
        for vuln_image, versions in vulnerable_images.items():
            if vuln_image in base_image.lower():
                for vuln_tag, cve_id in versions.items():
                    if tag == vuln_tag or tag.startswith(vuln_tag + '.'):
                        # Create a vulnerability
                        vuln = Vulnerability(
                            id=f"SCA-DOCKER-{cve_id}",
                            severity="HIGH",
                            confidence="MEDIUM",
                            file_path=file_path,
                            line_number=0,  # Line number not applicable for dependencies
                            description=f"Vulnerable Docker base image: {image}:{tag}. This image version may contain security vulnerabilities.",
                            code=f"Image: {image}\nTag: {tag}\nVulnerability: {cve_id}",
                            fix_suggestion=f"Update to a newer version of the {image} image."
                        )
                        vulnerabilities.append(vuln)
                        break

    def _check_dependency_vulnerability(self, file_path: str, package: str, version: str, ecosystem: str, vulnerabilities: List[Vulnerability]):
        """
        Check if a dependency has known vulnerabilities.

        Args:
            file_path (str): Path to the file being scanned.
            package (str): Package name.
            version (str): Package version.
            ecosystem (str): Package ecosystem (maven, npm, etc.).
            vulnerabilities (List[Vulnerability]): List to add found vulnerabilities to.
        """
        try:
            # Clean version string
            version = version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')

            # Skip 'latest' version
            if version == 'latest':
                return

            # Check for vulnerabilities
            nvd_vulns = get_vulnerabilities_for_package(package, version, ecosystem)
            if nvd_vulns:
                # Use the first vulnerability found
                vuln_info = nvd_vulns[0]
                vuln = Vulnerability(
                    id=f"SCA-{ecosystem.upper()}-{vuln_info['id']}",
                    severity=vuln_info['severity'],
                    confidence="HIGH",
                    file_path=file_path,
                    line_number=0,  # Line number not applicable for dependencies
                    description=f"Vulnerable dependency: {package} ({version}). {vuln_info['description']}",
                    code=f"Package: {package}\nVersion: {version}\nVulnerability: {vuln_info['id']}",
                    fix_suggestion=f"Update {package} to a newer version. See {', '.join(vuln_info['references'][:3])} for more information."
                )
                vulnerabilities.append(vuln)
        except Exception as e:
            logging.error(f"Error checking NVD for {package} ({version}): {e}")

    def _find_package_name_in_context(self, content: str, version_match: str) -> str:
        """
        Find the package name in the context of a version match.

        Args:
            content (str): File content.
            version_match (str): Version string that was matched.

        Returns:
            str: Package name if found, empty string otherwise.
        """
        # Look for common package name patterns near the version
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if version_match in line:
                # Check current line
                name_match = re.search(r'([a-zA-Z0-9\.-]+)[_\.]?version', line, re.IGNORECASE)
                if name_match:
                    return name_match.group(1)

                # Check previous line
                if i > 0:
                    prev_line = lines[i-1]
                    name_match = re.search(r'([a-zA-Z0-9\.-]+)[_\.]?name', prev_line, re.IGNORECASE)
                    if name_match:
                        return name_match.group(1)

                # Check next line
                if i < len(lines) - 1:
                    next_line = lines[i+1]
                    name_match = re.search(r'([a-zA-Z0-9\.-]+)[_\.]?name', next_line, re.IGNORECASE)
                    if name_match:
                        return name_match.group(1)

                # If no specific pattern found, try to extract a reasonable package name from the line
                words = re.findall(r'([a-zA-Z0-9\.-]+)', line)
                for word in words:
                    if word.lower() not in ['version', 'ver', 'v', 'release', 'build', 'tag', 'rev', 'revision']:
                        return word

        return ""

    def _scan_with_ai(self, directory: str) -> List[Vulnerability]:
        """
        Scan dependencies using AI-based analysis.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of vulnerabilities found by AI.
        """
        vulnerabilities = []

        try:
            # Collect all dependency files
            dependency_files = []
            for lang, patterns in DEPENDENCY_FILES.items():
                files = self._find_dependency_files(directory, patterns)
                dependency_files.extend(files)

            if not dependency_files:
                logging.info("No dependency files found for AI scanning")
                return []

            # Read the content of all dependency files
            file_contents = {}
            for file_path in dependency_files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_contents[file_path] = f.read()
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}")

            # Prepare the prompt for the AI model
            prompt = self._prepare_ai_prompt(file_contents)

            # Get the AI response
            response = self.ai_provider.scan_code(prompt)

            # Parse the AI response to extract vulnerabilities
            ai_vulnerabilities = self._parse_ai_response(response, file_contents)
            vulnerabilities.extend(ai_vulnerabilities)

        except Exception as e:
            logging.error(f"Error during AI-based scanning: {e}")

        return vulnerabilities

    def _prepare_ai_prompt(self, file_contents: Dict[str, str]) -> str:
        """
        Prepare the prompt for the AI model.

        Args:
            file_contents (Dict[str, str]): Dictionary mapping file paths to their contents.

        Returns:
            str: The prompt for the AI model.
        """
        prompt = """You are an expert in software security analysis, specializing in detecting vulnerable dependencies in software projects.
Your task is to analyze the following dependency files and identify any vulnerable packages or libraries.
For each vulnerability you find, provide:
1. The file path where the vulnerability was found
2. The package name and version
3. The vulnerability ID (CVE, etc.) if known
4. The severity level (Critical, High, Medium, Low)
5. A brief description of the vulnerability
6. A suggested fix (e.g., update to a specific version)

Here are the dependency files to analyze:

"""

        for file_path, content in file_contents.items():
            prompt += f"\n--- File: {file_path} ---\n{content}\n"

        prompt += """
Please analyze these files and list all vulnerable dependencies you can find.
Format your response as a structured list of vulnerabilities, with each vulnerability containing the information requested above.
"""

        return prompt

    def _parse_ai_response(self, response: str, file_contents: Dict[str, str]) -> List[Vulnerability]:
        """
        Parse the AI response to extract vulnerabilities.

        Args:
            response (str): The AI model's response.
            file_contents (Dict[str, str]): Dictionary mapping file paths to their contents.

        Returns:
            List[Vulnerability]: List of vulnerabilities found by AI.
        """
        vulnerabilities = []

        try:
            # Split the response into lines
            lines = response.split('\n')

            # Variables to track the current vulnerability being parsed
            current_file = None
            current_package = None
            current_version = None
            current_vuln_id = None
            current_severity = None
            current_description = None
            current_fix = None

            # Parse each line
            for line in lines:
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Look for file path
                if "File:" in line or "file:" in line:
                    # If we have a complete vulnerability, add it
                    if current_file and current_package and current_severity:
                        vuln = Vulnerability(
                            id=f"SCA-AI-{current_vuln_id or 'UNKNOWN'}",
                            severity=current_severity,
                            confidence="MEDIUM",
                            file_path=current_file,
                            line_number=0,  # Line number not applicable for dependencies
                            description=current_description or f"Vulnerable dependency: {current_package} ({current_version})",
                            code=f"Package: {current_package}\nVersion: {current_version}\nVulnerability: {current_vuln_id or 'Unknown'}",
                            fix_suggestion=current_fix or f"Update {current_package} to a newer version."
                        )
                        vulnerabilities.append(vuln)

                    # Start a new vulnerability
                    current_file = line.split(":", 1)[1].strip()
                    current_package = None
                    current_version = None
                    current_vuln_id = None
                    current_severity = None
                    current_description = None
                    current_fix = None

                # Look for package and version
                elif "Package:" in line or "package:" in line:
                    parts = line.split(":", 1)[1].strip().split()
                    if len(parts) > 0:
                        current_package = parts[0]
                        # Try to extract version
                        for part in parts[1:]:
                            if part.startswith("v") and part[1:].replace(".", "").isdigit():
                                current_version = part[1:]
                                break
                            elif part.replace(".", "").isdigit():
                                current_version = part
                                break

                # Look for version
                elif "Version:" in line or "version:" in line:
                    current_version = line.split(":", 1)[1].strip()

                # Look for vulnerability ID
                elif "CVE:" in line or "cve:" in line or "Vulnerability:" in line or "vulnerability:" in line:
                    id_part = line.split(":", 1)[1].strip()
                    # Extract CVE ID if present
                    cve_match = re.search(r'CVE-\d{4}-\d{4,}', id_part)
                    if cve_match:
                        current_vuln_id = cve_match.group(0)
                    else:
                        current_vuln_id = id_part

                # Look for severity
                elif "Severity:" in line or "severity:" in line:
                    severity = line.split(":", 1)[1].strip().upper()
                    if "CRITICAL" in severity:
                        current_severity = "CRITICAL"
                    elif "HIGH" in severity:
                        current_severity = "HIGH"
                    elif "MEDIUM" in severity:
                        current_severity = "MEDIUM"
                    elif "LOW" in severity:
                        current_severity = "LOW"
                    else:
                        current_severity = "MEDIUM"  # Default to medium if unclear

                # Look for description
                elif "Description:" in line or "description:" in line:
                    current_description = line.split(":", 1)[1].strip()

                # Look for fix
                elif "Fix:" in line or "fix:" in line or "Recommendation:" in line or "recommendation:" in line:
                    current_fix = line.split(":", 1)[1].strip()

            # Add the last vulnerability if it exists
            if current_file and current_package and current_severity:
                vuln = Vulnerability(
                    id=f"SCA-AI-{current_vuln_id or 'UNKNOWN'}",
                    severity=current_severity,
                    confidence="MEDIUM",
                    file_path=current_file,
                    line_number=0,  # Line number not applicable for dependencies
                    description=current_description or f"Vulnerable dependency: {current_package} ({current_version})",
                    code=f"Package: {current_package}\nVersion: {current_version}\nVulnerability: {current_vuln_id or 'Unknown'}",
                    fix_suggestion=current_fix or f"Update {current_package} to a newer version."
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logging.error(f"Error parsing AI response: {e}")

        return vulnerabilities

    def _is_vulnerable_version(self, current_version: str, vulnerable_version: str) -> bool:
        """
        Check if the current version is vulnerable.

        Args:
            current_version (str): Current version.
            vulnerable_version (str): Vulnerable version.

        Returns:
            bool: True if the current version is vulnerable, False otherwise.
        """
        # Simple version comparison
        # In a real implementation, this would use a proper version comparison library
        try:
            current_parts = [int(p) for p in current_version.split('.')]
            vulnerable_parts = [int(p) for p in vulnerable_version.split('.')]

            # Pad with zeros if needed
            while len(current_parts) < len(vulnerable_parts):
                current_parts.append(0)
            while len(vulnerable_parts) < len(current_parts):
                vulnerable_parts.append(0)

            # Compare versions
            return current_parts <= vulnerable_parts
        except (ValueError, AttributeError):
            # If we can't parse the version, assume it's vulnerable
            return True


def scan_dependencies(directory: str, nvd_api_key=None, huggingface_token=None) -> List[Vulnerability]:
    """
    Scan a directory for vulnerable dependencies.

    Args:
        directory (str): Path to the directory to scan.
        nvd_api_key (str, optional): API key for the NVD API.
        huggingface_token (str, optional): Token for Hugging Face API.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = SCAScanner()
    return scanner.scan_directory(directory, nvd_api_key, huggingface_token)
