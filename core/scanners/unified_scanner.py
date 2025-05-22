"""
Unified scanner framework for detecting vulnerabilities across multiple languages.
This module provides a comprehensive scanning capability for various file types.
"""

import os
import re
import logging
import importlib
from typing import List, Optional

from core.scanners.sast_scanner import Vulnerability

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Language detection by file extension
LANGUAGE_EXTENSIONS = {
    'js': 'javascript',
    'jsx': 'javascript',
    'ts': 'javascript',
    'tsx': 'javascript',
    'py': 'python',
    'java': 'java',
    'php': 'php',
    'rb': 'ruby',
    'go': 'go',
    'c': 'c',
    'cpp': 'cpp',
    'cs': 'csharp',
    'html': 'html',
    'css': 'css',
    'sql': 'sql',
    'xml': 'xml',
    'json': 'json',
    'yaml': 'yaml',
    'yml': 'yaml',
    'md': 'markdown',
    'sh': 'shell',
    'bat': 'batch',
    'ps1': 'powershell',
}

# Scanner modules for each language
SCANNER_MODULES = {
    'javascript': 'core.scanners.js_pattern_scanner',
    'python': 'core.scanners.sast_scanner',
    'java': 'core.scanners.java_pattern_scanner',
    'php': 'core.scanners.php_pattern_scanner',
    'ruby': 'core.scanners.ruby_pattern_scanner',
    'go': 'core.scanners.go_pattern_scanner',
    'c': 'core.scanners.c_pattern_scanner',
    'cpp': 'core.scanners.c_pattern_scanner',  # Use the same scanner for C++
    'xml': 'core.scanners.xml_scanner',
    'json': 'core.scanners.json_scanner',
    'text': 'core.scanners.text_scanner',
}

# Scanner functions for each language
SCANNER_FUNCTIONS = {
    'javascript': 'scan_js_file',
    'python': 'scan_directory',  # Bandit scanner works on directories
    'java': 'scan_java_file',
    'php': 'scan_php_file',
    'ruby': 'scan_ruby_file',
    'go': 'scan_go_file',
    'c': 'scan_c_file',
    'cpp': 'scan_c_file',  # Use the same scanner function for C++
    'xml': 'scan_file',  # XML scanner works on individual files
    'json': 'scan_file',  # JSON scanner works on individual files
    'text': 'scan_file',  # Text scanner works on individual files
}

# Directory scanner functions for each language
DIRECTORY_SCANNER_FUNCTIONS = {
    'javascript': 'scan_js_directory',
    'python': 'scan_directory',
    'java': 'scan_java_directory',
    'php': 'scan_php_directory',
    'ruby': 'scan_ruby_directory',
    'go': 'scan_go_directory',
    'c': 'scan_c_directory',
    'cpp': 'scan_c_directory',  # Use the same directory scanner for C++
    'xml': 'scan_xml_files',  # XML scanner works on directories
    'json': 'scan_json_files',  # JSON scanner works on directories
    'text': 'scan_text_files',  # Text scanner works on directories
}

class UnifiedScanner:
    """
    Unified scanner that can detect vulnerabilities across multiple languages.
    """

    def __init__(self, context_aware=True, confidence_threshold="LOW"):
        """
        Initialize the unified scanner.

        Args:
            context_aware (bool): Whether to use context-aware scanning to reduce false positives.
            confidence_threshold (str): Minimum confidence level for reporting vulnerabilities (LOW, MEDIUM, HIGH).
        """
        self.scanners = {}
        self.context_aware = context_aware
        self.confidence_threshold = confidence_threshold
        self._load_scanners()

    def _load_scanners(self):
        """
        Load all available scanners.
        """
        for language, module_name in SCANNER_MODULES.items():
            try:
                # Try to import the scanner module
                module = importlib.import_module(module_name)
                self.scanners[language] = module
                logging.info(f"Loaded scanner for {language}")
            except ImportError as e:
                logging.warning(f"Could not load scanner for {language}: {e}")

    def detect_language(self, file_path: str) -> Optional[str]:
        """
        Detect the programming language of a file based on its extension.

        Args:
            file_path (str): Path to the file.

        Returns:
            Optional[str]: Detected language or None if unknown.
        """
        _, ext = os.path.splitext(file_path)
        if ext.startswith('.'):
            ext = ext[1:]

        return LANGUAGE_EXTENSIONS.get(ext.lower())

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a file for vulnerabilities.

        Args:
            file_path (str): Path to the file to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []

        if os.path.isdir(file_path):
            return self.scan_directory(file_path)

        language = self.detect_language(file_path)
        if not language:
            logging.info(f"Unsupported file type: {file_path}")
            return []

        if language not in self.scanners:
            logging.info(f"No scanner available for {language}")
            return []

        try:
            # Get the scanner module and function
            module = self.scanners[language]
            scanner_func_name = SCANNER_FUNCTIONS.get(language)

            if not scanner_func_name or not hasattr(module, scanner_func_name):
                logging.error(f"Scanner function {scanner_func_name} not found for {language}")
                return []

            # Call the scanner function
            scanner_func = getattr(module, scanner_func_name)
            vulnerabilities = scanner_func(file_path)

            # Apply context-aware filtering and confidence threshold
            if self.context_aware:
                vulnerabilities = self._apply_context_filtering(vulnerabilities, file_path)

            # Filter by confidence threshold
            vulnerabilities = self._filter_by_confidence(vulnerabilities)

            logging.info(f"Found {len(vulnerabilities)} vulnerabilities in {file_path}")
            return vulnerabilities
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return []

    def _apply_context_filtering(self, vulnerabilities: List[Vulnerability], file_path: str) -> List[Vulnerability]:
        """
        Apply context-aware filtering to reduce false positives.

        Args:
            vulnerabilities (List[Vulnerability]): List of vulnerabilities to filter.
            file_path (str): Path to the file being scanned.

        Returns:
            List[Vulnerability]: Filtered list of vulnerabilities.
        """
        filtered_vulnerabilities = []

        # Read the file content for context analysis
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

                for vuln in vulnerabilities:
                    # Skip if line number is out of range
                    if vuln.line_number <= 0 or vuln.line_number > len(lines):
                        continue

                    # Get context around the vulnerability
                    context_start = max(0, vuln.line_number - 5)
                    context_end = min(len(lines), vuln.line_number + 5)
                    context_lines = lines[context_start:context_end]
                    context = '\n'.join(context_lines)

                    # Apply specific context rules based on vulnerability type
                    if self._is_valid_in_context(vuln, context):
                        filtered_vulnerabilities.append(vuln)
        except Exception as e:
            logging.error(f"Error in context filtering: {e}")
            # If context filtering fails, return the original vulnerabilities
            return vulnerabilities

        return filtered_vulnerabilities

    def _is_valid_in_context(self, vulnerability: Vulnerability, context: str) -> bool:
        """
        Check if a vulnerability is valid in the given context.

        Args:
            vulnerability (Vulnerability): The vulnerability to check.
            context (str): The context around the vulnerability.

        Returns:
            bool: True if the vulnerability is valid in the context, False otherwise.
        """
        # SQL Injection context rules
        if 'SQL-Injection' in vulnerability.id:
            # If there's evidence of parameterization or sanitization, it might be a false positive
            if 'prepare' in context.lower() or 'sanitize' in context.lower() or 'escape' in context.lower():
                # Look for specific patterns that indicate proper handling
                if re.search(r'\?.*\]', context) or re.search(r':[a-zA-Z0-9_]+', context):
                    return False

        # XSS context rules
        elif 'XSS' in vulnerability.id:
            # If there's evidence of sanitization or escaping, it might be a false positive
            if 'sanitize' in context.lower() or 'escape' in context.lower() or 'htmlspecialchars' in context.lower():
                return False

        # Command injection context rules
        elif 'Command-Injection' in vulnerability.id:
            # If there's evidence of validation or sanitization, it might be a false positive
            if 'validate' in context.lower() or 'sanitize' in context.lower() or 'escapeshell' in context.lower():
                return False

        # Path traversal context rules
        elif 'Path-Traversal' in vulnerability.id:
            # If there's evidence of path normalization or validation, it might be a false positive
            if 'normalize' in context.lower() or 'realpath' in context.lower() or 'basename' in context.lower():
                return False

        # By default, consider the vulnerability valid
        return True

    def _filter_by_confidence(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Filter vulnerabilities by confidence threshold.

        Args:
            vulnerabilities (List[Vulnerability]): List of vulnerabilities to filter.

        Returns:
            List[Vulnerability]: Filtered list of vulnerabilities.
        """
        confidence_levels = {
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }

        threshold = confidence_levels.get(self.confidence_threshold, 1)

        return [v for v in vulnerabilities if confidence_levels.get(v.confidence, 1) >= threshold]

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(directory):
            logging.error(f"Directory not found: {directory}")
            return []

        vulnerabilities = []
        languages_found = set()

        # First, identify all languages in the directory
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                language = self.detect_language(file_path)
                if language:
                    languages_found.add(language)

        # Then scan each language with its directory scanner
        for language in languages_found:
            if language not in self.scanners:
                logging.info(f"No scanner available for {language}")
                continue

            try:
                # Get the scanner module and function
                module = self.scanners[language]
                scanner_func_name = DIRECTORY_SCANNER_FUNCTIONS.get(language)

                if not scanner_func_name or not hasattr(module, scanner_func_name):
                    logging.warning(f"Directory scanner function {scanner_func_name} not found for {language}")
                    # Fall back to scanning individual files
                    for root, _, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if self.detect_language(file_path) == language:
                                file_vulnerabilities = self.scan_file(file_path)
                                vulnerabilities.extend(file_vulnerabilities)
                    continue

                # Call the directory scanner function
                scanner_func = getattr(module, scanner_func_name)
                language_vulnerabilities = scanner_func(directory)

                # Filter out SCA vulnerabilities (they should be handled by the SCA scanner)
                sast_vulns = []
                for vuln in language_vulnerabilities:
                    # Only include SAST vulnerabilities (not SCA)
                    if not (vuln.id.startswith("SCA-") or vuln.id.startswith("DEPENDENCY-")):
                        sast_vulns.append(vuln)

                logging.info(f"Found {len(sast_vulns)} {language} vulnerabilities in {directory}")
                vulnerabilities.extend(sast_vulns)
            except Exception as e:
                logging.error(f"Error scanning {language} files in {directory}: {e}")

        return vulnerabilities

    def get_supported_languages(self) -> List[str]:
        """
        Get a list of supported languages.

        Returns:
            List[str]: List of supported languages.
        """
        return list(self.scanners.keys())


def scan_all(directory: str, nvd_api_key=None, huggingface_token=None) -> List[Vulnerability]:
    """
    Scan a directory for vulnerabilities in all supported languages.

    Args:
        directory (str): Path to the directory to scan.
        nvd_api_key (str, optional): API key for the NVD API.
        huggingface_token (str, optional): Token for Hugging Face API.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    # Set environment variables for API keys if provided
    if nvd_api_key:
        os.environ["NVD_API_KEY"] = nvd_api_key

    if huggingface_token:
        os.environ["HUGGING_FACE_TOKEN"] = huggingface_token

    scanner = UnifiedScanner()
    return scanner.scan_directory(directory)


def scan_file(file_path: str, nvd_api_key=None, huggingface_token=None) -> List[Vulnerability]:
    """
    Scan a file for vulnerabilities.

    Args:
        file_path (str): Path to the file to scan.
        nvd_api_key (str, optional): API key for the NVD API.
        huggingface_token (str, optional): Token for Hugging Face API.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    # Set environment variables for API keys if provided
    if nvd_api_key:
        os.environ["NVD_API_KEY"] = nvd_api_key

    if huggingface_token:
        os.environ["HUGGING_FACE_TOKEN"] = huggingface_token

    scanner = UnifiedScanner()
    return scanner.scan_file(file_path)
