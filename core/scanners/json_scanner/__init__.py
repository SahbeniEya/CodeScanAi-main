"""
JSON Scanner module for detecting vulnerabilities in JSON files.
"""

# Make the scan_json_files function available at the package level
from core.scanners.sca_scanner import SCAScanner

# Create a function that delegates to the SCA scanner
def scan_json_files(directory, nvd_api_key=None):
    """
    Scan JSON files in a directory for vulnerabilities.

    Args:
        directory (str): Directory to scan.
        nvd_api_key (str, optional): API key for the NVD API.

    Returns:
        List[Vulnerability]: List of detected vulnerabilities.
    """
    scanner = SCAScanner()
    return scanner._scan_json_files_impl(directory, nvd_api_key)
