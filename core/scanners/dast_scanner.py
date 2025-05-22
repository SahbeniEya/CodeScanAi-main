"""
Dynamic Application Security Testing (DAST) scanner module.

This module provides functionality for scanning web applications dynamically
using OWASP ZAP (Zed Attack Proxy) to identify security vulnerabilities.
"""

import os
import re
import time
import logging
import subprocess
import tempfile
import requests
from typing import List, Optional
from urllib.parse import urlparse

from core.scanners.sast_scanner import Vulnerability

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class DastScanner:
    """
    DAST Scanner class for dynamic application security testing.
    Uses OWASP ZAP to scan web applications for security vulnerabilities.
    """

    def __init__(self, zap_path: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize the DAST scanner.

        Args:
            zap_path (str, optional): Path to the ZAP installation. If None, will try to find it.
            api_key (str, optional): API key for ZAP. If None, a random one will be generated.
        """
        self.zap_path = zap_path or self._find_zap_path()
        self.api_key = api_key
        self.zap_process = None
        self.zap_port = 8090
        self.zap_api_url = f"http://localhost:{self.zap_port}/JSON"
        self.temp_dir = None

    def _find_zap_path(self) -> str:
        """
        Find the ZAP installation path.

        Returns:
            str: Path to the ZAP installation.
        """
        # Common installation paths
        common_paths = [
            # Windows paths
            r"C:\Program Files\OWASP\Zed Attack Proxy",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy",
            r"C:\Program Files\OWASP ZAP",
            r"C:\Program Files (x86)\OWASP ZAP",
            r"C:\Program Files\ZAP",
            r"C:\Program Files (x86)\ZAP",
            # Linux paths
            r"/usr/share/zaproxy",
            r"/opt/zaproxy",
            r"/usr/local/bin/zaproxy",
            r"/usr/local/share/zaproxy",
            # macOS paths
            r"/Applications/OWASP ZAP.app/Contents/Java",
            r"/Applications/ZAP.app/Contents/Java"
        ]

        # Check if any of the common paths exist
        for path in common_paths:
            if os.path.exists(path):
                logging.info(f"Found ZAP installation at: {path}")
                return path

        # Try to find ZAP in PATH
        try:
            if os.name != "nt":  # Unix/Linux/Mac
                result = subprocess.run(["zap.sh", "-version"], capture_output=True, text=True)
                if result.returncode == 0:
                    logging.info("Found ZAP in PATH (zap.sh)")
                    return "zap.sh"
        except FileNotFoundError:
            pass

        try:
            if os.name == "nt":  # Windows
                result = subprocess.run(["zap.bat", "-version"], capture_output=True, text=True)
                if result.returncode == 0:
                    logging.info("Found ZAP in PATH (zap.bat)")
                    return "zap.bat"
        except FileNotFoundError:
            pass

        # If ZAP is not found, log a warning with installation instructions
        logging.warning("ZAP installation not found. Please install ZAP or provide the path.")
        logging.info("Common ZAP installation paths:")
        logging.info("  - Windows: C:\\Program Files\\OWASP\\Zed Attack Proxy")
        logging.info("  - Windows: C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy")
        logging.info("  - Linux: /usr/share/zaproxy")
        logging.info("  - macOS: /Applications/OWASP ZAP.app/Contents/Java")
        logging.info("You can download ZAP from: https://www.zaproxy.org/download/")
        return ""

    def start_zap(self) -> bool:
        """
        Start the ZAP process.

        Returns:
            bool: True if ZAP started successfully, False otherwise.
        """
        if not self.zap_path:
            logging.error("ZAP path not set. Cannot start ZAP.")
            return False

        # Create a temporary directory for ZAP in a location that's likely to have write permissions
        try:
            # Try to create in system temp directory which usually has proper permissions
            self.temp_dir = tempfile.mkdtemp(prefix="zap_")
            logging.info(f"Created temporary directory for ZAP: {self.temp_dir}")
        except PermissionError:
            # If that fails, try the current directory
            import random
            import string
            current_dir = os.path.abspath(os.path.curdir)
            self.temp_dir = os.path.join(current_dir, "zap_temp_" + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)))
            os.makedirs(self.temp_dir, exist_ok=True)
            logging.info(f"Created temporary directory for ZAP in current directory: {self.temp_dir}")

        # Determine the ZAP executable
        zap_executable = self.zap_path

        # If the path is a directory, find the executable
        if os.path.isdir(self.zap_path):
            if os.name == "nt":  # Windows
                zap_bat = os.path.join(self.zap_path, "zap.bat")
                if os.path.exists(zap_bat):
                    zap_executable = zap_bat
                else:
                    # Try to find zap.sh or zap.exe
                    for exe in ["zap.exe", "ZAP.exe"]:
                        exe_path = os.path.join(self.zap_path, exe)
                        if os.path.exists(exe_path):
                            zap_executable = exe_path
                            break
            else:  # Unix/Linux/Mac
                zap_sh = os.path.join(self.zap_path, "zap.sh")
                if os.path.exists(zap_sh):
                    zap_executable = zap_sh
                else:
                    # Try to find zap executable
                    for exe in ["zap", "zaproxy"]:
                        exe_path = os.path.join(self.zap_path, exe)
                        if os.path.exists(exe_path):
                            zap_executable = exe_path
                            break

        logging.info(f"Using ZAP executable: {zap_executable}")

        # Check if the executable exists
        if not os.path.exists(zap_executable) and zap_executable not in ["zap.sh", "zap.bat"]:
            logging.error(f"ZAP executable not found at: {zap_executable}")
            return False

        # Generate a random API key if not provided
        if not self.api_key:
            import random
            import string
            self.api_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            logging.info(f"Generated random API key: {self.api_key}")

        # Start ZAP with daemon mode and API key
        cmd = [
            zap_executable,
            "-daemon",
            "-port", str(self.zap_port),
            "-config", f"api.key={self.api_key}",
            "-dir", self.temp_dir
        ]

        try:
            self.zap_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait for ZAP to start
            time.sleep(10)

            # Check if ZAP is running
            try:
                response = requests.get(
                    f"{self.zap_api_url}/core/view/version",
                    params={"apikey": self.api_key}
                )
                if response.status_code == 200:
                    logging.info(f"ZAP started successfully. Version: {response.json()['version']}")
                    return True
                else:
                    logging.error(f"Failed to connect to ZAP API: {response.status_code}")
                    return False
            except requests.exceptions.ConnectionError:
                logging.error("Failed to connect to ZAP API. ZAP may not have started correctly.")
                return False
        except Exception as e:
            logging.error(f"Error starting ZAP: {e}")
            return False

    def stop_zap(self) -> bool:
        """
        Stop the ZAP process.

        Returns:
            bool: True if ZAP stopped successfully, False otherwise.
        """
        if not self.zap_process:
            logging.warning("ZAP is not running.")
            return True

        try:
            # Shutdown ZAP gracefully
            requests.get(
                f"{self.zap_api_url}/core/action/shutdown",
                params={"apikey": self.api_key}
            )

            # Wait for ZAP to stop
            self.zap_process.wait(timeout=30)

            # Clean up temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)

            logging.info("ZAP stopped successfully.")
            return True
        except Exception as e:
            logging.error(f"Error stopping ZAP: {e}")
            # Force kill if graceful shutdown fails
            if self.zap_process:
                self.zap_process.kill()
            return False

    def scan_url(self, url: str, scan_type: str = "active") -> List[Vulnerability]:
        """
        Scan a URL for vulnerabilities.

        Args:
            url (str): The URL to scan.
            scan_type (str): The type of scan to perform. Options: "active", "passive", "spider".

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not self._validate_url(url):
            logging.error(f"Invalid URL: {url}")
            return []

        vulnerabilities = []

        try:
            # Access the URL
            logging.info(f"Accessing URL: {url}")
            response = requests.get(
                f"{self.zap_api_url}/core/action/accessUrl",
                params={"apikey": self.api_key, "url": url}
            )
            if response.status_code != 200:
                logging.error(f"Failed to access URL: {response.status_code}")
                return []

            # Wait for passive scanning to complete
            time.sleep(2)

            # Perform spider scan if requested
            if scan_type in ["spider", "active"]:
                logging.info(f"Starting spider scan on: {url}")
                response = requests.get(
                    f"{self.zap_api_url}/spider/action/scan",
                    params={"apikey": self.api_key, "url": url}
                )
                if response.status_code == 200:
                    scan_id = response.json()["scan"]

                    # Wait for spider scan to complete
                    while True:
                        response = requests.get(
                            f"{self.zap_api_url}/spider/view/status",
                            params={"apikey": self.api_key, "scanId": scan_id}
                        )
                        if response.status_code == 200:
                            status = response.json()["status"]
                            if status == "100":
                                logging.info("Spider scan completed.")
                                break
                            logging.info(f"Spider scan progress: {status}%")
                            time.sleep(5)
                        else:
                            logging.error(f"Failed to get spider scan status: {response.status_code}")
                            break
                else:
                    logging.error(f"Failed to start spider scan: {response.status_code}")

            # Perform active scan if requested
            if scan_type == "active":
                logging.info(f"Starting active scan on: {url}")
                response = requests.get(
                    f"{self.zap_api_url}/ascan/action/scan",
                    params={"apikey": self.api_key, "url": url}
                )
                if response.status_code == 200:
                    scan_id = response.json()["scan"]

                    # Wait for active scan to complete
                    while True:
                        response = requests.get(
                            f"{self.zap_api_url}/ascan/view/status",
                            params={"apikey": self.api_key, "scanId": scan_id}
                        )
                        if response.status_code == 200:
                            status = response.json()["status"]
                            if status == "100":
                                logging.info("Active scan completed.")
                                break
                            logging.info(f"Active scan progress: {status}%")
                            time.sleep(5)
                        else:
                            logging.error(f"Failed to get active scan status: {response.status_code}")
                            break
                else:
                    logging.error(f"Failed to start active scan: {response.status_code}")

            # Get alerts (vulnerabilities)
            logging.info("Getting alerts...")
            response = requests.get(
                f"{self.zap_api_url}/core/view/alerts",
                params={"apikey": self.api_key, "baseurl": url}
            )
            if response.status_code == 200:
                alerts = response.json()["alerts"]
                logging.info(f"Found {len(alerts)} alerts.")

                # Convert alerts to vulnerabilities
                for alert in alerts:
                    severity = self._map_risk_to_severity(alert["risk"])
                    vuln = Vulnerability(
                        id=f"DAST-{alert['pluginId']}",
                        file_path=url,
                        line_number=0,
                        code=alert["url"],
                        severity=severity,
                        confidence=alert["confidence"].upper(),
                        description=f"{alert['name']}: {alert['description']}",
                        fix_suggestion=alert["solution"]
                    )
                    vulnerabilities.append(vuln)
            else:
                logging.error(f"Failed to get alerts: {response.status_code}")

        except Exception as e:
            logging.error(f"Error during DAST scan: {e}")

        return vulnerabilities

    def _validate_url(self, url: str) -> bool:
        """
        Validate a URL.

        Args:
            url (str): The URL to validate.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def _map_risk_to_severity(self, risk: str) -> str:
        """
        Map ZAP risk levels to severity levels.

        Args:
            risk (str): The ZAP risk level.

        Returns:
            str: The severity level.
        """
        risk_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO"
        }
        return risk_map.get(risk, "MEDIUM")


def scan_url(url: str, zap_path: Optional[str] = None, api_key: Optional[str] = None, use_basic_scanner: bool = False) -> List[Vulnerability]:
    """
    Scan a URL for vulnerabilities.

    Args:
        url (str): The URL to scan.
        zap_path (str, optional): Path to the ZAP installation.
        api_key (str, optional): API key for ZAP.
        use_basic_scanner (bool, optional): Whether to use the basic scanner instead of ZAP.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    # Validate URL format
    if not url:
        logging.error("No URL provided for DAST scanning")
        return []

    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        logging.info(f"Adding https:// prefix to URL: {url}")
        url = f"https://{url}"

    logging.info(f"DAST scanning URL: {url}")

    # Use basic scanner if requested or if ZAP is not available
    if use_basic_scanner or not zap_path:
        logging.info("Using basic scanner instead of ZAP")
        try:
            return basic_scan_url(url)
        except Exception as e:
            logging.error(f"Error in basic scanner: {e}")
            # Return a minimal vulnerability report instead of failing completely
            return [Vulnerability(
                id="DAST-SCAN-ERROR",
                file_path=url,
                line_number=0,
                code="",
                severity="INFO",
                confidence="HIGH",
                description=f"Error during DAST scan: {str(e)}",
                fix_suggestion="Check the application URL and try again."
            )]

    # Use ZAP scanner
    scanner = DastScanner(zap_path, api_key)

    # Start ZAP
    try:
        if not scanner.start_zap():
            logging.warning("Failed to start ZAP. Falling back to basic scanner.")
            try:
                return basic_scan_url(url)
            except Exception as e:
                logging.error(f"Error in basic scanner fallback: {e}")
                # Return a minimal vulnerability report instead of failing completely
                return [Vulnerability(
                    id="DAST-SCAN-ERROR",
                    file_path=url,
                    line_number=0,
                    code="",
                    severity="INFO",
                    confidence="HIGH",
                    description=f"Error during DAST scan: {str(e)}",
                    fix_suggestion="Check the application URL and try again."
                )]
    except Exception as e:
        logging.error(f"Error starting ZAP: {e}")
        # Return a minimal vulnerability report instead of failing completely
        return [Vulnerability(
            id="DAST-ZAP-ERROR",
            file_path=url,
            line_number=0,
            code="",
            severity="INFO",
            confidence="HIGH",
            description=f"Error starting ZAP: {str(e)}",
            fix_suggestion="Check ZAP installation or use basic scanner."
        )]

    try:
        # Perform the scan
        vulnerabilities = scanner.scan_url(url)
        return vulnerabilities
    finally:
        # Stop ZAP
        scanner.stop_zap()


def basic_scan_url(url: str) -> List[Vulnerability]:
    """
    Perform a basic scan of a URL without using ZAP.
    This is a fallback method when ZAP is not available.

    Args:
        url (str): The URL to scan.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    logging.info(f"Performing basic scan of URL: {url}")
    vulnerabilities = []

    try:
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            logging.error(f"Invalid URL: {url}")
            return []

        # Send a GET request to the URL
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        }

        # Add warning suppression for insecure requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Log the request
        logging.info(f"Sending GET request to {url}")

        # Make the request with a longer timeout
        response = requests.get(url, headers=headers, timeout=30, verify=False)

        # Check for HTTP security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vuln = Vulnerability(
                    id=f"DAST-HEADER-{header.replace('-', '')}",
                    file_path=url,
                    line_number=0,
                    code=f"Response headers: {dict(response.headers)}",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    description=f"{description}. This could expose the application to various attacks.",
                    fix_suggestion=f"Add the {header} header to your HTTP responses."
                )
                vulnerabilities.append(vuln)

        # Check for insecure cookies
        for cookie in response.cookies:
            if not cookie.secure:
                vuln = Vulnerability(
                    id="DAST-COOKIE-SECURE",
                    file_path=url,
                    line_number=0,
                    code=f"Cookie: {cookie.name}",
                    severity="MEDIUM",
                    confidence="HIGH",
                    description=f"Insecure cookie found: {cookie.name}. The cookie is not marked as secure, which means it can be transmitted over unencrypted connections.",
                    fix_suggestion="Set the 'secure' flag on all cookies to ensure they are only transmitted over HTTPS."
                )
                vulnerabilities.append(vuln)

            if not cookie.has_nonstandard_attr('HttpOnly'):
                vuln = Vulnerability(
                    id="DAST-COOKIE-HTTPONLY",
                    file_path=url,
                    line_number=0,
                    code=f"Cookie: {cookie.name}",
                    severity="MEDIUM",
                    confidence="HIGH",
                    description=f"Non-HttpOnly cookie found: {cookie.name}. The cookie is accessible to JavaScript, which makes it vulnerable to XSS attacks.",
                    fix_suggestion="Set the 'HttpOnly' flag on all cookies to prevent access from JavaScript."
                )
                vulnerabilities.append(vuln)

        # Check for HTTP instead of HTTPS
        if url.startswith('http://'):
            vuln = Vulnerability(
                id="DAST-HTTP-INSECURE",
                file_path=url,
                line_number=0,
                code=url,
                severity="HIGH",
                confidence="HIGH",
                description="The application uses HTTP instead of HTTPS. This means that all data transmitted between the client and server is sent in plaintext and can be intercepted.",
                fix_suggestion="Configure the application to use HTTPS instead of HTTP."
            )
            vulnerabilities.append(vuln)

        # Check for common sensitive information in the response
        sensitive_patterns = [
            (r'\b\d{16}\b', "DAST-SENSITIVE-CREDITCARD", "Possible credit card number found in the response", "HIGH"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "DAST-SENSITIVE-EMAIL", "Email address found in the response", "MEDIUM"),
            (r'\bpassword\b|\bpasswd\b|\bsecret\b|\bapi[-_]?key\b', "DAST-SENSITIVE-KEYWORD", "Sensitive keyword found in the response", "MEDIUM"),
        ]

        for pattern, id, description, severity in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vuln = Vulnerability(
                    id=id,
                    file_path=url,
                    line_number=0,
                    code=f"Found {len(matches)} instances of pattern {pattern}",
                    severity=severity,
                    confidence="MEDIUM",
                    description=description,
                    fix_suggestion="Ensure sensitive information is not exposed in responses."
                )
                vulnerabilities.append(vuln)

        # Check for common web vulnerabilities by looking for signs in the HTML
        if '<form' in response.text.lower():
            # Check for CSRF protection
            if 'csrf' not in response.text.lower():
                vuln = Vulnerability(
                    id="DAST-CSRF",
                    file_path=url,
                    line_number=0,
                    code="<form> element without CSRF token",
                    severity="HIGH",
                    confidence="MEDIUM",
                    description="Form found without CSRF protection. This could allow attackers to perform actions on behalf of authenticated users.",
                    fix_suggestion="Implement CSRF tokens in all forms."
                )
                vulnerabilities.append(vuln)

        # Crawl links on the page to find more URLs to scan
        soup = None
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
        except ImportError:
            logging.warning("BeautifulSoup not installed. Skipping link crawling.")

        if soup:
            # Check for potential XSS vulnerabilities
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and ('document.location' in script.string or 'document.URL' in script.string):
                    vuln = Vulnerability(
                        id="DAST-XSS-LOCATION",
                        file_path=url,
                        line_number=0,
                        code=str(script),
                        severity="HIGH",
                        confidence="MEDIUM",
                        description="Potential XSS vulnerability found. The script uses document.location or document.URL which can be manipulated by an attacker.",
                        fix_suggestion="Validate and sanitize all user inputs before using them in JavaScript."
                    )
                    vulnerabilities.append(vuln)

        logging.info(f"Basic scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities

    except requests.exceptions.RequestException as e:
        logging.error(f"Error during basic scan: {e}")
        vuln = Vulnerability(
            id="DAST-CONNECTION-ERROR",
            file_path=url,
            line_number=0,
            code=str(e),
            severity="INFO",
            confidence="HIGH",
            description=f"Error connecting to the URL: {e}",
            fix_suggestion="Ensure the URL is accessible and the server is running."
        )
        vulnerabilities.append(vuln)
        return vulnerabilities
    except Exception as e:
        logging.error(f"Unexpected error during basic scan: {e}")
        return []
