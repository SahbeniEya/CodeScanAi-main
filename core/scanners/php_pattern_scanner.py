"""
This module provides a pattern-based PHP scanner for detecting security vulnerabilities.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from core.scanners.sast_scanner import Vulnerability

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Vulnerability patterns
VULNERABILITY_PATTERNS = [
    {
        "name": "SQL-Injection",
        "pattern": r"(mysql_query\([^,]*\$|mysqli_query\([^,]*\$|->query\([^,]*\$|PDO::query\([^,]*\$|->exec\([^,]*\$)",
        "severity": "HIGH",
        "description": "SQL Injection vulnerability detected. User input is directly used in SQL query.",
        "fix": """Use prepared statements instead of directly including variables in queries:

```php
// Instead of:
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = $mysqli->query($query);

// Use:
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();

// Or with PDO:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
$result = $stmt->fetchAll();
```"""
    },
    {
        "name": "XSS",
        "pattern": r"(echo\s+\$_(?:GET|POST|REQUEST|COOKIE)|print\s+\$_(?:GET|POST|REQUEST|COOKIE)|\$_(?:GET|POST|REQUEST|COOKIE)[^\s]+\s*\?>)",
        "severity": "HIGH",
        "description": "Potential Cross-Site Scripting (XSS) vulnerability detected. User input is directly output to the page.",
        "fix": """Sanitize user input before outputting it:

```php
// Instead of:
echo $_GET['name'];

// Use:
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Or use a framework's escaping mechanism, like in Laravel:
{{ $name }}  // This is automatically escaped
{!! $name !!}  // This is not escaped, use with caution
```"""
    },
    {
        "name": "Command-Injection",
        "pattern": r"(system\([^)]*\$|exec\([^)]*\$|passthru\([^)]*\$|shell_exec\([^)]*\$|`[^`]*\$)",
        "severity": "HIGH",
        "description": "Potential command injection vulnerability detected. User input is used in command execution.",
        "fix": """Avoid using user input in command execution. If necessary, validate and sanitize the input:

```php
// Instead of:
system("ls " . $_GET['dir']);

// Use a whitelist approach:
$allowed_dirs = ['home', 'tmp', 'var'];
if (in_array($_GET['dir'], $allowed_dirs)) {
    system("ls " . $_GET['dir']);
} else {
    echo "Invalid directory";
}

// Or use escapeshellarg to escape arguments:
system("ls " . escapeshellarg($_GET['dir']));
```"""
    },
    {
        "name": "File-Inclusion",
        "pattern": r"(include\s+\$|include_once\s+\$|require\s+\$|require_once\s+\$)",
        "severity": "HIGH",
        "description": "Potential file inclusion vulnerability detected. User input is used to include files.",
        "fix": """Avoid using user input to include files. If necessary, validate and sanitize the input:

```php
// Instead of:
include $_GET['page'] . '.php';

// Use a whitelist approach:
$allowed_pages = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed_pages)) {
    include $_GET['page'] . '.php';
} else {
    include 'home.php';
}
```"""
    },
    {
        "name": "File-Upload",
        "pattern": r"(move_uploaded_file\(\$_FILES|\$_FILES\[[^\]]+\]\[['\"](tmp_name|name)['\"])",
        "severity": "MEDIUM",
        "description": "Potential insecure file upload detected. Validate file types and restrict uploads.",
        "fix": """Validate file uploads properly:

```php
// Check file type
$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($_FILES['file']['type'], $allowed_types)) {
    die("Invalid file type");
}

// Check file extension
$extension = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
if (!in_array(strtolower($extension), $allowed_extensions)) {
    die("Invalid file extension");
}

// Use a secure filename
$new_filename = md5(time() . $_FILES['file']['name']) . '.' . $extension;
$upload_path = '/path/to/secure/directory/' . $new_filename;

// Move the file
if (move_uploaded_file($_FILES['file']['tmp_name'], $upload_path)) {
    echo "File uploaded successfully";
} else {
    echo "Upload failed";
}
```"""
    },
    {
        "name": "Hardcoded-Credentials",
        "pattern": r"(\$(?:password|passwd|pwd|secret|key|token)\s*=\s*['\"][^'\"]{4,}['\"]|define\(['\"](?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN)['\"],\s*['\"][^'\"]{4,}['\"])",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected. Credentials should not be stored in code.",
        "fix": """Use environment variables or a secure configuration system:

```php
// Instead of:
$password = "hardcoded_password";

// Use environment variables:
$password = getenv('APP_PASSWORD');

// Or use a configuration file that is not checked into version control:
$config = parse_ini_file('/path/to/secure/config.ini');
$password = $config['app_password'];

// Or in modern frameworks like Laravel, use the .env file:
$password = env('APP_PASSWORD');
```"""
    }
]

class PHPPatternScanner:
    """
    Pattern-based scanner for PHP files to detect security vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the PHP pattern scanner.
        """
        self.patterns = VULNERABILITY_PATTERNS
    
    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a PHP file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the PHP file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []
        
        if not file_path.endswith(('.php', '.phtml', '.php5', '.php7')):
            logging.info(f"Skipping non-PHP file: {file_path}")
            return []
        
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                for pattern_info in self.patterns:
                    pattern = pattern_info["pattern"]
                    matches = re.finditer(pattern, content)
                    
                    for match in matches:
                        # Find the line number of the match
                        line_number = content[:match.start()].count('\n') + 1
                        
                        # Get the code snippet
                        start_line = max(0, line_number - 3)
                        end_line = min(len(lines), line_number + 3)
                        code_snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Create a vulnerability
                        vuln = Vulnerability(
                            id=f"PHP-{pattern_info['name']}",
                            file_path=file_path,
                            line_number=line_number,
                            severity=pattern_info["severity"],
                            description=pattern_info["description"],
                            confidence="HIGH",
                            code=code_snippet,
                            fix_suggestion=pattern_info["fix"]
                        )
                        
                        vulnerabilities.append(vuln)
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
        
        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in {file_path}")
        return vulnerabilities
    
    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """
        Scan a directory for PHP security vulnerabilities.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.php', '.phtml', '.php5', '.php7')):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities


def scan_php_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a PHP file for security vulnerabilities.
    
    Args:
        file_path (str): Path to the PHP file to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = PHPPatternScanner()
    return scanner.scan_file(file_path)


def scan_php_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for PHP security vulnerabilities.
    
    Args:
        directory (str): Path to the directory to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = PHPPatternScanner()
    return scanner.scan_directory(directory)
