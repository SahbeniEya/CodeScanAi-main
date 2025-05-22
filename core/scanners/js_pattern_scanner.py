"""
This module provides a pattern-based JavaScript scanner for detecting security vulnerabilities.
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
        "name": "SQL Injection",
        "pattern": r"(connection\.query\([^,]*\+|db\.query\([^,]*\+|sql\s*=\s*['\"][^'\"]*\s*\+|query\s*=\s*['\"][^'\"]*\s*\+)",
        "severity": "HIGH",
        "description": "SQL Injection vulnerability detected. User input is directly concatenated into SQL query.",
        "fix": """Use parameterized queries instead of string concatenation:

For object-based queries:
```javascript
let query = {
    sql: "SELECT * FROM users WHERE id = ?",
    values: [userId]
};
connection.query(query, (err, result) => {
    res.json(result);
});
```

For string-based queries:
```javascript
connection.query("SELECT * FROM users WHERE id = ?", [userId], (err, result) => {
    res.json(result);
});
```"""
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "pattern": r"(res\.send\([^)]*\)|res\.write\([^)]*\)|document\.write\([^)]*\)|innerHTML\s*=)",
        "severity": "HIGH",
        "description": "Potential Cross-Site Scripting (XSS) vulnerability detected. User input might be rendered as HTML.",
        "fix": """Sanitize user input before rendering it as HTML:

```javascript
const sanitizeHtml = require('sanitize-html');
// For Express.js
res.send(sanitizeHtml(userInput));

// For DOM manipulation
element.textContent = userInput; // Use textContent instead of innerHTML
```"""
    },
    {
        "name": "Insecure Cookie",
        "pattern": r"(cookie\s*=|res\.cookie\([^)]*\))",
        "severity": "MEDIUM",
        "description": "Potential insecure cookie usage detected. Cookies should have secure and httpOnly flags.",
        "fix": """Set secure and httpOnly flags on cookies:

```javascript
// For Express.js
res.cookie('name', 'value', {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
});
```"""
    },
    {
        "name": "Eval Usage",
        "pattern": r"(eval\(|setTimeout\(['\"][^'\"]+['\"]|setInterval\(['\"][^'\"]+['\"]|new Function\()",
        "severity": "HIGH",
        "description": "Dangerous eval() or similar function usage detected. This can lead to code injection.",
        "fix": """Avoid using eval() and similar functions. Use safer alternatives:

```javascript
// Instead of eval(jsonString)
const data = JSON.parse(jsonString);

// Instead of setTimeout("functionName()", 1000)
setTimeout(functionName, 1000);
```"""
    },
    {
        "name": "Path Traversal",
        "pattern": r"(fs\.readFile\([^,]*\+|fs\.writeFile\([^,]*\+|fs\.readFileSync\([^)]*\+|fs\.writeFileSync\([^)]*\+)",
        "severity": "HIGH",
        "description": "Potential path traversal vulnerability detected. User input is used in file operations.",
        "fix": """Validate and sanitize file paths:

```javascript
const path = require('path');
const safeFilePath = path.normalize(path.join(__dirname, 'safe', 'path', fileName))
    .replace(/^(\.\.[\/\\])+/, '');
fs.readFile(safeFilePath, (err, data) => {
    // Handle file data
});
```"""
    },
    {
        "name": "Hardcoded Credentials",
        "pattern": r"(password\s*=\s*['\"][^'\"]{4,}['\"]|apiKey\s*=\s*['\"][^'\"]{4,}['\"]|secret\s*=\s*['\"][^'\"]{4,}['\"])",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected. Credentials should not be stored in code.",
        "fix": """Use environment variables or a secure configuration system:

```javascript
// Instead of hardcoded credentials
const password = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;

// Load from a secure configuration system
const config = require('./config');
const secret = config.getSecret('mySecret');
```"""
    }
]

class JSPatternScanner:
    """
    Pattern-based scanner for JavaScript files to detect security vulnerabilities.
    """

    def __init__(self):
        """
        Initialize the JavaScript pattern scanner.
        """
        self.patterns = VULNERABILITY_PATTERNS

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a JavaScript file for security vulnerabilities.

        Args:
            file_path (str): Path to the JavaScript file to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []

        if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            logging.info(f"Skipping non-JavaScript file: {file_path}")
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
                            id=f"JS-{pattern_info['name']}",
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
        Scan a directory for JavaScript security vulnerabilities.

        Args:
            directory (str): Path to the directory to scan.

        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)

        return vulnerabilities


def scan_js_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a JavaScript file for security vulnerabilities.

    Args:
        file_path (str): Path to the JavaScript file to scan.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = JSPatternScanner()
    return scanner.scan_file(file_path)


def scan_js_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for JavaScript security vulnerabilities.

    Args:
        directory (str): Path to the directory to scan.

    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = JSPatternScanner()
    return scanner.scan_directory(directory)
