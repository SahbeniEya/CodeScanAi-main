"""
This module provides a pattern-based Java scanner for detecting security vulnerabilities.
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
        "pattern": r"(Statement\.executeQuery\([^)]*\+|createStatement\(\)\.executeQuery\([^)]*\+|prepareStatement\([^)]*\+)",
        "severity": "HIGH",
        "description": "SQL Injection vulnerability detected. User input is directly concatenated into SQL query.",
        "fix": """Use parameterized queries instead of string concatenation:

```java
// Instead of:
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// Use:
PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```"""
    },
    {
        "name": "XSS",
        "pattern": r"(response\.getWriter\(\)\.print\([^)]*\)|response\.getWriter\(\)\.println\([^)]*\)|out\.print\([^)]*\)|out\.println\([^)]*\))",
        "severity": "HIGH",
        "description": "Potential Cross-Site Scripting (XSS) vulnerability detected. User input might be rendered as HTML.",
        "fix": """Sanitize user input before rendering it as HTML:

```java
// Import the OWASP ESAPI library
import org.owasp.esapi.ESAPI;

// Instead of:
out.println(userInput);

// Use:
out.println(ESAPI.encoder().encodeForHTML(userInput));
```"""
    },
    {
        "name": "Path-Traversal",
        "pattern": r"(new File\([^)]*\+|new FileInputStream\([^)]*\+|new FileOutputStream\([^)]*\+)",
        "severity": "HIGH",
        "description": "Potential path traversal vulnerability detected. User input is used in file operations.",
        "fix": """Validate and sanitize file paths:

```java
// Import necessary classes
import java.nio.file.Path;
import java.nio.file.Paths;

// Instead of:
File file = new File(basePath + userInput);

// Use:
Path path = Paths.get(basePath).normalize();
Path resolvedPath = path.resolve(userInput).normalize();
if (!resolvedPath.startsWith(path)) {
    throw new SecurityException("Path traversal attempt detected");
}
File file = resolvedPath.toFile();
```"""
    },
    {
        "name": "Command-Injection",
        "pattern": r"(Runtime\.getRuntime\(\)\.exec\([^)]*\+|ProcessBuilder\([^)]*\+)",
        "severity": "HIGH",
        "description": "Potential command injection vulnerability detected. User input is used in command execution.",
        "fix": """Avoid using user input in command execution. If necessary, validate and sanitize the input:

```java
// Instead of:
Runtime.getRuntime().exec("cmd.exe /c " + userInput);

// Use a whitelist approach:
List<String> allowedCommands = Arrays.asList("ls", "dir", "echo");
if (!allowedCommands.contains(userInput)) {
    throw new SecurityException("Invalid command");
}
Runtime.getRuntime().exec(userInput);
```"""
    },
    {
        "name": "Insecure-Random",
        "pattern": r"(new Random\(\)|Math\.random\(\))",
        "severity": "MEDIUM",
        "description": "Insecure random number generator detected. This can lead to predictable values.",
        "fix": """Use a secure random number generator:

```java
// Import necessary classes
import java.security.SecureRandom;

// Instead of:
Random random = new Random();
int value = random.nextInt();

// Use:
SecureRandom secureRandom = new SecureRandom();
int value = secureRandom.nextInt();
```"""
    },
    {
        "name": "Hardcoded-Credentials",
        "pattern": r"(String\s+(?:password|passwd|pwd|secret|key|token)\s*=\s*\"[^\"]{4,}\"|private\s+static\s+final\s+String\s+(?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN)\s*=\s*\"[^\"]{4,}\")",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected. Credentials should not be stored in code.",
        "fix": """Use environment variables or a secure configuration system:

```java
// Instead of:
String password = "hardcoded_password";

// Use:
String password = System.getenv("APP_PASSWORD");
// Or use a properties file that is not checked into version control
Properties props = new Properties();
props.load(new FileInputStream("config.properties"));
String password = props.getProperty("app.password");
```"""
    }
]

class JavaPatternScanner:
    """
    Pattern-based scanner for Java files to detect security vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the Java pattern scanner.
        """
        self.patterns = VULNERABILITY_PATTERNS
    
    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a Java file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the Java file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []
        
        if not file_path.endswith('.java'):
            logging.info(f"Skipping non-Java file: {file_path}")
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
                            id=f"JAVA-{pattern_info['name']}",
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
        Scan a directory for Java security vulnerabilities.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities


def scan_java_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a Java file for security vulnerabilities.
    
    Args:
        file_path (str): Path to the Java file to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = JavaPatternScanner()
    return scanner.scan_file(file_path)


def scan_java_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for Java security vulnerabilities.
    
    Args:
        directory (str): Path to the directory to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = JavaPatternScanner()
    return scanner.scan_directory(directory)
