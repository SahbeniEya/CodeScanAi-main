"""
This module provides a pattern-based Go scanner for detecting security vulnerabilities.
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
        "pattern": r"(db\.(?:Query|Exec|QueryRow)\([^,]*\+|db\.(?:Query|Exec|QueryRow)\([^,]*fmt\.Sprintf)",
        "severity": "HIGH",
        "description": "SQL Injection vulnerability detected. User input is directly used in SQL query.",
        "fix": """Use parameterized queries instead of string concatenation:

```go
// Instead of:
rows, err := db.Query("SELECT * FROM users WHERE id = " + userID)

// Use:
rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)

// Or with named parameters (using sqlx):
rows, err := db.NamedQuery("SELECT * FROM users WHERE id = :id", map[string]interface{}{"id": userID})
```"""
    },
    {
        "name": "Command-Injection",
        "pattern": r"(exec\.Command\([^,]*\+|exec\.Command\([^,]*fmt\.Sprintf)",
        "severity": "HIGH",
        "description": "Potential command injection vulnerability detected. User input is used in command execution.",
        "fix": """Avoid using user input in command execution. If necessary, validate and sanitize the input:

```go
// Instead of:
cmd := exec.Command("ls", "-l", userInput)

// Use a whitelist approach:
allowedDirs := []string{"home", "tmp", "var"}
valid := false
for _, dir := range allowedDirs {
    if userInput == dir {
        valid = true
        break
    }
}
if valid {
    cmd := exec.Command("ls", "-l", userInput)
    // Execute command
} else {
    // Handle error
}
```"""
    },
    {
        "name": "Path-Traversal",
        "pattern": r"(os\.(?:Open|Create|OpenFile|Stat|ReadFile|WriteFile)\([^)]*\+|ioutil\.(?:ReadFile|WriteFile)\([^)]*\+)",
        "severity": "HIGH",
        "description": "Potential path traversal vulnerability detected. User input is used in file operations.",
        "fix": """Validate and sanitize file paths:

```go
import (
    "path/filepath"
    "strings"
)

// Instead of:
file, err := os.Open(basePath + userInput)

// Use:
// Clean the path and ensure it's within the base directory
cleanPath := filepath.Clean(userInput)
if strings.HasPrefix(cleanPath, "..") {
    // Path traversal attempt
    return errors.New("invalid path")
}
fullPath := filepath.Join(basePath, cleanPath)
if !strings.HasPrefix(fullPath, basePath) {
    // Path is outside the base directory
    return errors.New("invalid path")
}
file, err := os.Open(fullPath)
```"""
    },
    {
        "name": "Insecure-Random",
        "pattern": r"(rand\.(?:Int|Float|Intn|Read)\(|mrand\.(?:Int|Float|Intn|Read)\()",
        "severity": "MEDIUM",
        "description": "Insecure random number generator detected. This can lead to predictable values.",
        "fix": """Use a cryptographically secure random number generator:

```go
import (
    "crypto/rand"
    "math/big"
)

// Instead of:
n := rand.Intn(100)

// Use:
// Generate a random number between 0 and 99
max := big.NewInt(100)
n, err := rand.Int(rand.Reader, max)
if err != nil {
    // Handle error
}
randomNumber := n.Int64()
```"""
    },
    {
        "name": "Hardcoded-Credentials",
        "pattern": r"((?:password|passwd|pwd|secret|key|token)\s*:?=\s*\"[^\"]{4,}\"|const\s+(?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN)\s*=\s*\"[^\"]{4,}\")",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected. Credentials should not be stored in code.",
        "fix": """Use environment variables or a secure configuration system:

```go
import (
    "os"
    "github.com/joho/godotenv"
)

// Instead of:
password := "hardcoded_password"

// Use environment variables:
// Load .env file if it exists
godotenv.Load()
password := os.Getenv("APP_PASSWORD")

// Or use a configuration package like Viper:
import "github.com/spf13/viper"

func init() {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.ReadInConfig()
}

password := viper.GetString("app.password")
```"""
    },
    {
        "name": "XSS",
        "pattern": r"(template\.HTML\(|template\.JS\(|template\.CSS\()",
        "severity": "HIGH",
        "description": "Potential Cross-Site Scripting (XSS) vulnerability detected. Content is marked as safe without proper sanitization.",
        "fix": """Avoid using template.HTML, template.JS, or template.CSS with untrusted input:

```go
// Instead of:
template.HTML(userInput)

// Use the default template escaping:
// In your template:
{{ .UserInput }}  // This is automatically escaped

// If you must use template.HTML, sanitize the input first:
import "github.com/microcosm-cc/bluemonday"

p := bluemonday.UGCPolicy()  // Use a policy appropriate for your use case
sanitized := p.Sanitize(userInput)
safeHTML := template.HTML(sanitized)
```"""
    }
]

class GoPatternScanner:
    """
    Pattern-based scanner for Go files to detect security vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the Go pattern scanner.
        """
        self.patterns = VULNERABILITY_PATTERNS
    
    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a Go file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the Go file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []
        
        if not file_path.endswith('.go'):
            logging.info(f"Skipping non-Go file: {file_path}")
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
                            id=f"GO-{pattern_info['name']}",
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
        Scan a directory for Go security vulnerabilities.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.go'):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities


def scan_go_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a Go file for security vulnerabilities.
    
    Args:
        file_path (str): Path to the Go file to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = GoPatternScanner()
    return scanner.scan_file(file_path)


def scan_go_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for Go security vulnerabilities.
    
    Args:
        directory (str): Path to the directory to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = GoPatternScanner()
    return scanner.scan_directory(directory)
