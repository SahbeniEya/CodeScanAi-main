"""
This module provides a pattern-based C scanner for detecting security vulnerabilities.
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

# Vulnerability patterns for C code
VULNERABILITY_PATTERNS = [
    {
        "name": "Buffer-Overflow",
        "pattern": r"(strcpy\s*\([^,]*,|strcat\s*\([^,]*,|gets\s*\([^)]*\)|sprintf\s*\([^,]*,[^,]*,[^,]*\))",
        "severity": "HIGH",
        "description": "Buffer overflow vulnerability detected. Unsafe string functions are used without bounds checking.",
        "fix": """Use safer alternatives with bounds checking:
```c
// Instead of:
char buffer[10];
strcpy(buffer, user_input);  // Dangerous!

// Use:
char buffer[10];
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0';  // Ensure null termination

// Or better yet, use strlcpy if available:
strlcpy(buffer, user_input, sizeof(buffer));
```"""
    },
    {
        "name": "Format-String",
        "pattern": r"(printf\s*\([^,)]*\)|fprintf\s*\([^,]*,[^,)]*\)|sprintf\s*\([^,]*,[^,)]*\)|snprintf\s*\([^,]*,[^,]*,[^,)]*\))",
        "severity": "HIGH",
        "description": "Format string vulnerability detected. User input may be used as format string.",
        "fix": """Always use a literal format string:
```c
// Instead of:
printf(user_input);  // Dangerous!

// Use:
printf("%s", user_input);  // Safe
```"""
    },
    {
        "name": "Integer-Overflow",
        "pattern": r"(\w+\s*\+=|\w+\s*\*=|\w+\s*=\s*\w+\s*\+|\w+\s*=\s*\w+\s*\*)",
        "severity": "MEDIUM",
        "description": "Potential integer overflow. Integer operations without bounds checking.",
        "fix": """Check bounds before performing operations:
```c
// Instead of:
int result = a + b;  // Potential overflow

// Use:
if (a > INT_MAX - b) {
    // Handle error: would overflow
} else {
    int result = a + b;  // Safe
}
```"""
    },
    {
        "name": "Memory-Leak",
        "pattern": r"(malloc\s*\(|calloc\s*\(|realloc\s*\()",
        "severity": "MEDIUM",
        "description": "Potential memory leak. Ensure all allocated memory is freed.",
        "fix": """Always free allocated memory:
```c
// Instead of:
char *ptr = malloc(size);
// ... use ptr ...
// Missing free(ptr)

// Use:
char *ptr = malloc(size);
if (ptr == NULL) {
    // Handle allocation failure
}
// ... use ptr ...
free(ptr);
ptr = NULL;  // Avoid use-after-free
```"""
    },
    {
        "name": "Command-Injection",
        "pattern": r"(system\s*\([^)]*\)|popen\s*\([^)]*\)|exec[lv][pe]?\s*\()",
        "severity": "HIGH",
        "description": "Command injection vulnerability detected. User input may be used to execute commands.",
        "fix": """Avoid using system() with user input:
```c
// Instead of:
char cmd[100];
sprintf(cmd, "ls %s", user_input);  // Dangerous!
system(cmd);

// Use input validation or safer alternatives:
// 1. Validate input thoroughly
if (!is_valid_filename(user_input)) {
    // Handle error
    return;
}

// 2. Or use safer APIs like execve() with careful argument construction
```"""
    },
    {
        "name": "Use-After-Free",
        "pattern": r"(free\s*\([^)]+\).*\1)",
        "severity": "HIGH",
        "description": "Potential use-after-free vulnerability. Memory is used after being freed.",
        "fix": """Set pointers to NULL after freeing:
```c
// Instead of:
free(ptr);
// ... ptr is still used ...

// Use:
free(ptr);
ptr = NULL;  // Prevent use-after-free
// ... check ptr is not NULL before using ...
```"""
    },
    {
        "name": "Null-Pointer-Dereference",
        "pattern": r"(\w+\s*->\s*\w+|\*\s*\w+)",
        "severity": "MEDIUM",
        "description": "Potential null pointer dereference. Pointers should be checked before use.",
        "fix": """Always check pointers before dereferencing:
```c
// Instead of:
result = ptr->member;  // Dangerous if ptr is NULL

// Use:
if (ptr != NULL) {
    result = ptr->member;  // Safe
} else {
    // Handle NULL pointer case
}
```"""
    },
    {
        "name": "Hardcoded-Credentials",
        "pattern": r"(char\s+(?:password|passwd|pwd|secret|key|token)\s*\[\s*\d+\s*\]\s*=\s*\"[^\"]{4,}\"|#define\s+(?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN)\s+\"[^\"]{4,}\")",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected. Credentials should not be stored in code.",
        "fix": """Use environment variables or a secure configuration system:
```c
// Instead of:
char password[] = "hardcoded_secret";  // Dangerous!

// Use:
char *password = getenv("APP_PASSWORD");
if (password == NULL) {
    // Handle missing environment variable
}
```"""
    }
]


class CPatternScanner:
    """
    Pattern-based scanner for C files to detect security vulnerabilities.
    """

    def __init__(self):
        """
        Initialize the C pattern scanner.
        """
        self.patterns = VULNERABILITY_PATTERNS

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a C file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the C file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []
        
        if not file_path.endswith(('.c', '.h', '.cpp', '.hpp', '.cc')):
            logging.info(f"Skipping non-C/C++ file: {file_path}")
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
                            id=f"C-{pattern_info['name']}",
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
        Scan a directory for C security vulnerabilities.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.c', '.h', '.cpp', '.hpp', '.cc')):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities


def scan_c_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a C file for security vulnerabilities.
    
    Args:
        file_path (str): Path to the C file to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = CPatternScanner()
    return scanner.scan_file(file_path)


def scan_c_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for C security vulnerabilities.
    
    Args:
        directory (str): Path to the directory to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = CPatternScanner()
    return scanner.scan_directory(directory)
