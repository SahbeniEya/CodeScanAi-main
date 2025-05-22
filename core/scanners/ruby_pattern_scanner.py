"""
This module provides a pattern-based Ruby scanner for detecting security vulnerabilities.
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
        "pattern": r"(\.execute\([^)]*\+|\.execute\([^)]*#{|Model\.where\([^)]*#{|Model\.find_by_sql\([^)]*#{)",
        "severity": "HIGH",
        "description": "SQL Injection vulnerability detected. User input is directly used in SQL query.",
        "fix": """Use parameterized queries instead of string interpolation:

```ruby
# Instead of:
User.where("name = '#{params[:name]}'")

# Use:
User.where("name = ?", params[:name])

# Or with named parameters:
User.where("name = :name", name: params[:name])

# For raw SQL:
# Instead of:
ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE name = '#{params[:name]}'")

# Use:
ActiveRecord::Base.connection.execute(
  ActiveRecord::Base.sanitize_sql_array(["SELECT * FROM users WHERE name = ?", params[:name]])
)
```"""
    },
    {
        "name": "XSS",
        "pattern": r"(\.html_safe|raw\(|<%=\s+[^%]+%>)",
        "severity": "HIGH",
        "description": "Potential Cross-Site Scripting (XSS) vulnerability detected. Content is marked as HTML safe without proper sanitization.",
        "fix": """Avoid using html_safe or raw without proper sanitization:

```ruby
# Instead of:
<%= user_input.html_safe %>

# Use:
<%= sanitize(user_input) %>

# Or use the built-in Rails helpers:
<%= h(user_input) %>

# For specific HTML elements, use the tag helpers:
<%= content_tag(:div, user_input) %>
```"""
    },
    {
        "name": "Command-Injection",
        "pattern": r"(`[^`]*#{|\%x\([^)]*#{|system\([^)]*#{|exec\([^)]*#{|Open3\.(?:capture|popen)[^)]*#{)",
        "severity": "HIGH",
        "description": "Potential command injection vulnerability detected. User input is used in command execution.",
        "fix": """Avoid using user input in command execution. If necessary, validate and sanitize the input:

```ruby
# Instead of:
system("ls #{params[:directory]}")

# Use a whitelist approach:
allowed_dirs = ['home', 'tmp', 'var']
if allowed_dirs.include?(params[:directory])
  system("ls #{params[:directory]}")
else
  # Handle error
end

# Or use Shellwords to escape arguments:
require 'shellwords'
system("ls #{Shellwords.escape(params[:directory])}")
```"""
    },
    {
        "name": "File-Access",
        "pattern": r"(File\.(?:read|write|open|new)\([^)]*#{|IO\.(?:read|write|open|new)\([^)]*#{)",
        "severity": "HIGH",
        "description": "Potential file access vulnerability detected. User input is used in file operations.",
        "fix": """Validate and sanitize file paths:

```ruby
# Instead of:
File.read("#{params[:filename]}")

# Use:
# Ensure the file is in a safe directory
safe_dir = Rails.root.join('public', 'files')
filename = File.basename(params[:filename])
path = File.join(safe_dir, filename)

# Check that the resolved path is within the safe directory
if path.start_with?(safe_dir.to_s) && File.exist?(path)
  content = File.read(path)
else
  # Handle error
end
```"""
    },
    {
        "name": "Mass-Assignment",
        "pattern": r"(\.update\(params\[:|\.create\(params\[:|\.new\(params\[:|\.build\(params\[:|\.assign_attributes\(params\[:|\.attributes=\(params\[:)",
        "severity": "MEDIUM",
        "description": "Potential mass assignment vulnerability detected. Use strong parameters to whitelist attributes.",
        "fix": """Use strong parameters to whitelist attributes:

```ruby
# In your controller:
def user_params
  params.require(:user).permit(:name, :email, :age)
end

# Then use it:
@user.update(user_params)
# or
@user = User.create(user_params)
```"""
    },
    {
        "name": "Hardcoded-Credentials",
        "pattern": r"((?:password|passwd|pwd|secret|key|token)\s*=\s*['\"][^'\"]{4,}['\"]|ENV\[['\"](?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN)['\"]]\s*\|\|\s*['\"][^'\"]{4,}['\"])",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected. Credentials should not be stored in code.",
        "fix": """Use environment variables or a secure configuration system:

```ruby
# Instead of:
password = "hardcoded_password"

# Use environment variables:
password = ENV['APP_PASSWORD']

# Or use a configuration gem like Figaro or dotenv:
# With Figaro:
password = Figaro.env.app_password

# With Rails credentials (Rails 5.2+):
password = Rails.application.credentials.app_password
```"""
    }
]

class RubyPatternScanner:
    """
    Pattern-based scanner for Ruby files to detect security vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the Ruby pattern scanner.
        """
        self.patterns = VULNERABILITY_PATTERNS
    
    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a Ruby file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the Ruby file to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return []
        
        if not file_path.endswith(('.rb', '.rake', '.gemspec', 'Gemfile', 'Rakefile')):
            logging.info(f"Skipping non-Ruby file: {file_path}")
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
                            id=f"RUBY-{pattern_info['name']}",
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
        Scan a directory for Ruby security vulnerabilities.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            List[Vulnerability]: List of found vulnerabilities.
        """
        vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.rb', '.rake', '.gemspec')) or file in ('Gemfile', 'Rakefile'):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulnerabilities)
        
        return vulnerabilities


def scan_ruby_file(file_path: str) -> List[Vulnerability]:
    """
    Scan a Ruby file for security vulnerabilities.
    
    Args:
        file_path (str): Path to the Ruby file to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = RubyPatternScanner()
    return scanner.scan_file(file_path)


def scan_ruby_directory(directory: str) -> List[Vulnerability]:
    """
    Scan a directory for Ruby security vulnerabilities.
    
    Args:
        directory (str): Path to the directory to scan.
        
    Returns:
        List[Vulnerability]: List of found vulnerabilities.
    """
    scanner = RubyPatternScanner()
    return scanner.scan_directory(directory)
