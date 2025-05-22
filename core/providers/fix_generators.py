"""
This module provides custom fix generators for different types of vulnerabilities.
"""

import logging
import re
import os
from typing import Optional, Dict, Any, List, Tuple

from core.scanners.sast_scanner import Vulnerability


def generate_js_sql_injection_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for JavaScript SQL injection vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is a SQL injection vulnerability
        if not any(term in vulnerability.description.lower() for term in ['sql injection', 'sql query']):
            return None
        
        # Extract the function body to preserve the overall structure
        function_match = re.search(r'(router\.get\([^{]+{)([\s\S]+?)(}\))', code)
        if not function_match:
            # If we can't match the function pattern, return a generic fix
            return generate_generic_js_sql_fix()
        
        function_start = function_match.group(1)
        function_body = function_match.group(2)
        function_end = function_match.group(3)
        
        # Extract the variable name that contains user input
        var_match = re.search(r'let\s+(\w+)\s*=\s*req\.params\.(\w+)', function_body)
        if not var_match:
            # If we can't find the variable, return a generic fix
            return generate_generic_js_sql_fix()
        
        variable_name = var_match.group(1)
        
        # Pattern 1: connection.query with object containing sql property
        if "connection.query({" in function_body and "sql" in function_body:
            # Create a fixed function body with proper parameterized query
            fixed_body = re.sub(
                r'connection\.query\(\{\s*sql\s*:\s*["\']([^"\']+)["\'](\s*\+\s*\w+)[^}]*\}',
                f'connection.query({{\n        sql: "\\1 ?",\n        values: [{variable_name}]',
                function_body
            )
            
            # Add error handling
            fixed_body = add_error_handling(fixed_body)
            
            # Combine the parts back together
            return function_start + fixed_body + function_end
            
        # Pattern 2: Direct connection.query with string concatenation
        elif "connection.query(" in function_body and "+" in function_body:
            # Create a fixed function body with proper parameterized query
            fixed_body = re.sub(
                r'connection\.query\(\s*["\']([^"\']+)["\'](\s*\+\s*\w+)',
                f'connection.query("\\1 ?", [{variable_name}]',
                function_body
            )
            
            # Add error handling
            fixed_body = add_error_handling(fixed_body)
            
            # Combine the parts back together
            return function_start + fixed_body + function_end
        
        # If we couldn't match a specific pattern, try direct replacements
        if "connection.query" in function_body:
            # Example 1: query object
            if "let query = {" in function_body:
                fixed_body = function_body.replace(
                    f'sql : "SELECT * FROM users WHERE id=" + {variable_name}',
                    f'sql : "SELECT * FROM users WHERE id=?",\n        values: [{variable_name}]'
                )
                fixed_body = add_error_handling(fixed_body)
                return function_start + fixed_body + function_end
                
            # Example 2: direct query
            elif 'connection.query("SELECT' in function_body:
                fixed_body = function_body.replace(
                    f'connection.query("SELECT * FROM users WHERE id=" + {variable_name}',
                    f'connection.query("SELECT * FROM users WHERE id=?", [{variable_name}]'
                )
                fixed_body = add_error_handling(fixed_body)
                return function_start + fixed_body + function_end
                
            # Example 3: query object, different format
            elif "connection.query({" in function_body:
                fixed_body = function_body.replace(
                    f'sql : "SELECT * FROM users WHERE id=" +{variable_name}',
                    f'sql : "SELECT * FROM users WHERE id=?",\n        values: [{variable_name}]'
                )
                fixed_body = add_error_handling(fixed_body)
                return function_start + fixed_body + function_end
        
        # If all else fails, return a generic fix
        return generate_generic_js_sql_fix()
    
    except Exception as e:
        logging.error(f"Error generating JavaScript SQL injection fix: {e}")
        return generate_generic_js_sql_fix()


def add_error_handling(code: str) -> str:
    """Add error handling to the query callback."""
    if "(err, result)" in code and "res.json(result)" in code:
        return code.replace(
            "(err, result) => {\n        res.json(result);",
            "(err, result) => {\n        if (err) {\n            console.error(err);\n            return res.status(500).send('Server error');\n        }\n        res.json(result);"
        )
    return code


def generate_generic_js_sql_fix() -> str:
    """Generate a generic fix for SQL injection in JavaScript."""
    return """router.get('/example/user/:id', (req, res) => {
    let userId = req.params.id;
    
    // Use parameterized queries with placeholders
    connection.query("SELECT * FROM users WHERE id = ?", [userId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }
        res.json(result);
    });
})"""


def generate_js_xss_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for JavaScript XSS vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is an XSS vulnerability
        if not any(term in vulnerability.description.lower() for term in ['xss', 'cross-site scripting', 'cross site scripting']):
            return None
        
        # Extract the function body to preserve the overall structure
        function_match = re.search(r'((?:app|router)\.[a-z]+\([^{]+{)([\s\S]+?)(}\))', code)
        if not function_match:
            # If we can't match the function pattern, return a generic fix
            return generate_generic_js_xss_fix()
        
        function_start = function_match.group(1)
        function_body = function_match.group(2)
        function_end = function_match.group(3)
        
        # Pattern 1: Direct insertion of user input into HTML
        if re.search(r'res\.send\([^)]*\$\{[^}]+\}', function_body) or re.search(r'res\.send\([^)]*\+', function_body):
            # Replace direct insertion with proper escaping
            fixed_body = re.sub(
                r'res\.send\(([^)]*)\$\{([^}]+)\}([^)]*)\)',
                r'res.send(\1${escapeHtml(\2)}\3)',
                function_body
            )
            
            # Also handle concatenation style
            fixed_body = re.sub(
                r'res\.send\(([^)]*) \+ ([^)]+) \+ ([^)]*)\)',
                r'res.send(\1 + escapeHtml(\2) + \3)',
                fixed_body
            )
            
            # Add the escapeHtml function if it's not already in the code
            if 'function escapeHtml' not in code:
                fixed_body = """    // Add HTML escaping function
    function escapeHtml(unsafe) {
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
""" + fixed_body
            
            # Combine the parts back together
            return function_start + fixed_body + function_end
        
        # Pattern 2: res.render with unescaped variables
        elif 'res.render' in function_body:
            # Extract the template and data object
            render_match = re.search(r'res\.render\([\'"](\w+)[\'"]?\s*,\s*({[^}]+})\)', function_body)
            if render_match:
                template_name = render_match.group(1)
                data_obj = render_match.group(2)
                
                # Add explicit escaping for each variable in the data object
                data_obj_lines = data_obj.strip().split('\n')
                escaped_data_obj = []
                
                for line in data_obj_lines:
                    if ':' in line and not any(safe_term in line for safe_term in ['escapeHtml', 'encodeURIComponent']):
                        key, value = line.split(':', 1)
                        escaped_data_obj.append(f"{key}: escapeHtml({value.strip()})")
                    else:
                        escaped_data_obj.append(line)
                
                escaped_data_obj_str = '\n'.join(escaped_data_obj)
                
                # Replace the original render call with the escaped version
                fixed_body = function_body.replace(
                    f'res.render("{template_name}", {data_obj})',
                    f'res.render("{template_name}", {escaped_data_obj_str})'
                )
                
                # Add the escapeHtml function if it's not already in the code
                if 'function escapeHtml' not in code:
                    fixed_body = """    // Add HTML escaping function
    function escapeHtml(unsafe) {
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
""" + fixed_body
                
                # Combine the parts back together
                return function_start + fixed_body + function_end
        
        # Pattern 3: innerHTML assignment
        elif 'innerHTML' in function_body:
            # Replace innerHTML with textContent
            fixed_body = re.sub(
                r'([\w\.]+)\.innerHTML\s*=\s*([^;]+)',
                r'\1.textContent = \2',
                function_body
            )
            
            # Combine the parts back together
            return function_start + fixed_body + function_end
        
        # If we couldn't match a specific pattern, return a generic fix
        return generate_generic_js_xss_fix()
    
    except Exception as e:
        logging.error(f"Error generating JavaScript XSS fix: {e}")
        return generate_generic_js_xss_fix()


def generate_generic_js_xss_fix() -> str:
    """Generate a generic fix for XSS in JavaScript."""
    return """app.get('/example', (req, res) => {
    const userInput = req.query.input;
    
    // Always escape user input before inserting into HTML
    function escapeHtml(unsafe) {
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    // Use a templating engine with auto-escaping
    res.render('template', { 
        userInput: escapeHtml(userInput) 
    });
    
    // Or for direct HTML responses, escape the input
    // res.send(`<p>You said: ${escapeHtml(userInput)}</p>`);
})"""


def generate_js_command_injection_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for JavaScript command injection vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is a command injection vulnerability
        if not any(term in vulnerability.description.lower() for term in ['command injection', 'os command', 'shell injection']):
            return None
        
        # Extract the function body to preserve the overall structure
        function_match = re.search(r'((?:app|router)\.[a-z]+\([^{]+{)([\s\S]+?)(}\))', code)
        if not function_match:
            # If we can't match the function pattern, return a generic fix
            return generate_generic_js_command_injection_fix()
        
        function_start = function_match.group(1)
        function_body = function_match.group(2)
        function_end = function_match.group(3)
        
        # Pattern 1: child_process.exec with user input
        if 'child_process.exec' in function_body or 'exec(' in function_body:
            # Extract the command being executed
            exec_match = re.search(r'(?:child_process\.)?exec\(([^)]+)\)', function_body)
            if exec_match:
                command = exec_match.group(1)
                
                # Check if the command contains user input
                if '+' in command or '${' in command:
                    # Replace with execFile and sanitized arguments
                    fixed_body = function_body
                    
                    # Add input validation
                    var_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:params|query|body)\.(\w+)', function_body)
                    if var_match:
                        var_name = var_match.group(1)
                        
                        # Add validation for the user input
                        validation_code = f"""    // Validate user input
    if (!/^[a-zA-Z0-9_\\-\\.]+$/.test({var_name})) {{
        return res.status(400).send('Invalid input');
    }}
    
"""
                        
                        # Insert the validation code after the variable declaration
                        fixed_body = re.sub(
                            f'(?:const|let|var)\\s+{var_name}\\s*=\\s*req\\.(?:params|query|body)\\.\\w+;?\\n',
                            f'\\g<0>{validation_code}',
                            fixed_body
                        )
                    
                    # Replace exec with execFile
                    fixed_body = re.sub(
                        r'(?:child_process\.)?exec\(([^)]+)\)',
                        r'child_process.execFile(\'command\', [sanitizedArgs], ',
                        fixed_body
                    )
                    
                    # Add the sanitization function
                    if 'function sanitizeInput' not in code:
                        fixed_body = """    // Add input sanitization function
    function sanitizeInput(input) {
        // Only allow alphanumeric characters, underscore, dash, and dot
        return String(input).replace(/[^a-zA-Z0-9_\\-\\.]/g, '');
    }
    
    // Use an allowlist of commands and arguments
    const allowedCommands = ['ls', 'cat', 'echo'];
    const command = 'echo'; // Use a fixed command
    const sanitizedArgs = [sanitizeInput(userInput)]; // Sanitize arguments
    
""" + fixed_body
                    
                    # Combine the parts back together
                    return function_start + fixed_body + function_end
        
        # Pattern 2: Using spawn with user input in shell option
        elif 'spawn(' in function_body and 'shell: true' in function_body:
            # Replace shell: true with shell: false
            fixed_body = function_body.replace('shell: true', 'shell: false')
            
            # Add input validation
            var_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:params|query|body)\.(\w+)', function_body)
            if var_match:
                var_name = var_match.group(1)
                
                # Add validation for the user input
                validation_code = f"""    // Validate user input
    if (!/^[a-zA-Z0-9_\\-\\.]+$/.test({var_name})) {{
        return res.status(400).send('Invalid input');
    }}
    
"""
                
                # Insert the validation code after the variable declaration
                fixed_body = re.sub(
                    f'(?:const|let|var)\\s+{var_name}\\s*=\\s*req\\.(?:params|query|body)\\.\\w+;?\\n',
                    f'\\g<0>{validation_code}',
                    fixed_body
                )
            
            # Combine the parts back together
            return function_start + fixed_body + function_end
        
        # If we couldn't match a specific pattern, return a generic fix
        return generate_generic_js_command_injection_fix()
    
    except Exception as e:
        logging.error(f"Error generating JavaScript command injection fix: {e}")
        return generate_generic_js_command_injection_fix()


def generate_generic_js_command_injection_fix() -> str:
    """Generate a generic fix for command injection in JavaScript."""
    return """app.get('/example', (req, res) => {
    const userInput = req.query.input;
    
    // Validate user input
    if (!/^[a-zA-Z0-9_\\-\\.]+$/.test(userInput)) {
        return res.status(400).send('Invalid input');
    }
    
    // Use execFile instead of exec
    const { execFile } = require('child_process');
    
    // Use a fixed command and pass user input as an argument
    execFile('echo', [userInput], (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error}`);
            return res.status(500).send('Server error');
        }
        res.send(stdout);
    });
})"""


def generate_js_path_traversal_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for JavaScript path traversal vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is a path traversal vulnerability
        if not any(term in vulnerability.description.lower() for term in ['path traversal', 'directory traversal', 'file inclusion']):
            return None
        
        # Extract the function body to preserve the overall structure
        function_match = re.search(r'((?:app|router)\.[a-z]+\([^{]+{)([\s\S]+?)(}\))', code)
        if not function_match:
            # If we can't match the function pattern, return a generic fix
            return generate_generic_js_path_traversal_fix()
        
        function_start = function_match.group(1)
        function_body = function_match.group(2)
        function_end = function_match.group(3)
        
        # Pattern 1: fs.readFile with user input
        if 'fs.readFile' in function_body:
            # Extract the file path being read
            file_match = re.search(r'fs\.readFile\(([^,]+)', function_body)
            if file_match:
                file_path = file_match.group(1)
                
                # Check if the file path contains user input
                if '+' in file_path or '${' in file_path:
                    # Replace with path.resolve and path.normalize
                    fixed_body = """    const path = require('path');
    
    // Define a safe base directory
    const baseDir = path.resolve(__dirname, 'public');
    
"""
                    
                    # Add input validation
                    var_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:params|query|body)\.(\w+)', function_body)
                    if var_match:
                        var_name = var_match.group(1)
                        
                        # Add validation for the user input
                        validation_code = f"""    // Validate user input
    if (!/^[a-zA-Z0-9_\\-\\.]+$/.test({var_name})) {{
        return res.status(400).send('Invalid input');
    }}
    
    // Construct a safe file path
    const filePath = path.join(baseDir, {var_name});
    
    // Verify the path is within the base directory
    if (!filePath.startsWith(baseDir)) {{
        return res.status(400).send('Invalid path');
    }}
    
"""
                        
                        # Replace the original file path construction
                        fixed_body += validation_code
                        
                        # Replace the fs.readFile call
                        fixed_body += function_body.replace(
                            f'fs.readFile({file_path}',
                            'fs.readFile(filePath'
                        )
                        
                        # Combine the parts back together
                        return function_start + fixed_body + function_end
        
        # Pattern 2: Using express.static with user input
        elif 'express.static' in function_body:
            # Replace with a fixed path
            fixed_body = function_body.replace(
                'express.static(userInput)',
                'express.static(path.resolve(__dirname, \'public\'))'
            )
            
            # Add the path module if not already imported
            if 'require(\'path\')' not in code and 'require("path")' not in code:
                fixed_body = "    const path = require('path');\n" + fixed_body
            
            # Combine the parts back together
            return function_start + fixed_body + function_end
        
        # If we couldn't match a specific pattern, return a generic fix
        return generate_generic_js_path_traversal_fix()
    
    except Exception as e:
        logging.error(f"Error generating JavaScript path traversal fix: {e}")
        return generate_generic_js_path_traversal_fix()


def generate_generic_js_path_traversal_fix() -> str:
    """Generate a generic fix for path traversal in JavaScript."""
    return """app.get('/example', (req, res) => {
    const fileName = req.query.file;
    const fs = require('fs');
    const path = require('path');
    
    // Validate user input
    if (!/^[a-zA-Z0-9_\\-\\.]+$/.test(fileName)) {
        return res.status(400).send('Invalid filename');
    }
    
    // Define a safe base directory
    const baseDir = path.resolve(__dirname, 'public');
    
    // Construct a safe file path
    const filePath = path.join(baseDir, fileName);
    
    // Verify the path is within the base directory
    if (!filePath.startsWith(baseDir)) {
        return res.status(400).send('Invalid path');
    }
    
    // Read the file safely
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(404).send('File not found');
        }
        res.send(data);
    });
})"""


def get_fix_generator_for_vulnerability(vulnerability: Vulnerability) -> Optional[str]:
    """
    Get the appropriate fix generator for a vulnerability based on its type.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The generated fix, or None if no fix could be generated.
    """
    # Check vulnerability type and description to determine the appropriate generator
    vuln_id = vulnerability.id.lower()
    vuln_desc = vulnerability.description.lower()
    
    # SQL Injection
    if 'sql' in vuln_id or 'sql injection' in vuln_desc:
        return generate_js_sql_injection_fix(vulnerability)
    
    # XSS
    elif 'xss' in vuln_id or 'cross-site scripting' in vuln_desc or 'cross site scripting' in vuln_desc:
        return generate_js_xss_fix(vulnerability)
    
    # Command Injection
    elif 'command' in vuln_id or 'command injection' in vuln_desc or 'os command' in vuln_desc:
        return generate_js_command_injection_fix(vulnerability)
    
    # Path Traversal
    elif 'path' in vuln_id or 'path traversal' in vuln_desc or 'directory traversal' in vuln_desc:
        return generate_js_path_traversal_fix(vulnerability)
    
    # Default: return None if no appropriate generator is found
    return None
