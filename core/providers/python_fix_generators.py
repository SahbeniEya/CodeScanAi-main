"""
This module provides custom fix generators for Python vulnerabilities.
"""

import logging
import re
from typing import Optional

from core.scanners.sast_scanner import Vulnerability


def generate_python_sql_injection_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for Python SQL injection vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is a SQL injection vulnerability
        if not any(term in vulnerability.id.lower() for term in ['sql', 'b608']):
            return None
        
        # Pattern 1: f-string SQL query
        if "f\"" in code or "f'" in code:
            # Extract the SQL query
            f_string_match = re.search(r'(f["\'])(.*?)(["\'])', code)
            if f_string_match:
                prefix = f_string_match.group(1)
                query = f_string_match.group(2)
                suffix = f_string_match.group(3)
                
                # Extract variables from the f-string
                variables = re.findall(r'\{([^}]+)\}', query)
                
                # Replace f-string with parameterized query
                parameterized_query = re.sub(r'\{([^}]+)\}', '?', query)
                
                # Create the fixed code
                fixed_code = code.replace(
                    f"{prefix}{query}{suffix}",
                    f'"{parameterized_query}"'
                )
                
                # Add parameters to the execute call
                if 'execute(' in fixed_code:
                    fixed_code = re.sub(
                        r'execute\(([^)]+)\)',
                        f'execute(\\1, [{", ".join(variables)}])',
                        fixed_code
                    )
                elif 'cursor.execute(' in fixed_code:
                    fixed_code = re.sub(
                        r'cursor\.execute\(([^)]+)\)',
                        f'cursor.execute(\\1, [{", ".join(variables)}])',
                        fixed_code
                    )
                
                return fixed_code
        
        # Pattern 2: string format SQL query
        elif ".format(" in code:
            # Extract the SQL query
            format_match = re.search(r'(["\'])(.*?)(["\'])\.format\((.*?)\)', code)
            if format_match:
                prefix = format_match.group(1)
                query = format_match.group(2)
                suffix = format_match.group(3)
                variables = format_match.group(4).split(',')
                
                # Replace format placeholders with parameterized query
                parameterized_query = re.sub(r'\{\}', '?', query)
                
                # Create the fixed code
                fixed_code = code.replace(
                    f"{prefix}{query}{suffix}.format({','.join(variables)})",
                    f'"{parameterized_query}"'
                )
                
                # Add parameters to the execute call
                if 'execute(' in fixed_code:
                    fixed_code = re.sub(
                        r'execute\(([^)]+)\)',
                        f'execute(\\1, [{", ".join(variables)}])',
                        fixed_code
                    )
                elif 'cursor.execute(' in fixed_code:
                    fixed_code = re.sub(
                        r'cursor\.execute\(([^)]+)\)',
                        f'cursor.execute(\\1, [{", ".join(variables)}])',
                        fixed_code
                    )
                
                return fixed_code
        
        # Pattern 3: string concatenation SQL query
        elif "+" in code and ("SELECT" in code or "INSERT" in code or "UPDATE" in code or "DELETE" in code):
            # Extract the SQL query
            concat_match = re.search(r'(["\'])(.*?)(["\']) \+ (.*?) \+ (["\'])(.*?)(["\'])', code)
            if concat_match:
                prefix1 = concat_match.group(1)
                query1 = concat_match.group(2)
                suffix1 = concat_match.group(3)
                variable = concat_match.group(4)
                prefix2 = concat_match.group(5)
                query2 = concat_match.group(6)
                suffix2 = concat_match.group(7)
                
                # Create the parameterized query
                parameterized_query = f"{query1}?{query2}"
                
                # Create the fixed code
                fixed_code = code.replace(
                    f"{prefix1}{query1}{suffix1} + {variable} + {prefix2}{query2}{suffix2}",
                    f'"{parameterized_query}"'
                )
                
                # Add parameters to the execute call
                if 'execute(' in fixed_code:
                    fixed_code = re.sub(
                        r'execute\(([^)]+)\)',
                        f'execute(\\1, [{variable}])',
                        fixed_code
                    )
                elif 'cursor.execute(' in fixed_code:
                    fixed_code = re.sub(
                        r'cursor\.execute\(([^)]+)\)',
                        f'cursor.execute(\\1, [{variable}])',
                        fixed_code
                    )
                
                return fixed_code
        
        # If we couldn't match a specific pattern, return a generic fix
        return generate_generic_python_sql_fix()
    
    except Exception as e:
        logging.error(f"Error generating Python SQL injection fix: {e}")
        return generate_generic_python_sql_fix()


def generate_generic_python_sql_fix() -> str:
    """Generate a generic fix for SQL injection in Python."""
    return """# Use parameterized queries instead of string concatenation or formatting
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", [username, password])"""


def generate_python_requests_timeout_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for Python requests without timeout vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is a requests timeout vulnerability
        if not any(term in vulnerability.id.lower() for term in ['timeout', 'b113']):
            return None
        
        # Pattern: requests.X without timeout
        if "requests." in code:
            # Extract the requests call
            requests_match = re.search(r'(requests\.[a-z]+\()([^)]+)(\))', code)
            if requests_match:
                prefix = requests_match.group(1)
                args = requests_match.group(2)
                suffix = requests_match.group(3)
                
                # Check if timeout is already specified
                if "timeout=" not in args:
                    # Add timeout parameter
                    if args.strip().endswith(','):
                        fixed_code = code.replace(
                            f"{prefix}{args}{suffix}",
                            f"{prefix}{args} timeout=30{suffix}"
                        )
                    else:
                        fixed_code = code.replace(
                            f"{prefix}{args}{suffix}",
                            f"{prefix}{args}, timeout=30{suffix}"
                        )
                    
                    return fixed_code
        
        # If we couldn't match a specific pattern, return a generic fix
        return generate_generic_python_requests_timeout_fix()
    
    except Exception as e:
        logging.error(f"Error generating Python requests timeout fix: {e}")
        return generate_generic_python_requests_timeout_fix()


def generate_generic_python_requests_timeout_fix() -> str:
    """Generate a generic fix for requests without timeout in Python."""
    return """# Always include a timeout parameter with requests
response = requests.post(api_url, headers=headers, json=payload, timeout=30)"""


def generate_python_flask_debug_fix(vulnerability: Vulnerability) -> Optional[str]:
    """
    Generate a fix for Python Flask debug mode vulnerabilities.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The suggested fix, or None if no fix could be generated.
    """
    try:
        # Use the code attribute directly
        code = vulnerability.code
        
        # Check if this is a Flask debug mode vulnerability
        if not any(term in vulnerability.id.lower() for term in ['flask', 'debug', 'b201']):
            return None
        
        # Pattern: app.run(debug=True)
        if "app.run" in code and "debug=True" in code:
            # Replace debug=True with debug=False
            fixed_code = code.replace("debug=True", "debug=False")
            
            # Add environment check
            if "__name__ == '__main__'" in code:
                # Add environment check before app.run
                fixed_code = fixed_code.replace(
                    "if __name__ == '__main__':",
                    """if __name__ == '__main__':
    # Use environment variable to control debug mode
    import os
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'"""
                )
                
                # Update app.run to use the environment variable
                fixed_code = fixed_code.replace(
                    "app.run(debug=False",
                    "app.run(debug=debug_mode"
                )
            
            return fixed_code
        
        # If we couldn't match a specific pattern, return a generic fix
        return generate_generic_python_flask_debug_fix()
    
    except Exception as e:
        logging.error(f"Error generating Python Flask debug fix: {e}")
        return generate_generic_python_flask_debug_fix()


def generate_generic_python_flask_debug_fix() -> str:
    """Generate a generic fix for Flask debug mode in Python."""
    return """if __name__ == '__main__':
    # Use environment variable to control debug mode
    import os
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)"""


def get_python_fix_generator_for_vulnerability(vulnerability: Vulnerability) -> Optional[str]:
    """
    Get the appropriate fix generator for a Python vulnerability based on its type.
    
    Args:
        vulnerability (Vulnerability): The vulnerability to generate a fix for.
        
    Returns:
        Optional[str]: The generated fix, or None if no fix could be generated.
    """
    # Check vulnerability type and description to determine the appropriate generator
    vuln_id = vulnerability.id.lower()
    vuln_desc = vulnerability.description.lower()
    
    # SQL Injection
    if 'sql' in vuln_id or 'b608' in vuln_id or 'sql injection' in vuln_desc:
        return generate_python_sql_injection_fix(vulnerability)
    
    # Requests without timeout
    elif 'timeout' in vuln_id or 'b113' in vuln_id or 'requests without timeout' in vuln_desc:
        return generate_python_requests_timeout_fix(vulnerability)
    
    # Flask debug mode
    elif 'flask' in vuln_id or 'debug' in vuln_id or 'b201' in vuln_id or 'flask app' in vuln_desc:
        return generate_python_flask_debug_fix(vulnerability)
    
    # Default: return None if no appropriate generator is found
    return None
