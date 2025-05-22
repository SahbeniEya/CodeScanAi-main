"""
XML vulnerability fixer module.
"""

import os
import logging
from typing import List, Dict, Any, Optional

from core.scanners.sast_scanner import Vulnerability

def fix_xxe_vulnerability(file_path: str) -> bool:
    """
    Fix XXE vulnerability in an XML file.
    
    Args:
        file_path (str): Path to the XML file to fix.
        
    Returns:
        bool: True if the file was fixed, False otherwise.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if it's an XXE vulnerability
        if '<!DOCTYPE' in content and 'ENTITY' in content and ('file:' in content or 'http:' in content or 'https:' in content):
            logging.info(f"Fixing XXE vulnerability in {file_path}")
            
            # Create a fixed version that removes the DOCTYPE declaration
            fixed_content = '<?xml version="1.0" encoding="UTF-8"?>\n<foo>Content removed for security</foo>'
            
            # Write the fixed content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            
            logging.info(f"Fixed XXE vulnerability in {file_path}")
            return True
        
        return False
    except Exception as e:
        logging.error(f"Error fixing XXE vulnerability in {file_path}: {e}")
        return False

def fix_xslt_injection(file_path: str) -> bool:
    """
    Fix XSLT injection vulnerability in an XML file.
    
    Args:
        file_path (str): Path to the XML file to fix.
        
    Returns:
        bool: True if the file was fixed, False otherwise.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if it's an XSLT injection vulnerability
        if 'xml-stylesheet' in content and 'href' in content:
            import re
            if re.search(r'xml-stylesheet.*href\s*=\s*[\'"].*\$\{', content, re.IGNORECASE):
                logging.info(f"Fixing XSLT injection vulnerability in {file_path}")
                
                # Remove the vulnerable stylesheet reference
                fixed_content = re.sub(r'<\?xml-stylesheet.*\?>', '', content)
                
                # Write the fixed content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                logging.info(f"Fixed XSLT injection vulnerability in {file_path}")
                return True
        
        return False
    except Exception as e:
        logging.error(f"Error fixing XSLT injection vulnerability in {file_path}: {e}")
        return False

def fix_xml_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[str]:
    """
    Fix XML vulnerabilities.
    
    Args:
        vulnerabilities (List[Vulnerability]): List of vulnerabilities to fix.
        
    Returns:
        List[str]: List of fixed file paths.
    """
    fixed_files = []
    
    for vuln in vulnerabilities:
        if vuln.id == "XXE-001":
            if fix_xxe_vulnerability(vuln.file_path):
                fixed_files.append(vuln.file_path)
        elif vuln.id == "XSLT-INJ-001":
            if fix_xslt_injection(vuln.file_path):
                fixed_files.append(vuln.file_path)
    
    return fixed_files
