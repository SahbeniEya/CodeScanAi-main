from typing import List, Dict, Any, Optional
from core.validation.fix_validator import FixValidator
from core.scanners.sast_scanner import Vulnerability

class EnhancedFixValidator(FixValidator):
    """Enhanced validator for fix validation."""
    
    def __init__(self, directory: str) -> None: ...
    
    def enhanced_validate_fixes(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]: ...
