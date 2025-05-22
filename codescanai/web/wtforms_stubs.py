"""
Type stubs for WTForms to fix type checking issues.
"""
from typing import Any, Callable, Dict, List, Optional, Sequence, Type, TypeVar, Union, Protocol

T = TypeVar('T')

class FormField(Protocol):
    """Protocol for form fields."""
    name: str
    label: str
    default: Any
    data: Any
    
    def __call__(self, **kwargs: Any) -> Any: ...
    def validate(self, form: Any, extra_validators: Optional[Sequence[Any]] = None) -> bool: ...

class BooleanField:
    """Type stub for BooleanField."""
    name: str
    label: str
    default: bool
    data: bool
    
    def __init__(self, label: str = "", validators: Any = None, default: bool = False, **kwargs: Any) -> None: ...
    def __call__(self, **kwargs: Any) -> Any: ...
    def validate(self, form: Any, extra_validators: Optional[Sequence[Any]] = None) -> bool: ...
