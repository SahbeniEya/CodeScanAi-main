# pyright: reportGeneralTypeIssues=false

from typing import Any, Optional, Union, List, Dict, Callable, Type, TypeVar, Generic, Sequence, Mapping, Protocol, cast, overload

T = TypeVar('T')

# Define a protocol for form fields to satisfy type checking
class FormField(Protocol):
    name: str
    label: str
    default: Any
    data: Any

    def __call__(self, **kwargs: Any) -> Any: ...
    def validate(self, form: Any, extra_validators: Optional[Sequence[Any]] = None) -> bool: ...

# Make Field implement the FormField protocol
class Field(Generic[T]):
    name: str
    label: str
    default: Optional[T]
    description: str
    filters: List[Callable]
    flags: Any
    validators: List[Any]
    data: T

    def __init__(self, label: str = "", validators: Any = None, filters: Any = None,
                 description: str = "", id: Optional[str] = None, default: Optional[T] = None,
                 widget: Any = None, render_kw: Optional[Dict[str, Any]] = None,
                 _form: Optional[Any] = None, _name: Optional[str] = None,
                 _prefix: str = "", _translations: Optional[Any] = None,
                 _meta: Optional[Any] = None) -> None: ...

    def __call__(self, **kwargs: Any) -> Any: ...

    def process(self, formdata: Optional[Any] = None, data: Optional[Any] = None,
                extra_filters: Optional[List[Callable]] = None) -> None: ...

    def process_data(self, value: Any) -> None: ...

    def process_formdata(self, valuelist: List[str]) -> None: ...

    def validate(self, form: Any, extra_validators: Optional[Sequence[Any]] = None) -> bool: ...

# Define field types with proper type annotations
class BooleanField(Field[bool]):
    data: bool
    def __init__(self, label: str = "", validators: Any = None, default: bool = False, **kwargs: Any) -> None: ...

class StringField(Field[str]):
    data: str
    def __init__(self, label: str = "", validators: Any = None, default: str = "", **kwargs: Any) -> None: ...

class SelectField(Field[str]):
    data: str
    choices: List[Any]
    def __init__(self, label: str = "", validators: Any = None, choices: Any = None, default: str = "", **kwargs: Any) -> None: ...

class SubmitField(Field[bool]):
    data: bool
    def __init__(self, label: str = "", validators: Any = None, **kwargs: Any) -> None: ...

# Define form class
class Form:
    def __init__(self, formdata: Any = None, obj: Any = None, prefix: str = '', data: Any = None, meta: Any = None, **kwargs: Any) -> None: ...
    def validate(self) -> bool: ...
    def validate_on_submit(self) -> bool: ...

class FlaskForm(Form):
    def __init__(self, formdata: Any = None, obj: Any = None, prefix: str = '', data: Any = None, meta: Any = None, **kwargs: Any) -> None: ...
    def validate_on_submit(self) -> bool: ...
