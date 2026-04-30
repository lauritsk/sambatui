from importlib.metadata import PackageNotFoundError, version

from .app import SambatuiApp, main
from .dns import (
    parse_records,
    parse_zones,
    ptr_target_for_name,
    reverse_record_for_ipv4,
    valid_dns_name,
    validate_record,
)
from .models import DnsRow

try:
    __version__ = version("sambatui")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "__version__",
    "DnsRow",
    "SambatuiApp",
    "main",
    "parse_records",
    "parse_zones",
    "ptr_target_for_name",
    "reverse_record_for_ipv4",
    "valid_dns_name",
    "validate_record",
]
