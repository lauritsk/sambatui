from importlib.metadata import PackageNotFoundError, version

from .app import SambatuiApp, main
from .client import SambaToolClient, SambaToolConfig
from .discovery import DiscoveredService, discover_ad_services
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
    "DiscoveredService",
    "SambaToolClient",
    "SambaToolConfig",
    "SambatuiApp",
    "discover_ad_services",
    "main",
    "parse_records",
    "parse_zones",
    "ptr_target_for_name",
    "reverse_record_for_ipv4",
    "valid_dns_name",
    "validate_record",
]
