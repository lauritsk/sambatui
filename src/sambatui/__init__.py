from importlib.metadata import PackageNotFoundError, version

from .app import DnsRow, SambatuiApp, main, parse_records, parse_zones, validate_record

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
    "validate_record",
]
