from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import tomllib
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from ..dns.names import is_reverse_dns_zone

CONFIG_DIR = Path("/config")
SECRETS_DIR = Path("/run/secrets")
USER_CONFIG_PATH = CONFIG_DIR / "config.toml"
PASSWORD_FILE_PATH = CONFIG_DIR / "password"
type UserConfigValidation = Literal["choice", "integer"]


@dataclass(frozen=True)
class UserConfigField:
    key: str
    validation: UserConfigValidation | None = None


USER_CONFIG_FIELDS = (
    UserConfigField("server"),
    UserConfigField("domain"),
    UserConfigField("zone"),
    UserConfigField("last_zone"),
    UserConfigField("user"),
    UserConfigField("auth", "choice"),
    UserConfigField("kerberos", "choice"),
    UserConfigField("krb5_ccache"),
    UserConfigField("configfile"),
    UserConfigField("options"),
    UserConfigField("ldap_base"),
    UserConfigField("ldap_encryption", "choice"),
    UserConfigField("auto_ptr", "choice"),
    UserConfigField("smart_days", "integer"),
    UserConfigField("smart_disabled_days", "integer"),
    UserConfigField("smart_never_logged_days", "integer"),
    UserConfigField("smart_max_rows", "integer"),
    UserConfigField("password_file"),
)
USER_CONFIG_KEYS = frozenset(field.key for field in USER_CONFIG_FIELDS)
VALIDATED_USER_CONFIG_KEYS = tuple(
    field.key for field in USER_CONFIG_FIELDS if field.validation is not None
)
CHOICE_VALUES = {
    "auth": frozenset({"password", "kerberos"}),
    "kerberos": frozenset({"off", "desired", "required"}),
    "ldap_encryption": frozenset({"ldaps", "starttls"}),
    "auto_ptr": frozenset({"ask", "on", "off"}),
}
INTEGER_RANGES = {
    "smart_days": (1, None),
    "smart_disabled_days": (1, None),
    "smart_never_logged_days": (1, None),
    "smart_max_rows": (1, 5000),
}
CHOICE_LABELS = {
    "auth": "password or kerberos",
    "kerberos": "off, desired, or required",
    "ldap_encryption": "ldaps or starttls",
    "auto_ptr": "ask, on, or off",
}
FIELD_LABELS = {
    "auth": "Auth",
    "kerberos": "Kerberos",
    "ldap_encryption": "LDAP encryption",
    "auto_ptr": "Auto PTR",
    "smart_days": "Smart days",
    "smart_disabled_days": "Smart disabled days",
    "smart_never_logged_days": "Smart never-logged days",
    "smart_max_rows": "Smart max rows",
}


class CompletedProcessRunner(Protocol):
    def __call__(
        self, cmd: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]: ...


def load_user_config(path: Path = USER_CONFIG_PATH) -> dict[str, str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError, OSError, tomllib.TOMLDecodeError:
        return {}

    return _safe_user_config_values(data)


def _preference_value(value: object) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return ""


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def save_user_config(
    values: Mapping[str, object], path: Path = USER_CONFIG_PATH
) -> dict[str, str]:
    safe_values = _safe_user_config_values(values)
    content = "".join(
        f"{key} = {_toml_string(safe_values[key])}\n" for key in sorted(safe_values)
    )
    write_private_text(path, content)
    return safe_values


def write_private_text(path: Path, content: str) -> None:
    parent_exists = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_exists:
        path.parent.chmod(0o700)

    file_descriptor, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", text=True
    )
    tmp_path = Path(tmp_name)
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as file:
            file_descriptor = -1
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        tmp_path.replace(path)
    except BaseException:
        with suppress(FileNotFoundError):
            tmp_path.unlink()
        raise
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _safe_user_config_values(values: Mapping[str, object]) -> dict[str, str]:
    safe_values: dict[str, str] = {}
    for key, value in values.items():
        normalized = _safe_user_config_value(key, value)
        if normalized:
            safe_values[key] = normalized
    return safe_values


def _safe_user_config_value(key: str, value: object) -> str:
    normalized = _preference_value(value)
    if key not in USER_CONFIG_KEYS or not normalized:
        return ""
    if key in CHOICE_VALUES:
        return _normalized_choice(key, normalized)
    if key in INTEGER_RANGES:
        return _normalized_integer(key, normalized)
    return normalized


def _normalized_choice(key: str, value: str) -> str:
    normalized = value.casefold()
    return normalized if normalized in CHOICE_VALUES[key] else ""


def _normalized_integer(key: str, value: str) -> str:
    return value if _integer_value_error(key, value) is None else ""


def user_config_value_error(key: str, value: object) -> str | None:
    normalized = _preference_value(value)
    if not normalized or key not in USER_CONFIG_KEYS:
        return None
    if key in CHOICE_VALUES:
        return None if _normalized_choice(key, normalized) else _choice_error(key)
    if key in INTEGER_RANGES:
        return _integer_value_error(key, normalized)
    return None


def _choice_error(key: str) -> str:
    return f"{FIELD_LABELS[key]} must be {CHOICE_LABELS[key]}."


def user_config_validation_error(values: Mapping[str, object]) -> str | None:
    for key in VALIDATED_USER_CONFIG_KEYS:
        error = user_config_value_error(key, values.get(key, ""))
        if error:
            return error
    return None


def _integer_value_error(key: str, value: str) -> str | None:
    minimum, maximum = INTEGER_RANGES[key]
    try:
        number = int(value)
    except ValueError:
        return f"{FIELD_LABELS[key]} must be a whole number."
    if number < minimum:
        return f"{FIELD_LABELS[key]} must be at least {minimum}."
    if maximum is not None and number > maximum:
        return f"{FIELD_LABELS[key]} must be at most {maximum}."
    return None


USER_CONFIG = load_user_config()


def has_valid_kerberos_ticket(
    runner: CompletedProcessRunner | None = None,
) -> bool:
    check_runner = runner or subprocess.run
    try:
        result = check_runner(
            ["klist", "-s"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except FileNotFoundError, OSError, subprocess.SubprocessError:
        return False
    return result.returncode == 0


def detected_default_auth(
    *,
    env: Mapping[str, str] = os.environ,
    user_config: Mapping[str, str] = USER_CONFIG,
    ticket_checker: Callable[[], bool] = has_valid_kerberos_ticket,
) -> str:
    explicit_auth = env.get("SAMBATUI_AUTH") or user_config.get("auth")
    if explicit_auth:
        return explicit_auth
    return "kerberos" if ticket_checker() else "password"


def password_file_permissions_too_open(path: Path) -> bool:
    try:
        info = _password_file_lstat(path)
    except FileNotFoundError, OSError:
        return False
    return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o077)


def fix_password_file_permissions(path: Path) -> None:
    info = _password_file_lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise OSError(f"Refusing to chmod symlink password file {path}")
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"Password file is not a regular file: {path}")

    file_descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened_info = os.fstat(file_descriptor)
        if not stat.S_ISREG(opened_info.st_mode):
            raise OSError(f"Password file is not a regular file: {path}")
        if opened_info.st_uid != os.getuid():
            raise OSError(f"Password file must be owned by the current user: {path}")
        os.fchmod(file_descriptor, 0o600)
    finally:
        os.close(file_descriptor)


def _is_read_only_secret(path: Path, file_descriptor: int | None = None) -> bool:
    if path.parent != SECRETS_DIR:
        return False
    info = os.statvfs(path) if file_descriptor is None else os.fstatvfs(file_descriptor)
    return bool(info.f_flag & os.ST_RDONLY)


def password_file_warning(path: Path) -> str | None:
    try:
        info = _password_file_lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"Cannot inspect password file {path}: {exc}"
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        return f"Password file must not be a symlink: {path}."
    if not stat.S_ISREG(mode):
        return f"Password file must be a regular file: {path}."
    try:
        if _is_read_only_secret(path):
            return None
    except OSError as exc:
        return f"Cannot inspect password file {path}: {exc}"
    if info.st_uid != os.getuid():
        return f"Password file must be owned by the current user: {path}."
    if mode & 0o077:
        return (
            f"Password file permissions too open: {path}. "
            f"Press p to fix and load, or run chmod 600 {path}."
        )
    return None


def _password_file_lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _open_private_password_file(path: Path) -> int:
    file_descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(file_descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"Password file must be a regular file: {path}")
        if _is_read_only_secret(path, file_descriptor):
            return file_descriptor
        if info.st_uid != os.getuid():
            raise OSError(f"Password file must be owned by the current user: {path}")
        if info.st_mode & 0o077:
            raise OSError(f"Password file permissions too open: {path}")
        return file_descriptor
    except BaseException:
        os.close(file_descriptor)
        raise


def read_password_file(path: Path = PASSWORD_FILE_PATH) -> str:
    if password_file_warning(path):
        return ""
    try:
        file_descriptor = _open_private_password_file(path)
        with os.fdopen(file_descriptor, "r", encoding="utf-8") as file:
            return file.readline().removesuffix("\n").removesuffix("\r")
    except FileNotFoundError, OSError:
        return ""


@dataclass(frozen=True)
class AppConfig:
    server: str
    domain: str
    zone: str
    user: str
    password: str = field(repr=False)
    auth: str
    kerberos: str
    krb5_ccache: str
    configfile: str
    options: str
    ldap_base: str
    ldap_encryption: str
    auto_ptr: str
    smart_days: str
    smart_disabled_days: str
    smart_never_logged_days: str
    smart_max_rows: str
    password_file: Path
    command_timeout: int

    @classmethod
    def load(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        preferences: Mapping[str, str] | None = None,
        ticket_checker: Callable[[], bool] = has_valid_kerberos_ticket,
    ) -> AppConfig:
        environment = os.environ if env is None else env
        saved = USER_CONFIG if preferences is None else preferences

        def value(envvar: str, key: str, fallback: str) -> str:
            return environment.get(envvar, saved.get(key, fallback))

        configured_domain = value("SAMBATUI_DOMAIN", "domain", "")
        legacy_zone = saved.get("zone", "")
        domain = configured_domain or (
            "" if is_reverse_dns_zone(legacy_zone) else legacy_zone
        )
        zone = environment.get("SAMBATUI_ZONE", saved.get("last_zone") or legacy_zone)
        password_file = Path(
            value(
                "SAMBATUI_PASSWORD_FILE",
                "password_file",
                str(PASSWORD_FILE_PATH),
            )
        ).expanduser()
        auth = detected_default_auth(
            env=environment, user_config=saved, ticket_checker=ticket_checker
        )
        password = (
            environment["SAMBATUI_PASSWORD"]
            if "SAMBATUI_PASSWORD" in environment
            else read_password_file(password_file)
        )
        try:
            command_timeout = int(environment.get("SAMBATUI_COMMAND_TIMEOUT", "60"))
        except ValueError:
            command_timeout = 60
        command_timeout = max(1, command_timeout)

        return cls(
            server=value("SAMBATUI_SERVER", "server", ""),
            domain=domain,
            zone=zone,
            user=value("SAMBATUI_USER", "user", ""),
            password=password,
            auth=auth,
            kerberos=value("SAMBATUI_KERBEROS", "kerberos", "off"),
            krb5_ccache=value(
                "SAMBATUI_KRB5_CCACHE", "krb5_ccache", environment.get("KRB5CCNAME", "")
            ),
            configfile=value("SAMBATUI_CONFIGFILE", "configfile", ""),
            options=value("SAMBATUI_OPTIONS", "options", ""),
            ldap_base=value("SAMBATUI_LDAP_BASE", "ldap_base", ""),
            ldap_encryption=value(
                "SAMBATUI_LDAP_ENCRYPTION", "ldap_encryption", "ldaps"
            ),
            auto_ptr=value("SAMBATUI_AUTO_PTR", "auto_ptr", "ask"),
            smart_days=value("SAMBATUI_SMART_DAYS", "smart_days", "90"),
            smart_disabled_days=value(
                "SAMBATUI_SMART_DISABLED_DAYS", "smart_disabled_days", "180"
            ),
            smart_never_logged_days=value(
                "SAMBATUI_SMART_NEVER_LOGGED_DAYS",
                "smart_never_logged_days",
                "30",
            ),
            smart_max_rows=value("SAMBATUI_SMART_MAX_ROWS", "smart_max_rows", "500"),
            password_file=password_file,
            command_timeout=command_timeout,
        )


APP_CONFIG = AppConfig.load()
DEFAULT_SERVER = APP_CONFIG.server
DEFAULT_DOMAIN = APP_CONFIG.domain
DEFAULT_ZONE = APP_CONFIG.zone
DEFAULT_USER = APP_CONFIG.user
DEFAULT_PASSWORD = APP_CONFIG.password
DEFAULT_AUTH = APP_CONFIG.auth
DEFAULT_KERBEROS = APP_CONFIG.kerberos
DEFAULT_KRB5_CCACHE = APP_CONFIG.krb5_ccache
DEFAULT_CONFIGFILE = APP_CONFIG.configfile
DEFAULT_OPTIONS = APP_CONFIG.options
DEFAULT_LDAP_BASE = APP_CONFIG.ldap_base
DEFAULT_LDAP_ENCRYPTION = APP_CONFIG.ldap_encryption
DEFAULT_AUTO_PTR = APP_CONFIG.auto_ptr
DEFAULT_SMART_DAYS = APP_CONFIG.smart_days
DEFAULT_SMART_DISABLED_DAYS = APP_CONFIG.smart_disabled_days
DEFAULT_SMART_NEVER_LOGGED_DAYS = APP_CONFIG.smart_never_logged_days
DEFAULT_SMART_MAX_ROWS = APP_CONFIG.smart_max_rows
DEFAULT_PASSWORD_FILE = APP_CONFIG.password_file
DEFAULT_COMMAND_TIMEOUT = APP_CONFIG.command_timeout
