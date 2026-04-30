from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

AuthMode = Literal["password", "kerberos"]
KERBEROS_MODES = frozenset({"off", "desired", "required"})
AUTH_MODES = frozenset({"password", "kerberos"})


@dataclass(frozen=True)
class SambaToolConfig:
    server: str
    user: str = ""
    password: str = ""
    auth_mode: str = "password"
    kerberos: str = "off"
    krb5_ccache: str = ""
    configfile: str = ""
    options: tuple[str, ...] = ()

    @property
    def normalized_auth_mode(self) -> str:
        return (self.auth_mode or "password").casefold()

    @property
    def normalized_kerberos(self) -> str:
        kerberos = (self.kerberos or "off").casefold()
        if self.normalized_auth_mode == "kerberos" and kerberos == "off":
            return "required"
        return kerberos


class SambaToolClient:
    def __init__(self, config: SambaToolConfig) -> None:
        self.config = config

    def authentication_error(self) -> str | None:
        auth_mode = self.config.normalized_auth_mode
        if auth_mode not in AUTH_MODES:
            return "Auth must be password or kerberos."
        if self.config.normalized_kerberos not in KERBEROS_MODES:
            return "Kerberos must be off, desired, or required."
        if auth_mode == "password":
            if not self.config.user:
                return "Enter username or switch auth to kerberos."
            if not self.config.password:
                return "Enter password, load password file, or switch auth to kerberos."
        return None

    def dns_command(self, action: str, zone: str, args: Sequence[str]) -> list[str]:
        return [
            "samba-tool",
            "dns",
            action,
            self.config.server,
            zone,
            *args,
        ] + self._global_args()

    def dns_zone_command(
        self, action: str, zone: str, args: Sequence[str]
    ) -> list[str]:
        return self.dns_command(action, zone, args)

    def zonelist_command(self) -> list[str]:
        return [
            "samba-tool",
            "dns",
            "zonelist",
            self.config.server,
        ] + self._global_args()

    def _global_args(self) -> list[str]:
        args: list[str] = []
        if self.config.configfile:
            args.append(f"--configfile={self.config.configfile}")
        for option in self.config.options:
            args.append(f"--option={option}")
        args.extend(self._auth_args())
        return args

    def _auth_args(self) -> list[str]:
        args: list[str] = []
        auth_mode = self.config.normalized_auth_mode
        if auth_mode == "password":
            args.extend(["-U", f"{self.config.user}%{self.config.password}"])
        elif self.config.user:
            args.extend(["-U", self.config.user])

        args.append(f"--use-kerberos={self.config.normalized_kerberos}")
        if self.config.krb5_ccache:
            args.append(f"--use-krb5-ccache={self.config.krb5_ccache}")
        return args

    @staticmethod
    def redact_command(command: Iterable[str]) -> list[str]:
        redacted: list[str] = []
        redact_next_user = False
        for arg in command:
            if redact_next_user:
                redacted.append(_redact_user_arg(arg))
                redact_next_user = False
                continue
            redacted.append(_redact_arg(arg))
            if arg == "-U":
                redact_next_user = True
        return redacted

    @staticmethod
    def status_command(command: Iterable[str], *, max_len: int = 140) -> str:
        text = " ".join(SambaToolClient.redact_command(command))
        return text if len(text) <= max_len else f"{text[: max_len - 1]}…"


def _redact_arg(arg: str) -> str:
    if arg.startswith("--password="):
        return "--password=******"
    return arg


def _redact_user_arg(arg: str) -> str:
    user, sep, password = arg.partition("%")
    if not sep or not password:
        return arg
    return f"{user}%******" if user else "******"


def parse_samba_options(value: str) -> tuple[str, ...]:
    options: list[str] = []
    for line in value.splitlines():
        options.extend(part.strip() for part in line.split(";"))
    return tuple(option for option in options if option)
