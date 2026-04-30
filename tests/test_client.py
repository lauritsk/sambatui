from pathlib import Path

from sambatui.client import SambaToolClient, SambaToolConfig, parse_samba_options
from sambatui.config import password_file_warning, read_password_file


def test_password_auth_builds_existing_samba_tool_command() -> None:
    client = SambaToolClient(
        SambaToolConfig(
            server="dc01.example.com",
            user="EXAMPLE\\administrator",
            password="secret",
            auth_mode="password",
            kerberos="off",
        )
    )

    assert client.authentication_error() is None
    assert client.dns_command("query", "example.com", ["@", "ALL"]) == [
        "samba-tool",
        "dns",
        "query",
        "dc01.example.com",
        "example.com",
        "@",
        "ALL",
        "-U",
        "EXAMPLE\\administrator%secret",
        "--use-kerberos=off",
    ]


def test_kerberos_auth_does_not_require_or_embed_password() -> None:
    client = SambaToolClient(
        SambaToolConfig(
            server="dc01.example.com",
            user="EXAMPLE\\administrator",
            auth_mode="kerberos",
            kerberos="off",
            krb5_ccache="/tmp/krb5cc_test",
        )
    )

    assert client.authentication_error() is None
    assert client.zonelist_command() == [
        "samba-tool",
        "dns",
        "zonelist",
        "dc01.example.com",
        "-U",
        "EXAMPLE\\administrator",
        "--use-kerberos=required",
        "--use-krb5-ccache=/tmp/krb5cc_test",
    ]


def test_configfile_options_and_redaction() -> None:
    client = SambaToolClient(
        SambaToolConfig(
            server="dc01.example.com",
            user="admin",
            password="secret",
            configfile="/etc/samba/smb.conf",
            options=("client min protocol=SMB3", "log level=1"),
        )
    )
    command = client.dns_command("add", "example.com", ["www", "A", "192.0.2.10"])

    assert "--configfile=/etc/samba/smb.conf" in command
    assert "--option=client min protocol=SMB3" in command
    assert "--option=log level=1" in command
    assert "admin%secret" in command
    assert "admin%secret" not in " ".join(client.redact_command(command))
    assert "admin%******" in " ".join(client.redact_command(command))


def test_authentication_error_prefers_kerberos_for_passwordless_use() -> None:
    assert SambaToolClient(
        SambaToolConfig(server="dc01.example.com")
    ).authentication_error() == ("Enter username or switch auth to kerberos.")
    assert (
        SambaToolClient(
            SambaToolConfig(server="dc01.example.com", user="admin")
        ).authentication_error()
        == "Enter password, load password file, or switch auth to kerberos."
    )


def test_parse_samba_options_uses_semicolon_separated_values() -> None:
    assert parse_samba_options("client min protocol=SMB3; log level=1\nfoo=bar") == (
        "client min protocol=SMB3",
        "log level=1",
        "foo=bar",
    )


def test_password_file_warning_rejects_group_or_other_permissions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "password"
    path.write_text("secret\n", encoding="utf-8")
    path.chmod(0o644)

    assert password_file_warning(path) is not None
    assert read_password_file(path) == ""

    path.chmod(0o600)

    assert password_file_warning(path) is None
    assert read_password_file(path) == "secret"
