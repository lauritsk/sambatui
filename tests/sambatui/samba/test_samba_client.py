from hypothesis import given
from hypothesis import strategies as st

from sambatui.samba.client import SambaToolClient, SambaToolConfig, parse_samba_options

TOKEN = st.text(
    alphabet=st.characters(
        blacklist_characters="%;\n\r", min_codepoint=33, max_codepoint=126
    ),
    min_size=1,
    max_size=20,
)


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


@given(st.lists(TOKEN, min_size=1, max_size=8))
def test_parse_samba_options_uses_semicolon_separated_values(
    options: list[str],
) -> None:
    value = (
        "; ".join(options[: len(options) // 2])
        + "\n"
        + ";".join(options[len(options) // 2 :])
    )

    assert parse_samba_options(value) == tuple(options)


@given(TOKEN, TOKEN)
def test_redact_command_masks_generated_password(user: str, password: str) -> None:
    command = ["samba-tool", "-U", f"{user}%{password}", f"--password={password}"]

    assert SambaToolClient.redact_command(command) == [
        "samba-tool",
        "-U",
        f"{user}%******",
        "--password=******",
    ]


@given(
    TOKEN,
    TOKEN,
    TOKEN,
    st.lists(TOKEN, max_size=4),
)
def test_dns_command_preserves_generated_command_parts(
    server: str, zone: str, action: str, args: list[str]
) -> None:
    client = SambaToolClient(
        SambaToolConfig(server=server, user="admin", password="secret")
    )

    command = client.dns_command(action, zone, args)

    assert command[:5] == ["samba-tool", "dns", action, server, zone]
    assert command[5 : 5 + len(args)] == args
    assert command[-3:] == ["-U", "admin%secret", "--use-kerberos=off"]
