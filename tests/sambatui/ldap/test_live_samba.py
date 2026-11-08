"""A disposable loopback-only AD. Mandatory in Docker, never uses supplied AD credentials."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from collections.abc import Generator
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import pytest
from ldap3.core.exceptions import LDAPSocketReceiveError

from sambatui.ldap import client as client_module
from sambatui.ldap.client import LdapDirectoryClient
from sambatui.ldap.connection import new_ldap_connection
from sambatui.ldap.controls import entry_assertion
from sambatui.ldap.errors import LdapOperationError
from sambatui.ldap.types import LdapAttributes, LdapSearchConfig
from sambatui.samba.client import SambaToolClient, SambaToolConfig
from sambatui.samba.execution import execute_command
from sambatui.smart_views.ldap import ldap_disable_fix

pytestmark = pytest.mark.samba
PASSWORD = "Disposable-test-only_42!"
BASE = "DC=lab,DC=invalid"


def run(
    *command: str, env: dict[str, str] | None = None, input: bytes | None = None
) -> None:
    result = subprocess.run(
        command, env=env, input=input, capture_output=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stdout.decode(
        errors="replace"
    ) + result.stderr.decode(errors="replace")


@pytest.fixture
def ad_root() -> Generator[Path]:
    # Unix-domain socket paths must stay below 108 bytes, including under xdist.
    with tempfile.TemporaryDirectory(prefix="tui-ad-") as directory:
        yield Path(directory)


@pytest.fixture
def ad(
    ad_root: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[tuple[LdapSearchConfig, SambaToolClient, subprocess.Popen[bytes], Path]]:
    if os.getenv("SAMBA_INTEGRATION_REQUIRED") != "1":
        pytest.skip("Disposable AD runs inside the Docker development/test image")
    assert shutil.which("samba"), "Docker tests require samba-ad-dc"
    domain = ad_root / "domain"
    # We exercise LDAP/DNS, not SMB/GPO filesystem ACLs. Samba's ACL provisioner
    # currently panics in this container; do not grant the container extra capabilities.
    run(
        "/usr/bin/python3",
        "-c",
        f"from samba.provision import provision; from samba.auth import system_session; import logging; provision(logging.getLogger('test-ad'), system_session(), targetdir={str(domain)!r}, realm='LAB.INVALID', domain='LAB', hostname='dc', hostip='127.0.0.1', users='app', serverrole='active directory domain controller', dns_backend='SAMBA_INTERNAL', adminpass={PASSWORD!r}, skip_sysvolacl=True)",
    )
    cert, key = ad_root / "cert.pem", ad_root / "key.pem"
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-subj",
        "/CN=dc.lab.invalid",
        "-addext",
        "subjectAltName=DNS:dc.lab.invalid,IP:127.0.0.1",
    )
    conf = domain / "etc/smb.conf"
    # These options are appended to [global], before the provisioned shares.
    content = conf.read_text()
    options = f"\n interfaces = 127.0.0.1\n bind interfaces only = yes\n tls enabled = yes\n tls keyfile = {key}\n tls certfile = {cert}\n tls cafile = {cert}\n dns forwarder =\n"
    conf.write_text(content.replace("[global]", "[global]" + options))
    # BuildKit mounts /etc/hosts read-only. Resolve only the fixture hostname
    # here; LDAP still verifies that hostname against the real TLS certificate.
    getaddrinfo = socket.getaddrinfo

    def loopback_address(host: str, *args, **kwargs):
        return getaddrinfo(
            "127.0.0.1" if host == "dc.lab.invalid" else host, *args, **kwargs
        )

    monkeypatch.setattr(socket, "getaddrinfo", loopback_address)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    krb5 = ad_root / "krb5.conf"
    krb5.write_text(
        "[libdefaults]\n default_realm = LAB.INVALID\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n dns_canonicalize_hostname = false\n[realms]\n LAB.INVALID = {\n kdc = 127.0.0.1\n }\n"
    )
    monkeypatch.setenv("KRB5_CONFIG", str(krb5))
    log_path = ad_root / "samba.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            ["samba", "-i", "--no-process-group", f"--configfile={conf}"],
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            for _ in range(300):
                if process.poll() is not None:
                    pytest.fail(log_path.read_text(errors="replace"))
                try:
                    with socket.create_connection(("127.0.0.1", 636), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                pytest.fail(
                    "AD did not start:\n" + log_path.read_text(errors="replace")
                )
            for name in ("Alice", "Bob"):
                run(
                    "samba-tool",
                    "user",
                    "create",
                    name,
                    PASSWORD,
                    f"--configfile={conf}",
                )
            config = LdapSearchConfig(
                "dc.lab.invalid",
                user="Administrator@lab.invalid",
                password=PASSWORD,
                base_dn=BASE,
                page_size=1,
                timeout=3,
            )
            samba = SambaToolClient(
                SambaToolConfig(
                    "127.0.0.1",
                    user="Administrator",
                    password=PASSWORD,
                    configfile=str(conf),
                )
            )
            yield config, samba, process, ad_root
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            # Some daemon children outlive their parent during graceful shutdown.
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)


def test_real_ad_authentication_paging_safe_writes_and_dns(
    ad: tuple[LdapSearchConfig, SambaToolClient, subprocess.Popen[bytes], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, samba, process, root = ad
    client = LdapDirectoryClient(config)
    client.check_connection()
    LdapDirectoryClient(replace(config, encryption="starttls")).check_connection()
    with monkeypatch.context() as context:
        context.setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
        with pytest.raises(LdapOperationError):
            client.check_connection()
    with pytest.raises(LdapOperationError):
        LdapDirectoryClient(replace(config, server="localhost")).check_connection()
    with pytest.raises(LdapOperationError):
        LdapDirectoryClient(
            replace(config, password="wrong-password")
        ).check_connection()
    assert len(client.search("users", max_entries=3)) == 3
    assert len(client.search("users")) >= 4
    assert client.child_containers()
    ou = client.add_entry("ou", BASE, "Lifecycle", {})
    dn = client.add_entry("group", ou, "TuiLifecycleGroup", {"description": "before"})
    row = client.search("groups", "TuiLifecycleGroup")[0]
    alice = client.search("users", "Alice")[0]
    fix = ldap_disable_fix(alice)
    flags = int(fix["fix_value"])
    assert not flags & 2
    # Samba 4.22 rejects RFC 4528. Prove that the real server is never allowed
    # to silently downgrade a conditional edit, delete, or guided disable.
    for write in (
        lambda: client.modify_attributes(
            dn, {"description": "unsafe"}, expected_revision=row.revision
        ),
        lambda: client.delete_entry(dn, expected_revision=row.revision),
        lambda: client.disable_account(
            alice.dn, flags, expected_revision=fix["fix_revision"]
        ),
    ):
        with pytest.raises(LdapOperationError, match="conditional LDAP writes"):
            write()
    assert client.search("groups", "TuiLifecycleGroup")[0].attributes[
        "description"
    ] == ("before",)
    assert (
        int(client.search("users", "Alice")[0].attributes["userAccountControl"][0])
        == flags
    )
    with monkeypatch.context() as context:
        context.setattr(
            client_module,
            "entry_assertion",
            lambda revision: ("1.2.3.4.5.6.7", True, entry_assertion(revision)[2]),
        )
        with pytest.raises(LdapOperationError):
            client.modify_attributes(
                dn, {"description": "unsafe fallback"}, expected_revision=row.revision
            )
    # Simulate losing the reply *after* an actual add committed. There must be
    # one attempt, and an error must not be interpreted as a rolled-back write.
    attempts: list[str] = []

    def lost_reply_factory(settings: LdapSearchConfig, *, read_only: bool = True):
        connection, server = new_ldap_connection(settings, read_only=read_only)
        add = connection.add

        def lost_reply(
            target: str, object_class: tuple[str, ...], attributes: LdapAttributes
        ) -> bool:
            attempts.append(target)
            assert add(target, object_class, attributes)
            raise LDAPSocketReceiveError("connection lost after server commit")

        monkeypatch.setattr(connection, "add", lost_reply)
        return connection, server

    with pytest.raises(LdapOperationError, match="connection lost"):
        LdapDirectoryClient(config, connection_factory=lost_reply_factory).add_entry(
            "group", ou, "LostReply", {}
        )
    assert attempts == [f"CN=LostReply,{ou}"]
    assert len(client.search("groups", "LostReply")) == 1
    bob = replace(config, user="Bob@lab.invalid")
    reader = LdapDirectoryClient(bob)
    assert reader.search("users", "Administrator")
    with pytest.raises(LdapOperationError, match="insufficientAccessRights"):
        reader.add_entry("group", ou, "Unauthorized", {})
    ccache = root / "ccache"
    run(
        "kinit",
        "Bob@LAB.INVALID",
        env={**os.environ, "KRB5CCNAME": f"FILE:{ccache}"},
        input=(PASSWORD + "\n").encode(),
    )
    kerberos = replace(
        bob, password="", auth_mode="kerberos", krb5_ccache=f"FILE:{ccache}"
    )
    with monkeypatch.context() as context:
        context.setenv("KRB5CCNAME", f"FILE:{ccache}")
        with pytest.raises(
            LdapOperationError, match="Cannot load Kerberos credentials"
        ):
            LdapDirectoryClient(
                replace(kerberos, krb5_ccache=f"FILE:{root / 'missing'}")
            ).check_connection()
        context.setenv("KRB5CCNAME", f"FILE:{root / 'missing-default'}")
        for user in ("Bob@lab.invalid", ""):
            LdapDirectoryClient(replace(kerberos, user=user)).check_connection()

    async def dns_lifecycle() -> None:
        for action, args in (
            ("add", ["lifecycle", "A", "192.0.2.10"]),
            ("query", ["lifecycle", "A"]),
            ("update", ["lifecycle", "A", "192.0.2.10", "192.0.2.11"]),
            ("delete", ["lifecycle", "A", "192.0.2.11"]),
            ("add", ["lifecycle", "TXT", "--help"]),
            ("query", ["lifecycle", "TXT"]),
            ("delete", ["lifecycle", "TXT", "--help"]),
        ):
            result = await execute_command(
                samba.dns_command(action, "lab.invalid", args),
                env=samba.execution_env(),
                timeout=20,
            )
            assert result.code == 0, result.output
            if action == "query":
                assert ("192.0.2.10" if args[1] == "A" else "--help") in result.output
                assert "ttl=" in result.output.lower()

    asyncio.run(dns_lifecycle())
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=10)
    with pytest.raises(LdapOperationError):
        client.check_connection()
