"""Disposable Samba fixture only. The installed client never imports this module."""

import logging
import os
from pathlib import Path
import signal
import subprocess
import time
from dataclasses import dataclass


STATE = Path("/tmp/native-ad")
PASSWORD = "Disposable-test-only_42!"
COMMAND_TIMEOUT_SECONDS = 60
SERVER_LIFETIME_SECONDS_MAX = 900
CONFIG_BYTES_MAX = 64 << 10


def main() -> None:
    validate_fixture(os.environ, Path("/.dockerenv"), STATE)
    os.umask(0o077)
    shutdown = Shutdown()

    def request_shutdown(_number, _frame) -> None:
        # Signals request shutdown; the owning loop performs process cleanup.
        shutdown.requested = True

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    STATE.mkdir(mode=0o700)
    (STATE / "disposable.marker").write_text("sambatui isolated disposable lab\n")
    provision_domain()
    configure_samba(STATE / "domain/etc/smb.conf")
    prepare_authentication()
    for user, password in (("Reader", PASSWORD), ("Whitespace", "  " + PASSWORD + "  ")):
        run_command([
            "samba-tool", "user", "create", user, password,
            "--configfile=" + str(STATE / "domain/etc/smb.conf"),
        ])
    if shutdown.requested:
        raise RuntimeError("fixture shutdown requested before Samba startup")
    server = subprocess.Popen([
        "samba", "--interactive", "--no-process-group",
        "--configfile=" + str(STATE / "domain/etc/smb.conf"),
    ], start_new_session=True)
    deadline = time.monotonic() + SERVER_LIFETIME_SECONDS_MAX
    try:
        wait_for_kerberos(server, shutdown)
        environment = dict(os.environ, PASSWD=PASSWORD)
        run_command([
            "samba-tool", "dns", "zonecreate", "127.0.0.1", "2.0.192.in-addr.arpa",
            "--username=LAB\\Administrator",
        ], environment=environment)
        (STATE / "ready.tmp").write_text("ready\n")
        (STATE / "ready.tmp").replace(STATE / "ready")
        wait_for_shutdown(server, shutdown, deadline)
    finally:
        stop_process(server)


@dataclass
class Shutdown:
    requested: bool = False


def validate_fixture(environment, container_marker: Path, state: Path) -> None:
    if environment.get("SAMBATUI_SERVER_FIXTURE") != "DISPOSABLE":
        raise RuntimeError("fixture only; use go run ./cmd/dev integration")
    if not container_marker.is_file():
        raise RuntimeError("refusing host provisioning")
    if state.exists():
        raise RuntimeError("refusing to overwrite existing fixture state")


def provision_domain() -> None:
    # Samba exposes provisioning only through its server-side Python API.
    from samba.auth import system_session
    from samba.provision import provision

    provision(
        logging.getLogger("native-test"), system_session(),
        targetdir=str(STATE / "domain"), realm="LAB.INVALID", domain="LAB",
        hostname="dc", hostip="127.0.0.1", users="app",
        serverrole="active directory domain controller", dns_backend="SAMBA_INTERNAL",
        adminpass=PASSWORD, skip_sysvolacl=True,
    )


def configure_samba(path: Path) -> None:
    with path.open("rb") as source:
        data = source.read(CONFIG_BYTES_MAX + 1)
    if len(data) > CONFIG_BYTES_MAX:
        raise RuntimeError("generated Samba configuration exceeds safety limit")
    configuration = data.decode("utf-8")
    if configuration.count("[global]") != 1:
        raise RuntimeError("generated Samba configuration must have one global section")
    settings = """[global]
 interfaces = 127.0.0.1
 bind interfaces only = yes
 tls enabled = yes
 tls keyfile = /tmp/native-ad/key.pem
 tls certfile = /tmp/native-ad/cert.pem
 tls cafile = /tmp/native-ad/cert.pem
 dns forwarder =
"""
    path.write_text(configuration.replace("[global]", settings), encoding="utf-8")


def prepare_authentication() -> None:
    run_command([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
        "-keyout", str(STATE / "key.pem"), "-out", str(STATE / "cert.pem"),
        "-subj", "/CN=dc.lab.invalid", "-addext",
        "subjectAltName=DNS:dc.lab.invalid,IP:127.0.0.1",
    ])
    with Path("/etc/hosts").open("a", encoding="ascii") as hosts:
        hosts.write("127.0.0.1 dc.lab.invalid\n")
    (STATE / "krb5.conf").write_text("""[libdefaults]
 default_realm = LAB.INVALID
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
[realms]
 LAB.INVALID = {
 kdc = 127.0.0.1
 }
""", encoding="ascii")


def wait_for_kerberos(server, shutdown: Shutdown) -> None:
    environment = dict(
        os.environ, KRB5_CONFIG=str(STATE / "krb5.conf"),
        KRB5CCNAME="FILE:" + str(STATE / "reader.ccache"),
    )
    for _attempt in range(30):
        if shutdown.requested or server.poll() is not None:
            raise RuntimeError("Samba stopped before Kerberos readiness")
        try:
            run_command(
                ["kinit", "Reader@LAB.INVALID"], input_data=(PASSWORD + "\n").encode(),
                environment=environment, timeout_seconds=2,
            )
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Ticket acquisition is idempotent; retry only inside this startup budget.
            time.sleep(1)
    raise RuntimeError("Kerberos readiness exceeded 30 attempts")


def wait_for_shutdown(server, shutdown: Shutdown, deadline: float) -> None:
    # An intentionally long-running fixture still has a finite lifetime and owner.
    for _tick in range(SERVER_LIFETIME_SECONDS_MAX):
        if shutdown.requested:
            return
        if server.poll() is not None:
            raise RuntimeError("Samba exited unexpectedly")
        if time.monotonic() >= deadline:
            raise RuntimeError("disposable server exceeded lifetime safety limit")
        time.sleep(1)
    raise RuntimeError("disposable server exceeded wait iteration limit")


def run_command(
    arguments, *, input_data=None, environment=None, timeout_seconds=COMMAND_TIMEOUT_SECONDS,
) -> None:
    assert 0 < len(arguments) <= 32, "fixture command argument bound"
    assert 0 < timeout_seconds <= COMMAND_TIMEOUT_SECONDS, "fixture command time bound"
    if input_data is not None:
        assert len(input_data) <= 1024, "fixture command input bound"
    process = subprocess.Popen(
        arguments, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        env=environment, start_new_session=True,
    )
    try:
        process.communicate(input=input_data, timeout=timeout_seconds)
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, arguments)
    finally:
        # Reap the entire owned group even if a tool exits before its descendants.
        stop_process(process)


def stop_process(process) -> None:
    assert process.pid > 0, "fixture process must have started"
    assert process.pid != os.getpid(), "fixture must not signal its own process group"
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # Already-exited groups are an expected cleanup state.
    try:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The leader may exit between the timeout and KILL.
            process.wait(timeout=5)
    finally:
        try:
            # The leader may have exited while descendants ignored TERM.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # Already-exited groups are an expected cleanup state.
        if process.stdin is not None:
            process.stdin.close()


if __name__ == "__main__":
    main()
