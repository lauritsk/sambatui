"""Smoke-test the installed production image without contacting AD."""

import asyncio
import importlib.util
import os
import shutil
import ssl
import subprocess
import sys

import gssapi

from sambatui.app import SambatuiApp
from sambatui.core.config import (
    APP_CONFIG,
    PASSWORD_FILE_PATH,
    USER_CONFIG_PATH,
    load_user_config,
    read_password_file,
    save_user_config,
    write_private_text,
)

assert os.getuid() == 1000
assert sys.version_info[:2] == (3, 15)
assert gssapi.raw.indicate_mechs()
assert importlib.util.find_spec("pytest") is None
assert shutil.which("gcc") is None
assert ssl.create_default_context().get_ca_certs()
assert APP_CONFIG.krb5_ccache == os.environ["KRB5CCNAME"] == "FILE:/config/krb5cc"
save_user_config({"server": "dc.example.com", "password": "not-a-preference"})
assert load_user_config() == {"server": "dc.example.com"}
assert USER_CONFIG_PATH.stat().st_mode & 0o777 == 0o600
write_private_text(PASSWORD_FILE_PATH, "test-only\n")
assert read_password_file() == "test-only"
assert PASSWORD_FILE_PATH.stat().st_mode & 0o777 == 0o600
for command in (["samba-tool", "dns", "--help"], ["klist", "-V"], ["dig", "-v"]):
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


async def check_tui() -> None:
    async with SambatuiApp().run_test() as pilot:
        await pilot.pause()
        assert pilot.app.query_one("#records")


asyncio.run(check_tui())
print("Production runtime OK: non-root, Python 3.15, Samba, Kerberos, DNS, TUI")
