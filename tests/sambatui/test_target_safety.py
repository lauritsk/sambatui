from __future__ import annotations

import asyncio

import pytest

from sambatui.app import SambatuiApp
from sambatui.core.models import DnsRow
from sambatui.ldap.rows import DirectoryRow
from sambatui.smart_views.ldap import ldap_disable_fix
from sambatui.smart_views.models import SmartViewRow


class LocalApp(SambatuiApp):
    def on_mount(self) -> None:
        self.initialize_view()

    def save_preferences(self) -> None:
        pass


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("server", "other.example.com"),
        ("user", "bob"),
        ("password", "different"),
        ("zone", "other.example.com"),
        ("ldap_base", "OU=Other,DC=example,DC=com"),
        ("ldap_encryption", "starttls"),
        ("auth", "kerberos"),
    ],
)
def test_target_changes_invalidate_rows_even_when_refresh_fails(
    field: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        app = LocalApp()
        app.set_connection_values(
            {
                "server": "old.example.com",
                "domain": "example.com",
                "zone": "example.com",
                "user": "alice",
                "password": "secret",
                "ldap_base": "DC=example,DC=com",
            }
        )

        async def failed_refresh() -> tuple[int, str]:
            return 1, "unreachable"

        def forbidden_client(*args: object, **kwargs: object) -> None:
            pytest.fail("old rows were allowed to start a write on the new target")

        monkeypatch.setattr(app, "run_zonelist", failed_refresh)
        monkeypatch.setattr(app, "ldap_client", forbidden_client)
        async with app.run_test():
            app.populate_directory(
                [
                    DirectoryRow(
                        "CN=Alice,DC=example,DC=com",
                        "user",
                        "Alice",
                        "",
                        {"uSNChanged": ("17",)},
                    )
                ]
            )
            app.views.directory.selected_rows = {0}
            app.views.dns.rows = [DnsRow("host", "1", "0", "A", "192.0.2.1", "60", "")]
            app.views.smart.rows = [
                SmartViewRow("low", "Alice", "old finding", "", "review", "ldap")
            ]
            app.views.dns.last_search_zone = "example.com"
            app.set_val(field, value)
            await app.load_zones()
            assert (
                app.views.directory.rows
                == app.views.dns.rows
                == app.views.smart.rows
                == []
            )
            assert app.views.directory.selected_rows == set()
            assert app.views.dns.last_search_zone == ""
            await app.delete_ldap_entry()

    asyncio.run(scenario())


def test_display_preferences_do_not_discard_loaded_rows() -> None:
    async def scenario() -> None:
        app = LocalApp()
        async with app.run_test():
            row = DirectoryRow("CN=Alice,DC=example,DC=com", "user", "Alice", "", {})
            app.populate_directory([row])
            app.set_val("smart_days", "120")
            assert app.views.directory.rows == [row]

    asyncio.run(scenario())


def test_missing_or_ambiguous_revisions_cannot_offer_a_guided_write() -> None:
    for attributes in (
        {"userAccountControl": ("512",)},
        {"userAccountControl": ("512",), "uSNChanged": ("1", "2")},
    ):
        row = DirectoryRow(
            "CN=Alice,DC=example,DC=com", "user", "Alice", "", attributes
        )
        assert row.revision == ""
        assert ldap_disable_fix(row) == {}
