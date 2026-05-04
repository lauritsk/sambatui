import asyncio


from sambatui.app import (
    SambatuiApp,
)
from textual.widgets import DataTable, Input

from sambatui.ui.screens import (
    ConfirmScreen,
    FormScreen,
    SmartViewPickerScreen,
)


def test_modal_key_shortcuts_open_without_key_handler_crash() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            for key, screen_type in [
                ("ctrl+o", FormScreen),
                ("w", FormScreen),
                ("c", FormScreen),
                ("L", FormScreen),
                ("S", SmartViewPickerScreen),
                ("1", FormScreen),
                ("q", FormScreen),
                ("a", FormScreen),
            ]:
                await pilot.press(key)
                for _ in range(10):
                    await pilot.pause()
                    if isinstance(app.screen, screen_type):
                        break
                assert isinstance(app.screen, screen_type), key
                await pilot.press("escape")
                for _ in range(10):
                    await pilot.pause()
                    if not isinstance(app.screen, screen_type):
                        break

            app.query_one("#password", Input).value = "secret"
            await pilot.press("P")
            for _ in range(10):
                await pilot.pause()
                if isinstance(app.screen, ConfirmScreen):
                    break
            assert isinstance(app.screen, ConfirmScreen)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(run_app())


def test_modal_tab_stays_inside_foreground_popup() -> None:
    async def run_app() -> None:
        app = SambatuiApp()
        async with app.run_test() as pilot:
            app.query_one("#records", DataTable).focus()
            await pilot.press("w")
            for _ in range(10):
                await pilot.pause()
                if isinstance(app.screen, FormScreen):
                    break

            assert isinstance(app.screen, FormScreen)
            focused = app.screen.focused
            assert focused is not None
            assert str(focused.id) == "domain"

            await pilot.press("tab")
            await pilot.pause()

            focused = app.screen.focused
            assert focused is not None
            assert str(focused.id) == "user"
            assert not app.query_one("#zones", DataTable).has_focus

    asyncio.run(run_app())
