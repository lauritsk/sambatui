from __future__ import annotations

import os
from typing import ClassVar

from textual.app import App
from textual.binding import BindingType

from .app_actions import APP_BINDINGS
from .app_layout import AppLayoutMixin
from .app_navigation import AppNavigationMixin
from .controllers import (
    AppCoreMixin,
    AppDnsActionsMixin,
    AppLdapActionsMixin,
    AppSetupMixin,
    AppSmartActionsMixin,
    AppViewsMixin,
)
from .ui.styles import APP_CSS


class SambatuiApp(
    AppCoreMixin,
    AppSetupMixin,
    AppViewsMixin,
    AppLdapActionsMixin,
    AppSmartActionsMixin,
    AppDnsActionsMixin,
    AppLayoutMixin,
    AppNavigationMixin,
    App,
):
    CSS = APP_CSS
    BINDINGS: ClassVar[list[BindingType]] = list(APP_BINDINGS)

    def __init__(self) -> None:
        super().__init__()
        self.initialize_state()
        requested_theme = os.getenv("SAMBATUI_THEME") or os.getenv("TEXTUAL_THEME")
        self.theme = (
            requested_theme if requested_theme in self.available_themes else "ansi-dark"
        )


def main() -> None:
    SambatuiApp().run()


if __name__ == "__main__":
    main()
