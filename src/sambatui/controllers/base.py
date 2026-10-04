from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.view_state import AppViewState

if TYPE_CHECKING:

    class AppControllerBase:
        """Type-checking base for controller mixins composed into SambatuiApp."""

        views: AppViewState

        def __getattr__(self, name: str) -> Any: ...

else:

    class AppControllerBase:
        """Runtime marker base for controller mixins."""

        views: AppViewState
