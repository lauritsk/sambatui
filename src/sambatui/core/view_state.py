from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..ldap.rows import DirectoryRow
from ..smart_views.models import SmartViewRow
from .models import DnsRow


class ViewMode(StrEnum):
    DNS = "dns"
    DIRECTORY = "directory"
    SMART = "smart"


def next_sort_state(
    current_field: str, current_reverse: bool, requested_field: str
) -> tuple[str, bool]:
    return (
        requested_field,
        not current_reverse if current_field == requested_field else False,
    )


@dataclass
class TableState[Row]:
    rows: list[Row] = field(default_factory=list)
    selected_rows: set[int] = field(default_factory=set)
    selection_anchor: int | None = None
    sort_field: str = ""
    sort_reverse: bool = False

    def clear_selection(self) -> None:
        self.selected_rows.clear()
        self.selection_anchor = None

    def sort_by(self, field: str) -> None:
        self.sort_field, self.sort_reverse = next_sort_state(
            self.sort_field, self.sort_reverse, field
        )


@dataclass
class DnsViewState(TableState[DnsRow]):
    sort_field: str = "name"
    last_search_zone: str = ""


@dataclass(kw_only=True)
class DirectoryViewState(TableState[DirectoryRow]):
    max_rows: int
    values: dict[str, str] = field(default_factory=dict)


@dataclass(kw_only=True)
class SmartViewState(TableState[SmartViewRow]):
    max_rows: int
    view_id: str = ""
    values: dict[str, str] = field(default_factory=dict)

    def clear(self) -> None:
        self.rows = []
        self.values = {}
        self.view_id = ""
        self.sort_field = ""
        self.sort_reverse = False
        self.clear_selection()


type ResultTableState = (
    TableState[DnsRow] | TableState[DirectoryRow] | TableState[SmartViewRow]
)


@dataclass(kw_only=True)
class AppViewState:
    directory: DirectoryViewState
    smart: SmartViewState
    dns: DnsViewState = field(default_factory=DnsViewState)
    mode: ViewMode | str = ViewMode.DNS
    visual_selecting: bool = False

    def table(self, mode: ViewMode | str) -> ResultTableState | None:
        tables: dict[str, ResultTableState] = {
            ViewMode.DNS: self.dns,
            ViewMode.DIRECTORY: self.directory,
            ViewMode.SMART: self.smart,
        }
        return tables.get(mode)

    @property
    def current(self) -> ResultTableState:
        table = self.table(self.mode)
        return self.dns if table is None else table

    def reset_selection(self) -> None:
        for table in (self.dns, self.directory, self.smart):
            table.clear_selection()
        self.visual_selecting = False

    def activate(self, mode: ViewMode) -> None:
        """Switch result modes without leaking finding metadata or row selections."""
        self.mode = mode
        if mode is not ViewMode.SMART:
            self.smart.clear()
        self.reset_selection()
