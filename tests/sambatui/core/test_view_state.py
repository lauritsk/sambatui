from __future__ import annotations

import pytest

from sambatui.core.view_state import (
    AppViewState,
    DirectoryViewState,
    SmartViewState,
    TableState,
    ViewMode,
)
from sambatui.smart_views.models import SmartViewRow


def make_state() -> AppViewState:
    return AppViewState(
        directory=DirectoryViewState(max_rows=200),
        smart=SmartViewState(max_rows=500),
    )


def test_table_state_defaults_are_independent_and_sort_toggles() -> None:
    first = TableState[str]()
    second = TableState[str]()
    first.rows.append("first")
    first.selected_rows.add(0)
    first.selection_anchor = 0
    assert second.rows == []
    assert second.selected_rows == set()
    assert second.selection_anchor is None

    first.sort_by("name")
    assert (first.sort_field, first.sort_reverse) == ("name", False)
    first.sort_by("name")
    assert (first.sort_field, first.sort_reverse) == ("name", True)
    first.sort_by("name")
    assert (first.sort_field, first.sort_reverse) == ("name", False)
    first.sort_by("value")
    assert (first.sort_field, first.sort_reverse) == ("value", False)
    first.clear_selection()
    assert not first.selected_rows
    assert first.selection_anchor is None
    assert first.rows == ["first"]


@pytest.mark.parametrize("mode", list(ViewMode))
def test_view_transitions_reset_all_selections(mode: ViewMode) -> None:
    state = make_state()
    for table in (state.dns, state.directory, state.smart):
        table.selected_rows.add(1)
        table.selection_anchor = 1
    state.visual_selecting = True
    state.smart.view_id = "ldap_inactive_users"
    state.smart.values = {"days": "90"}
    state.smart.sort_field = "age"
    state.smart.sort_reverse = True

    state.activate(mode)

    assert state.mode is mode
    assert state.current is state.table(mode)
    assert not state.visual_selecting
    for table in (state.dns, state.directory, state.smart):
        assert not table.selected_rows
        assert table.selection_anchor is None
    if mode is ViewMode.SMART:
        assert state.smart.view_id == "ldap_inactive_users"
        assert state.smart.values == {"days": "90"}
        assert state.smart.sort_field == "age"
    else:
        assert state.smart.view_id == ""
        assert state.smart.values == {}
        assert state.smart.sort_field == ""
        assert not state.smart.sort_reverse
    assert state.directory.max_rows == 200
    assert state.smart.max_rows == 500
    assert state.dns.sort_field == "name"


def test_unknown_mode_has_no_table_and_safe_selection_fallback() -> None:
    state = make_state()
    state.mode = "unknown"
    assert state.table(state.mode) is None
    assert state.current is state.dns


def test_clearing_smart_state_does_not_modify_input_results() -> None:
    state = make_state()
    rows = [SmartViewRow("info", "object", "finding", "evidence", "review", "dns")]
    values = {"max_rows": "500"}
    state.smart.rows = rows
    state.smart.values = values

    state.activate(ViewMode.DNS)

    assert len(rows) == 1
    assert values == {"max_rows": "500"}
    assert state.smart.rows == []
    assert state.smart.values == {}
