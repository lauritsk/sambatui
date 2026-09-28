from __future__ import annotations

from dataclasses import dataclass

from .smart_view_catalog import SMART_VIEWS

type CommandPaletteChoice = tuple[str, str, str, str]


@dataclass(frozen=True)
class ActionDefinition:
    action_id: str
    method: str
    binding: str = ""
    character: str = ""
    binding_label: str = ""
    palette_label: str = ""
    description: str = ""
    args: tuple[str, ...] = ()

    @property
    def textual_action(self) -> str:
        return self.method.removeprefix("action_")

    @property
    def shortcut(self) -> str:
        if self.character and self.character != " ":
            return self.character
        labels = {
            "question_mark": "?",
            "slash": "/",
            "space": "Space",
            "escape": "Esc",
        }
        return labels.get(self.binding, self.binding.replace("+", "+").title())


ACTIONS: tuple[ActionDefinition, ...] = (
    ActionDefinition(
        "help",
        "action_help",
        "question_mark",
        "?",
        "Help",
        "Show help",
        "Open the keyboard shortcut and workflow help.",
    ),
    ActionDefinition(
        "open_command_palette",
        "action_open_command_palette",
        "ctrl+p",
        binding_label="Command palette",
    ),
    ActionDefinition(
        "connection",
        "action_connection",
        "ctrl+o",
        binding_label="Connection",
        palette_label="Open connection settings",
        description="Edit server, zone, auth, LDAP, and finding defaults.",
    ),
    ActionDefinition(
        "setup_wizard",
        "action_setup_wizard",
        "w",
        "w",
        "Setup wizard",
        "Run first-run setup wizard",
        "Enter AD domain and credentials, discover a DC, check DNS/LDAP, and load zones.",
    ),
    ActionDefinition(
        "load_password",
        "action_load_password_file",
        "p",
        "p",
        "Load password",
        "Load password file",
        "Load the configured password file after checking permissions.",
    ),
    ActionDefinition(
        "save_password",
        "action_save_password_file",
        "P",
        "P",
        "Save password",
        "Save password file",
        "Write the current password field to disk with chmod 600.",
    ),
    ActionDefinition(
        "load_zones",
        "action_load_zones",
        "z",
        "z",
        "Zones",
        "Load DNS zones",
        "List DNS zones from samba-tool.",
    ),
    ActionDefinition(
        "discover_ad",
        "action_discover_ad",
        "c",
        "c",
        "Discover DC",
        "Discover AD domain controller",
        "Find domain controllers from DNS SRV records and fill connection fields.",
    ),
    ActionDefinition(
        "ldap_search",
        "action_ldap_search",
        "L",
        "L",
        "LDAP",
        "Search LDAP directory",
        "Search AD users, groups, computers, OUs, or all entries.",
    ),
    ActionDefinition(
        "smart_view_picker",
        "action_smart_view",
        "S",
        "S",
        "Findings picker",
        "Pick finding filter",
        "Choose a DNS or LDAP finding filter from a list.",
    ),
    ActionDefinition(
        "refresh",
        "action_refresh",
        "r",
        "r",
        "Refresh",
        "Refresh current view",
        "Reload the current DNS zone or rerun the active finding view.",
    ),
    ActionDefinition(
        "query_record",
        "action_query",
        "q",
        "q",
        "Query",
        "Query DNS records",
        "Query one DNS name and type.",
    ),
    ActionDefinition(
        "add_record",
        "action_add",
        "a",
        "a",
        "Add",
        "Add DNS record or LDAP entry",
        "Create a DNS record or LDAP entry in the active view.",
    ),
    ActionDefinition(
        "update_record",
        "action_update",
        "u",
        "u",
        "Update selected",
        "Update selected DNS record or LDAP entry attributes",
        "Edit one selected DNS record value or one LDAP entry's allowlisted attributes.",
    ),
    ActionDefinition(
        "delete_records",
        "action_delete",
        "d",
        "d",
        "Delete selected",
        "Delete selected DNS records or LDAP entries",
        "Delete selected DNS records or LDAP entries after confirmation.",
    ),
    ActionDefinition("toggle_select", "action_toggle_select", "space", " ", "Toggle select"),
    ActionDefinition("toggle_select_ctrl", "action_toggle_select", "ctrl+space", binding_label="Toggle select"),
    ActionDefinition("visual_select", "action_visual_select", "v", "v", "Visual select"),
    ActionDefinition("select_range", "action_select_range", "V", "V", "Select range"),
    ActionDefinition("clear", "action_clear_navigation_state", "escape", binding_label="Clear"),
    ActionDefinition("extend_up", "action_extend_up", "shift+up", binding_label="Extend up"),
    ActionDefinition("extend_down", "action_extend_down", "shift+down", binding_label="Extend down"),
    ActionDefinition("next_table", "action_next_table", "tab", binding_label="Next table"),
    ActionDefinition("previous_table", "action_previous_table", "shift+tab", binding_label="Previous table"),
    ActionDefinition("next_side_tab", "action_next_side_tab", "]", "]", "Next DNS/LDAP tab"),
    ActionDefinition("previous_side_tab", "action_previous_side_tab", "[", "[", "Previous DNS/LDAP tab"),
    ActionDefinition("focus_zones", "action_focus_zones", "h", "h", "Focus zones"),
    ActionDefinition("focus_records", "action_focus_records", "l", "l", "Focus records"),
    ActionDefinition("cursor_down", "action_cursor_down", "j", "j", "Down"),
    ActionDefinition("cursor_up", "action_cursor_up", "k", "k", "Up"),
    ActionDefinition("half_page_down", "action_cursor_half_page_down", "ctrl+d", binding_label="Half page down"),
    ActionDefinition("half_page_up", "action_cursor_half_page_up", "ctrl+u", binding_label="Half page up"),
    ActionDefinition("page_down", "action_cursor_page_down", "pagedown", binding_label="Page down"),
    ActionDefinition("page_up", "action_cursor_page_up", "pageup", binding_label="Page up"),
    ActionDefinition("cursor_top", "action_cursor_top", "home", binding_label="Top"),
    ActionDefinition("cursor_bottom", "action_cursor_bottom", "end", binding_label="Bottom"),
    ActionDefinition("cursor_bottom_g", "action_cursor_bottom", "G", binding_label="Bottom"),
    ActionDefinition("activate", "action_activate_row", "enter", binding_label="Activate"),
    ActionDefinition(
        "fix_smart",
        "action_fix_smart",
        "f",
        "f",
        "Fix smart finding",
        "Fix selected finding",
        "Apply the available guided fix for the selected finding.",
    ),
    ActionDefinition(
        "ldap_load_more",
        "action_load_more_directory",
        "m",
        "m",
        "Load more LDAP",
        "Load more LDAP entries",
        "Rerun the last LDAP search with 200 more rows.",
    ),
    ActionDefinition(
        "filter_results",
        "action_search",
        "slash",
        "/",
        "Search",
        "Search/filter results",
        "Focus inline search for DNS, LDAP, or finding rows.",
    ),
    ActionDefinition("sort_name", "action_sort_name", "n", "n", "Sort name"),
    ActionDefinition("sort_type", "action_sort_type", "t", "t", "Sort type"),
    ActionDefinition("sort_value", "action_sort_value", "e", "e", "Sort value"),
    ActionDefinition("quit", "action_quit", "ctrl+q", binding_label="Quit"),
    ActionDefinition(
        "ldap_search_users",
        "action_ldap_search_kind",
        palette_label="Search LDAP users",
        description="Open LDAP search prefilled for users.",
        args=("users",),
    ),
    ActionDefinition(
        "ldap_search_groups",
        "action_ldap_search_kind",
        palette_label="Search LDAP groups",
        description="Open LDAP search prefilled for groups.",
        args=("groups",),
    ),
    ActionDefinition(
        "ldap_search_computers",
        "action_ldap_search_kind",
        palette_label="Search LDAP computers",
        description="Open LDAP search prefilled for computers.",
        args=("computers",),
    ),
)

ACTION_BY_ID = {action.action_id: action for action in ACTIONS}
APP_BINDINGS = tuple(
    (action.binding, action.textual_action, action.binding_label)
    for action in ACTIONS
    if action.binding
)
KEY_ACTION_NAMES = {
    action.binding: action.method
    for action in ACTIONS
    if action.binding and not action.character and action.binding != "G"
}
CHAR_ACTION_NAMES = {
    action.character.casefold(): action.method
    for action in ACTIONS
    if action.character and action.character == action.character.casefold()
}
CASE_SENSITIVE_ACTION_NAMES = {
    action.character: action.method
    for action in ACTIONS
    if action.character and action.character != action.character.casefold()
}
PALETTE_ACTIONS: tuple[CommandPaletteChoice, ...] = (
    *(
        (
            action.action_id,
            action.palette_label,
            action.shortcut if action.binding else "",
            action.description,
        )
        for action in ACTIONS
        if action.palette_label
    ),
    *(
        (
            f"smart_view_{view.shortcut}",
            f"Open finding filter: {view.label}",
            view.shortcut,
            view.description,
        )
        for view in SMART_VIEWS
    ),
)
PALETTE_ACTION_MAP: dict[str, tuple[str, tuple[str, ...]]] = {
    **{
        action.action_id: (action.method, action.args)
        for action in ACTIONS
        if action.palette_label
    },
    **{
        f"smart_view_{view.shortcut}": (
            "action_smart_view_shortcut",
            (view.shortcut,),
        )
        for view in SMART_VIEWS
    },
}


def shortcut_for(action_id: str) -> str:
    return ACTION_BY_ID[action_id].shortcut
