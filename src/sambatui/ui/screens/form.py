from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from ipaddress import ip_address
from typing import TypeAlias
from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.events import Key
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.suggester import Suggester
from textual.widgets import Button, Input, Static

from ...ldap.client import domain_to_base_dn
from .base import FocusedModalScreen


FormField: TypeAlias = tuple[str, str, str, str]
FormValidator: TypeAlias = Callable[[dict[str, str]], str | None]


def user_principal_name_suggestion(value: str, domain: str) -> str:
    username = value.strip()
    dns_domain = domain.strip().rstrip(".").lower()
    if not username or not dns_domain or "@" in username or "\\" in username:
        return username
    return f"{username}@{dns_domain}"


class UserPrincipalNameSuggester(Suggester):
    def __init__(self, domain_provider: Callable[[], str]) -> None:
        super().__init__(use_cache=False, case_sensitive=True)
        self.domain_provider = domain_provider

    async def get_suggestion(self, value: str) -> str | None:
        suggestion = user_principal_name_suggestion(value, self.domain_provider())
        return suggestion if suggestion != value.strip() else None


def infer_domain_from_server(server: str) -> str:
    value = server.strip().rstrip(".")
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value).strip().rstrip(".")
    if not host:
        return ""
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        return ""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 3:
        return ""
    if any("_" in label for label in labels):
        return ""
    return ".".join(labels[1:])


class FormScreen(FocusedModalScreen[dict[str, str] | None]):
    CSS = """
    FormScreen { align: center middle; }
    #form_dialog {
        width: 88;
        height: auto;
        max-height: 92%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #form_title { text-style: bold; color: $accent; margin-bottom: 1; }
    #form_hint { color: $text-muted; margin-bottom: 1; }
    #form_error { color: $error; margin-bottom: 1; }
    #form_fields { height: auto; max-height: 72%; margin-bottom: 1; }
    .hint { color: $text-muted; margin-bottom: 0; }
    .form_row { height: auto; margin-bottom: 1; }
    .form_row Input { width: 1fr; margin-right: 1; }
    #form_buttons { height: auto; align-horizontal: right; }
    #form_buttons Button { width: 16; margin-left: 1; }
    """

    def __init__(
        self,
        title: str,
        hint: str,
        fields: list[FormField],
        submit_label: str = "Continue",
        validator: FormValidator | None = None,
    ) -> None:
        super().__init__()
        self.form_title = title
        self.hint = hint
        self.fields = fields
        self.submit_label = submit_label
        self.validator = validator
        self._autofilled: dict[str, str] = {}
        self._suppress_autofill = False

    def compose(self) -> ComposeResult:
        with Vertical(id="form_dialog"):
            yield Static(self.form_title, id="form_title")
            if self.hint:
                yield Static(self.hint, id="form_hint")
            if self.validator:
                yield Static("", id="form_error")
            with VerticalScroll(id="form_fields"):
                for label, field_id, placeholder, value in self.fields:
                    yield Static(label, classes="hint")
                    with Horizontal(classes="form_row"):
                        yield Input(
                            value=value,
                            placeholder=placeholder,
                            password=field_id == "password",
                            suggester=self.input_suggester(field_id),
                            id=field_id,
                        )
            with Horizontal(id="form_buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(self.submit_label, id="submit", variant="primary")

    def form_values(self) -> dict[str, str]:
        values = {}
        for _, field_id, _, _ in self.fields:
            values[field_id] = self.query_one(f"#{field_id}", Input).value.strip()
        if self.should_suggest_upn_domain():
            values["user"] = user_principal_name_suggestion(
                values.get("user", ""), values.get("domain", "")
            )
        return values

    def field_ids(self) -> set[str]:
        return {field_id for _, field_id, _, _ in self.fields}

    def should_suggest_upn_domain(self) -> bool:
        return self.form_title == "First-run setup wizard" and {
            "domain",
            "user",
        }.issubset(self.field_ids())

    def upn_domain(self) -> str:
        return self.query_one("#domain", Input).value.strip()

    def input_suggester(self, field_id: str) -> Suggester | None:
        if field_id == "user" and self.should_suggest_upn_domain():
            return UserPrincipalNameSuggester(self.upn_domain)
        return None

    def upn_suggestion_for_input(self, user_input: Input) -> str:
        return user_principal_name_suggestion(user_input.value, self.upn_domain())

    def refresh_upn_suggestion(self) -> None:
        if not self.should_suggest_upn_domain():
            return
        with suppress(Exception):
            user_input = self.query_one("#user", Input)
            suggestion = self.upn_suggestion_for_input(user_input)
            user_input._suggestion = (
                suggestion if suggestion != user_input.value.strip() else ""
            )

    def accept_upn_suggestion(self) -> None:
        if not self.should_suggest_upn_domain():
            return
        with suppress(Exception):
            user_input = self.query_one("#user", Input)
            suggestion = self.upn_suggestion_for_input(user_input)
            if suggestion == user_input.value.strip():
                return
            self._suppress_autofill = True
            try:
                user_input.value = suggestion
                user_input._suggestion = ""
            finally:
                self._suppress_autofill = False

    def maybe_autofill_connection_fields(self) -> None:
        if not {"server", "zone", "ldap_base"}.issubset(self.field_ids()):
            return

        server = self.query_one("#server", Input).value.strip()
        zone_input = self.query_one("#zone", Input)
        ldap_base_input = self.query_one("#ldap_base", Input)
        zone = zone_input.value.strip()

        inferred_zone = infer_domain_from_server(server)
        if inferred_zone and self.can_autofill("zone", zone):
            self.autofill("zone", inferred_zone)
            zone = inferred_zone

        base_dn = domain_to_base_dn(zone)
        if base_dn and self.can_autofill("ldap_base", ldap_base_input.value.strip()):
            self.autofill("ldap_base", base_dn)

    def can_autofill(self, field_id: str, current: str) -> bool:
        return not current or self._autofilled.get(field_id) == current

    def autofill(self, field_id: str, value: str) -> None:
        self._suppress_autofill = True
        try:
            self.query_one(f"#{field_id}", Input).value = value
        finally:
            self._suppress_autofill = False
        self._autofilled[field_id] = value

    def validation_error(self) -> str | None:
        if self.validator is None:
            return None
        return self.validator(self.form_values())

    def refresh_validation(self) -> str | None:
        error = self.validation_error()
        with suppress(Exception):
            self.query_one("#form_error", Static).update(error or "")
        with suppress(Exception):
            self.query_one("#submit", Button).disabled = error is not None
        return error

    def refresh_form_feedback(self) -> None:
        self.refresh_upn_suggestion()
        self.refresh_validation()

    def submit(self) -> None:
        if self.refresh_validation() is not None:
            return
        self.dismiss(self.form_values())

    def on_mount(self) -> None:
        self.maybe_autofill_connection_fields()
        self.refresh_form_feedback()
        self.focus_first_control()

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._suppress_autofill:
            return
        field_id = str(event.input.id)
        if self._autofilled.get(field_id) != event.input.value.strip():
            self._autofilled.pop(field_id, None)
            self.maybe_autofill_connection_fields()
        self.refresh_form_feedback()

    def on_input_blurred(self, event: Input.Blurred) -> None:
        if event.input.id == "user":
            self.accept_upn_suggestion()
            self.refresh_form_feedback()

    def on_key(self, event: Key) -> None:
        if isinstance(self.focused, Button) and event.key in {"enter", "space"}:
            return
        if event.key == "escape":
            event.prevent_default()
            event.stop()
            self.dismiss(None)
            return
        if event.key == "enter":
            event.prevent_default()
            event.stop()
            self.submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.submit()
