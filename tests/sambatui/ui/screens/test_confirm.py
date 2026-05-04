from hypothesis import given
from hypothesis import strategies as st

from sambatui.ui.screens import ConfirmScreen


@given(
    st.booleans(),
    st.sampled_from(
        [
            ("x", "y", True),
            ("x", "Y", True),
            ("x", "n", False),
            ("escape", None, False),
            ("x", "j", None),
        ]
    ),
)
def test_confirmation_keys_match_yes_no_and_default(
    default_confirm: bool, key_case: tuple[str, str | None, bool | None]
) -> None:
    key, character, expected = key_case
    screen = ConfirmScreen("Continue?", default_confirm=default_confirm)

    assert screen.key_decision(key, character) is expected
    assert screen.key_decision("enter") is default_confirm


@given(st.booleans(), st.booleans())
def test_confirmation_labels_show_enter_default(
    default_confirm: bool, confirms: bool
) -> None:
    screen = ConfirmScreen("Continue?", default_confirm=default_confirm)
    expected = "Yes" if confirms else "No"
    if confirms == default_confirm:
        expected = f"{expected} (Enter)"

    assert screen.button_label(confirms) == expected
