from sambatui.screens import ConfirmScreen


def test_confirmation_keys_match_yes_no_and_default() -> None:
    dangerous = ConfirmScreen("Delete?", default_confirm=False)
    safe = ConfirmScreen("Add?", default_confirm=True)

    assert dangerous.key_decision("x", "y") is True
    assert dangerous.key_decision("x", "Y") is True
    assert dangerous.key_decision("x", "n") is False
    assert dangerous.key_decision("escape") is False
    assert dangerous.key_decision("enter") is False
    assert safe.key_decision("enter") is True
    assert safe.key_decision("x", "j") is None


def test_confirmation_labels_show_enter_default() -> None:
    dangerous = ConfirmScreen("Delete?", default_confirm=False)
    safe = ConfirmScreen("Add?", default_confirm=True)

    assert dangerous.button_label(False) == "No (Enter)"
    assert dangerous.button_label(True) == "Yes"
    assert safe.button_label(False) == "No"
    assert safe.button_label(True) == "Yes (Enter)"
