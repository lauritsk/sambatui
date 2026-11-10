package tui

import (
	"errors"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/rivo/uniseg"
)

func (current *form) caret(index int) int {
	text := current.Fields[index].text()
	if current.Fields[index].Secret {
		return len(text)
	}
	position, exists := current.Carets[index]
	if !exists {
		return len(text)
	}
	return min(max(0, position), len(text))
}

func (current *form) setCaret(index, position int) {
	invariant.Require(position >= 0 && position <= len(current.Fields[index].text()),
		"field caret is outside its text")
	if current.Fields[index].Secret {
		return
	}
	if current.Carets == nil {
		current.Carets = make(map[int]int, len(current.Fields))
	}
	current.Carets[index] = position
}

func (model *Model) editFormField(message tea.KeyMsg) {
	current := model.form
	index := current.Cursor
	field := &current.Fields[index]
	text, position := field.text(), current.caret(index)
	switch message.String() {
	case "left", "right", "home", "end":
		if field.Secret {
			return
		}
		switch message.String() {
		case "left":
			position = previousBoundary(text, position)
		case "right":
			position = nextBoundary(text, position)
		case "home":
			position = 0
		case "end":
			position = len(text)
		}
	case "ctrl+u":
		text, position = "", 0
	case "backspace", "ctrl+h":
		start := previousBoundary(text, position)
		text, position = text[:start]+text[position:], start
	case "delete":
		text = text[:position] + text[nextBoundary(text, position):]
	default:
		if message.Type != tea.KeyRunes {
			return
		}
		prefix, err := formInput(fieldPrefix(*field, position), message.Runes)
		if err != nil {
			model.error(err)
			model.errorUnread = false
			return
		}
		if len(prefix) > formFieldBytesMax-len(text[position:]) {
			model.error(errors.New("form input exceeds 1 MiB"))
			model.errorUnread = false
			return
		}
		text, position = prefix+text[position:], len(prefix)
		if position > 0 && position < len(text) {
			position = nextBoundary(text, position-1)
		}
	}
	field.setText(text)
	current.setCaret(index, position)
}

func fieldPrefix(current field, position int) field {
	return field{Label: current.Label, Value: current.text()[:position], Secret: current.Secret}
}

func previousBoundary(text string, position int) int {
	invariant.Require(len(text) <= formFieldBytesMax, "unvalidated editor text")
	invariant.Require(position >= 0 && position <= len(text), "invalid previous caret")
	graphemes := uniseg.NewGraphemes(text)
	for graphemes.Next() {
		start, end := graphemes.Positions()
		if end >= position {
			return start
		}
	}
	return 0
}

func nextBoundary(text string, position int) int {
	invariant.Require(len(text) <= formFieldBytesMax, "unvalidated editor text")
	invariant.Require(position >= 0 && position <= len(text), "invalid next caret")
	graphemes := uniseg.NewGraphemes(text)
	for graphemes.Next() {
		_, end := graphemes.Positions()
		if end > position {
			return end
		}
	}
	return len(text)
}

func fieldValueAt(current field, width int, active bool, position int) string {
	if !active || current.Secret {
		return fieldValue(current, width, active)
	}
	invariant.Require(width >= 3 && width <= terminalColumnsMax, "invalid editor viewport")
	invariant.Require(position >= 0 && position <= len(current.text()), "invalid editor caret")
	prefix, suffix := Literal(current.text()[:position]), Literal(current.text()[position:])
	available := width - 3
	left := available
	if suffix != "" {
		left = max(1, available*2/3)
	}
	prefix = ansi.TruncateLeft(prefix, max(0, ansi.StringWidth(prefix)-left), "")
	remaining := max(0, available-ansi.StringWidth(prefix))
	if remaining == 0 {
		suffix = ""
	} else {
		suffix = ansi.Truncate(suffix, remaining, "…")
	}
	return "  " + prefix + "_" + suffix
}

func fieldValue(current field, width int, active bool) string {
	invariant.Require(width >= 3, "field requires padding and an insertion point")
	invariant.Require(width <= terminalColumnsMax, "field width exceeds terminal limit")
	value := ""
	if current.Secret {
		if current.text() != "" {
			value = "[hidden]"
		}
	} else {
		value = Literal(current.text())
	}
	available := max(1, width-2)
	if active {
		value = ansi.TruncateLeft(value, max(0, ansi.StringWidth(value)-available+1), "")
		return "  " + value + "_"
	}
	return "  " + ansi.Truncate(value, available, "…")
}
