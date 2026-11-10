package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/invariant"
)

func (current *form) setChoices(index int, values ...string) {
	invariant.Require(index >= 0 && index < len(current.Fields), "invalid choice field")
	invariant.Require(!current.Fields[index].Secret, "secret cannot be a choice field")
	invariant.Require(len(values) > 0 && len(values) <= formFieldsMax, "invalid choice count")
	if current.Choices == nil {
		current.Choices = make(map[int][]string, len(current.Fields))
	}
	current.Choices[index] = values
}

func (current *form) updateChoice(message tea.KeyMsg) {
	choices := current.Choices[current.Cursor]
	index := 0
	for position, choice := range choices {
		if choice == current.Fields[current.Cursor].text() {
			index = position
		}
	}
	switch message.String() {
	case "left":
		index = (index + len(choices) - 1) % len(choices)
	case "right", " ":
		index = (index + 1) % len(choices)
	default:
		if message.Type != tea.KeyRunes {
			return
		}
		text := string(message.Runes)
		matched := false
		for position, choice := range choices {
			if strings.EqualFold(text, choice) ||
				(len(message.Runes) == 1 && strings.HasPrefix(choice, strings.ToLower(text))) {
				index, matched = position, true
				break
			}
		}
		if !matched {
			return
		}
	}
	current.Fields[current.Cursor].setText(choices[index])
}

func (current *form) filteredItems() []string {
	needle := strings.ToLower(current.Fields[0].text())
	items := make([]string, 0, len(current.Items))
	for _, item := range current.Items {
		if strings.Contains(strings.ToLower(item+" "+current.ItemLabels[item]), needle) {
			items = append(items, item)
		}
	}
	return items
}

func (model *Model) updatePicker(message tea.KeyMsg) tea.Cmd {
	current := model.form
	items := current.filteredItems()
	current.ItemCursor = min(current.ItemCursor, max(0, len(items)-1))
	switch message.String() {
	case "up":
		current.ItemCursor = max(0, current.ItemCursor-1)
	case "down":
		current.ItemCursor = min(max(0, len(items)-1), current.ItemCursor+1)
	case "enter", "ctrl+s":
		if len(items) == 0 {
			return nil
		}
		current.Fields[0].setText(items[min(current.ItemCursor, len(items)-1)])
		return model.submitForm()
	case "esc", "tab", "shift+tab":
		return model.updateFormField(message)
	default:
		before := current.Fields[0].text()
		command := model.updateFormField(message)
		if current.Fields[0].text() != before {
			current.ItemCursor = 0
		}
		return command
	}
	return nil
}
