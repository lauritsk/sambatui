package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
)

// A coalesced key message is finite work, even if a terminal sends bad input.
// Bracketed paste is data only: it must never be interpreted as UI commands.
const commandRunesMax = 4096

func (model *Model) updateKey(key tea.KeyMsg) tea.Cmd {
	if model.form == nil && key.Paste {
		return nil
	}
	if model.form == nil && key.Type == tea.KeyRunes && len(key.Runes) > 1 && !key.Alt {
		if len(key.Runes) > commandRunesMax {
			model.status = "Command input exceeds safety limit; nothing executed."
			return nil
		}
		commands := []tea.Cmd{}
		for _, character := range key.Runes {
			command := model.updateSingleKey(
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}},
			)
			if command != nil {
				commands = append(commands, command)
			}
		}
		return tea.Batch(commands...)
	}
	return model.updateSingleKey(key)
}

func (model *Model) updateSingleKey(message tea.KeyMsg) tea.Cmd {
	key := message.String()
	if model.writeCancel == nil {
		model.status = ""
	}
	if key == "ctrl+z" {
		if model.writeCancel != nil {
			model.status = "Cannot suspend during a write; cancel and drain it first."
			return nil
		}
		return tea.Suspend
	}
	if key == "ctrl+c" {
		if model.writeCancel != nil {
			model.writeCancel()
			model.writeCancelling = true
			model.status = "Cancelling · not rollback"
			return nil
		}
		if model.form != nil {
			model.closeForm()
			return nil
		}
		return tea.Quit
	}
	if model.form != nil {
		return model.updateForm(message)
	}
	if model.detail != "" {
		model.updateDetailKey(key)
		return nil
	}
	return model.updateActionKey(key)
}

func (model *Model) updateDetailKey(key string) {
	width, page := model.detailViewport()
	last := max(0, wrappedPage(model.detail, width, 0, page).totalRows-page)
	offset := min(model.detailOffset, last)
	switch key {
	case "esc", "enter", "q":
		model.detail = ""
	case "j", "down":
		model.detailOffset = min(offset+1, last)
	case "k", "up":
		model.detailOffset = max(0, offset-1)
	case "pgdown":
		model.detailOffset = min(offset+page, last)
	case "pgup":
		model.detailOffset = max(0, offset-page)
	}
}

func (model *Model) updateActionKey(key string) tea.Cmd {
	switch key {
	case "Q":
		if model.flow != nil {
			model.status = "Cannot quit during a write; cancel and drain it first."
			return nil
		}
		return tea.Quit
	case "?":
		model.showHelp()
	case "!":
		model.showLastError()
	case "ctrl+o":
		model.connectionForm()
	case "ctrl+p":
		model.commandForm()
	case "z":
		model.setMode("dns")
		return model.load("zones")
	case "l":
		model.ldapForm()
	case "q":
		model.queryForm()
	case "r":
		return model.load(model.mode)
	case "R":
		return model.reconcile()
	case "/":
		model.searchForm()
	case "enter":
		if model.sidebar {
			return model.activateSide()
		}
		model.details()
	case "a", "u", "e", "d":
		return model.writeForm(key)
	case "m":
		return model.loadMore()
	case "p":
		model.loadPassword()
	case "P":
		model.savePasswordForm()
	default:
		model.updateNavigationKey(key)
	}
	return nil
}

func (model *Model) updateNavigationKey(key string) {
	switch key {
	case "tab", "shift+tab":
		model.sidebar = !model.sidebar
	case "j", "down":
		model.move(1)
	case "k", "up":
		model.move(-1)
	case "pgdown", "ctrl+d":
		model.move(max(1, (model.height-10)/2))
	case "pgup", "ctrl+u":
		model.move(-max(1, (model.height-10)/2))
	case "home", "g":
		model.move(-len(model.visible()) - len(model.sideLabels()))
	case "end", "G":
		model.move(len(model.visible()) + len(model.sideLabels()))
	case " ":
		if !model.sidebar {
			indices := model.visible()
			if model.cursor < len(indices) {
				index := indices[model.cursor]
				model.selected[index] = !model.selected[index]
				model.anchor = model.cursor
			}
		}
	case "v":
		if model.anchor < 0 {
			model.anchor = model.cursor
		} else {
			indices := model.visible()
			first := min(model.anchor, model.cursor)
			last := min(max(model.anchor, model.cursor), len(indices)-1)
			for index := first; index <= last; index++ {
				model.selected[indices[index]] = true
			}
			model.anchor = -1
		}
	case "esc":
		model.selected = map[int]bool{}
		model.search = ""
		model.anchor = -1
	case "s":
		model.cycleSort()
	}
}

func (model *Model) loadMore() tea.Cmd {
	if model.mode != "ldap" {
		model.status = "Load more is available for the directory view"
		return nil
	}
	model.settings.LDAPMaxRows = min(5000, model.settings.LDAPMaxRows+200)
	model.state.Change(model.settings)
	model.selected = map[int]bool{}
	return model.load(model.mode)
}

func (model *Model) loadPassword() {
	password, err := config.ReadPassword(model.settings.PasswordFile)
	if err != nil {
		model.error(err)
		return
	}
	settings := model.settings
	settings.Password = newSecret(password)
	model.setConnection(settings)
}
