package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/config"
)

// A coalesced key message is finite work, even if a terminal sends bad input.
// Bracketed paste is data only: it must never be interpreted as UI commands.
const commandRunesMax = 4096

func (m *Model) updateKey(key tea.KeyMsg) tea.Cmd {
	if m.form == nil && key.Paste {
		return nil
	}
	if m.form == nil && key.Type == tea.KeyRunes && len(key.Runes) > 1 && !key.Alt {
		if len(key.Runes) > commandRunesMax {
			m.status = "Command input exceeds safety limit; nothing executed."
			return nil
		}
		commands := []tea.Cmd{}
		for _, character := range key.Runes {
			command := m.updateSingleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}})
			if command != nil {
				commands = append(commands, command)
			}
		}
		return tea.Batch(commands...)
	}
	return m.updateSingleKey(key)
}

func (m *Model) updateSingleKey(message tea.KeyMsg) tea.Cmd {
	key := message.String()
	if key == "ctrl+c" {
		if m.writeCancel != nil {
			m.writeCancel()
			m.status = "Cancellation requested; waiting for worker cleanup. This is not rollback."
			return nil
		}
		if m.form != nil {
			m.closeForm()
			return nil
		}
		return tea.Quit
	}
	if m.form != nil {
		return m.updateForm(message)
	}
	if m.detail != "" {
		m.updateDetailKey(key)
		return nil
	}
	return m.updateActionKey(key)
}

func (m *Model) updateDetailKey(key string) {
	switch key {
	case "esc", "enter", "q":
		m.detail = ""
	case "j", "down":
		m.detailOffset++
	case "k", "up":
		m.detailOffset = max(0, m.detailOffset-1)
	case "pgdown":
		m.detailOffset += max(1, m.height-8)
	case "pgup":
		m.detailOffset = max(0, m.detailOffset-max(1, m.height-8))
	}
}

func (m *Model) updateActionKey(key string) tea.Cmd {
	switch key {
	case "Q":
		if m.flow != nil {
			m.status = "Cannot quit during a write; cancel and drain it first."
			return nil
		}
		return tea.Quit
	case "?":
		m.showDetails(help)
	case "h":
		m.findingsForm()
	case "ctrl+o":
		m.connectionForm()
	case "ctrl+p":
		m.commandForm()
	case "z":
		m.setMode("dns")
		return m.load("zones")
	case "l":
		m.ldapForm()
	case "q":
		m.queryForm()
	case "r":
		return m.load(m.mode)
	case "R":
		return m.reconcile()
	case "/":
		m.searchForm()
	case "enter":
		if m.sidebar {
			return m.activateSide()
		}
		m.details()
	case "a", "u", "e", "d", "f":
		return m.writeForm(key)
	case "m":
		return m.loadMore()
	case "p":
		m.loadPassword()
	case "P":
		m.savePasswordForm()
	case "1", "2", "3", "4", "5", "6", "7", "8":
		m.healthCheck = int(key[0] - '0')
		return m.load("health")
	default:
		m.updateNavigationKey(key)
	}
	return nil
}

func (m *Model) updateNavigationKey(key string) {
	switch key {
	case "tab":
		m.sidebar = !m.sidebar
	case "j", "down":
		m.move(1)
	case "k", "up":
		m.move(-1)
	case "pgdown", "ctrl+d":
		m.move(max(1, (m.height-10)/2))
	case "pgup", "ctrl+u":
		m.move(-max(1, (m.height-10)/2))
	case "home", "g":
		m.move(-len(m.visible()) - len(m.sideLabels()))
	case "end", "G":
		m.move(len(m.visible()) + len(m.sideLabels()))
	case " ":
		if !m.sidebar {
			indices := m.visible()
			if m.cursor < len(indices) {
				index := indices[m.cursor]
				m.selected[index] = !m.selected[index]
				m.anchor = m.cursor
			}
		}
	case "v":
		if m.anchor < 0 {
			m.anchor = m.cursor
		} else {
			indices := m.visible()
			for index := min(m.anchor, m.cursor); index <= max(m.anchor, m.cursor) && index < len(indices); index++ {
				m.selected[indices[index]] = true
			}
			m.anchor = -1
		}
	case "esc":
		m.selected = map[int]bool{}
		m.search = ""
		m.anchor = -1
	case "s":
		m.sortField = (m.sortField + 1) % 3
		m.reverse = !m.reverse
	}
}

func (m *Model) loadMore() tea.Cmd {
	switch m.mode {
	case "health":
		m.cfg.MaxRows = min(5000, m.cfg.MaxRows+200)
	case "ldap":
		m.cfg.LDAPMaxRows = min(5000, m.cfg.LDAPMaxRows+200)
	default:
		m.status = "Load more is available for directory/findings views"
		return nil
	}
	m.state.Change(m.cfg)
	m.selected = map[int]bool{}
	return m.load(m.mode)
}

func (m *Model) loadPassword() {
	password, err := config.ReadPassword(m.cfg.PasswordFile)
	if err != nil {
		m.error(err)
		return
	}
	settings := m.cfg
	settings.Password = newSecret(password)
	m.setConnection(settings)
}
