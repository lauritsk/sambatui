package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

type theme struct {
	muted, focus, selection, warning, failure lipgloss.Style
	border, chrome, cursor, input             lipgloss.Style
}

func newTheme(light bool) theme {
	accent, focus, muted := "#e135ff", "#80ffea", "#b7a8cf"
	warning, failure := "#f1fa8c", "#ff6e96"
	border, surface, foreground := "#76618e", "#2b2142", "#f8f8f2"
	cursor, input := "#493461", "#221c34"
	if light {
		accent, focus, muted = "#7800a3", "#006b64", "#61536f"
		warning, failure = "#755500", "#b00036"
		border, surface, foreground = "#8c769e", "#e9e0f2", "#23113f"
		cursor, input = "#d9c8ed", "#eee7f3"
	}
	return theme{
		muted:     lipgloss.NewStyle().Foreground(lipgloss.Color(muted)),
		focus:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(focus)),
		selection: lipgloss.NewStyle().Underline(true).Foreground(lipgloss.Color(accent)),
		warning:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(warning)),
		failure:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(failure)),
		border:    lipgloss.NewStyle().Foreground(lipgloss.Color(border)),
		chrome: lipgloss.NewStyle().Foreground(lipgloss.Color(foreground)).
			Background(lipgloss.Color(surface)),
		cursor: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(foreground)).
			Background(lipgloss.Color(cursor)),
		input: lipgloss.NewStyle().Foreground(lipgloss.Color(foreground)).
			Background(lipgloss.Color(input)),
	}
}

func (model *Model) SetTheme(name string) error {
	if name != "dark" && name != "light" {
		return fmt.Errorf("theme must be dark or light")
	}
	model.theme = newTheme(name == "light")
	return nil
}
