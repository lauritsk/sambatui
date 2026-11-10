package tui

import (
	"strings"

	"github.com/lauritsk/sambatui/internal/invariant"
)

func (model *Model) footerLine(visibleCount int) string {
	text, warning := model.footerMessage(visibleCount)
	style := model.theme.muted
	if warning {
		style = model.theme.warning
	}
	if model.status != "" && model.status == model.lastError && !warning {
		style = model.theme.failure
		text = "Error: " + Literal(model.status)
		if model.form == nil && model.detail == "" {
			text = footerSuffix(text, "! details", model.width)
		}
	} else if model.errorUnread && model.form == nil && model.detail == "" &&
		model.writeCancel == nil {
		text = footerSuffix(text, "! error", model.width)
	}
	return style.Render(cell(text, model.width))
}

func (model *Model) footerMessage(visibleCount int) (string, bool) {
	if model.writeCancel != nil {
		text := "Writing · Ctrl+C cancel (not rollback)"
		if model.writeCancelling {
			text = "Cancelling · not rollback"
		}
		if model.lastWrite.Settings.Server != model.settings.Server {
			text += " · " + Literal(model.lastWrite.Settings.Server)
		}
		return text, true
	}
	if model.form == nil && model.detail == "" {
		if _, uncertain := model.state.Uncertain(); uncertain {
			return "Unknown write · R reconcile", true
		}
	}
	if model.status != "" {
		return Literal(model.status), false
	}
	if model.form != nil {
		return model.formFooter(), false
	}
	if model.detail != "" {
		return "Esc close", false
	}
	if model.loading != "" {
		return "Loading " + Literal(model.loading) + "…", false
	}
	return model.browserFooter(visibleCount), false
}

func (model *Model) formFooter() string {
	if model.form.Items != nil {
		if len(model.form.filteredItems()) == 0 {
			return "Type to filter · Esc close"
		}
		return "↑/↓ choose · Enter run · Esc close"
	}
	if len(model.form.Choices[model.form.Cursor]) > 0 {
		if model.width < 60 {
			return "←/→ · Tab · Ctrl+S · Esc cancel"
		}
		return "←/→ choose · Tab next · Ctrl+S submit · Esc cancel"
	}
	if model.form.EnterSubmits {
		return "Enter submit · Esc cancel"
	}
	if len(model.form.fieldIndices()) == 1 {
		return "Ctrl+S submit · Esc cancel"
	}
	return "Tab next · Ctrl+S submit · Esc cancel"
}

func (model *Model) browserFooter(visibleCount int) string {
	if model.settings.Server == "" {
		return "Ctrl+O setup · ? help · Q quit"
	}
	if model.errorUnread && model.width < 60 {
		return "? help · Q quit"
	}
	if model.sidebar {
		if len(model.sideLabels()) == 0 {
			return "z zones · ? help · Q quit"
		}
		return "Enter open · Tab pane · ? help · Q quit"
	}
	if model.search != "" {
		return "Esc clear filter · ? help · Q quit"
	}
	if visibleCount == 0 {
		return "r refresh · ? help · Q quit"
	}
	if model.width < 60 {
		return "Tab pane · Enter · ? help · Q quit"
	}
	return "Enter details · Tab pane · / filter · ? help · Q quit"
}

func footerSuffix(text, suffix string, width int) string {
	invariant.Require(width >= 20 && width <= terminalColumnsMax, "invalid footer width")
	return strings.TrimRight(cell(text, max(1, width-len(suffix)-3)), " ") + " · " + suffix
}
