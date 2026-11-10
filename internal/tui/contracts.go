package tui

import (
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

const (
	terminalColumnsMax = 1000
	terminalRowsMax    = 1000
	formFieldsMax      = 32
)

// Match the outstanding intent, not the currently displayed connection. A slow
// inspection result must not clear a newer journal or replace another form.
func (model *Model) reconcileCurrent(snapshot lifecycle.Snapshot) bool {
	if model.form != nil {
		return false
	}
	return model.reconcileMatches(snapshot)
}

func (model *Model) reconcileMatches(snapshot lifecycle.Snapshot) bool {
	uncertain, exists := model.state.Uncertain()
	if !exists {
		return false
	}
	if model.flow != nil {
		return false
	}
	return uncertain == snapshot
}

func (current *form) assertValid() {
	invariant.Require(len(current.Fields) > 0, "form must contain fields")
	invariant.Require(len(current.Fields) <= formFieldsMax, "form has too many fields")
	invariant.Require(current.Cursor >= 0, "negative form cursor")
	invariant.Require(current.Cursor < len(current.Fields), "form cursor out of bounds")
	invariant.Require(current.Accept != nil, "form requires an accept callback")
	invariant.Require(!current.Write || !current.EnterSubmits, "write requires explicit submission")
	if current.Write {
		invariant.Require(current.Owner != nil, "write form lost its reservation")
	}
	invariant.Require(len(current.Choices) <= len(current.Fields), "too many choice fields")
	invariant.Require(len(current.Items) <= formFieldsMax, "too many picker items")
	invariant.Require(len(current.ItemLabels) <= formFieldsMax, "too many picker labels")
	invariant.Require(len(current.Carets) <= len(current.Fields), "too many field carets")
	invariant.Require(current.ItemCursor >= 0, "negative picker cursor")
	if current.Items != nil {
		invariant.Require(!current.Write, "write cannot use an implicit picker submission")
		invariant.Require(len(current.Fields) == 1, "picker needs one query field")
	}
	current.cursorPosition(current.fieldIndices())
	invariant.Require(current.ContextOffset >= 0, "negative form preview offset")
	invariant.Require(len(current.Context) <= viewTextBytesMax, "unvalidated form preview")
}

func (model *Model) assertValid() {
	invariant.Require(model.state != nil, "model requires connection state")
	invariant.Require(model.service != nil, "model requires backend service")
	invariant.Require(model.width > 0, "terminal width must be positive")
	invariant.Require(model.width <= terminalColumnsMax, "terminal width exceeds budget")
	invariant.Require(model.height > 0, "terminal height must be positive")
	invariant.Require(model.height <= terminalRowsMax, "terminal height exceeds budget")
	invariant.Require(model.mode == "dns" || model.mode == "ldap", "unknown view mode")
	invariant.Require(model.detailOffset >= 0, "negative detail preview offset")
	invariant.Require(len(model.detail) <= viewTextBytesMax, "unvalidated detail preview")
	invariant.Require(len(model.lastError) <= errorTextBytesMax, "error retention exceeds budget")
	if model.errorUnread {
		invariant.Require(model.lastError != "", "unread error is missing")
	}
	invariant.Require(model.cursor >= 0, "negative result cursor")
	invariant.Require(model.sideCursor >= 0, "negative sidebar cursor")
	if model.writeCancelling {
		invariant.Require(model.writeCancel != nil, "cancelling write has no worker")
	}
	invariant.Require(model.sortField >= 0, "negative sort field")
	invariant.Require(model.sortField < 3, "sort field out of bounds")
	if model.form != nil {
		model.form.assertValid()
		if model.form.Write {
			invariant.Require(model.form.Owner == model.flow, "write form changed its owner")
		}
	}
}
