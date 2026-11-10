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
}

func (model *Model) assertValid() {
	invariant.Require(model.state != nil, "model requires connection state")
	invariant.Require(model.service != nil, "model requires backend service")
	invariant.Require(model.cursor >= 0, "negative result cursor")
	invariant.Require(model.sideCursor >= 0, "negative sidebar cursor")
	invariant.Require(model.sortField >= 0, "negative sort field")
	invariant.Require(model.sortField < 3, "sort field out of bounds")
	if model.form != nil {
		model.form.assertValid()
	}
}
