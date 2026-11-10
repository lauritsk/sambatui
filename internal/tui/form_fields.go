package tui

import "github.com/lauritsk/sambatui/internal/invariant"

func (current *form) fieldIndices() []int {
	invariant.Require(len(current.Fields) > 0, "form requires fields")
	invariant.Require(len(current.Fields) <= formFieldsMax, "form field budget exceeded")
	var indices []int
	if current.VisibleFields != nil {
		indices = current.VisibleFields(current.Fields)
	} else {
		indices = make([]int, len(current.Fields))
		for index := range indices {
			indices[index] = index
		}
	}
	invariant.Require(len(indices) > 0, "form has no visible fields")
	invariant.Require(len(indices) <= len(current.Fields), "too many visible form fields")
	var seen [formFieldsMax]bool
	for _, index := range indices {
		invariant.Require(index >= 0 && index < len(current.Fields), "invalid visible field")
		invariant.Require(!seen[index], "duplicate visible field")
		seen[index] = true
	}
	return indices
}

func (current *form) cursorPosition(indices []int) int {
	for position, index := range indices {
		if index == current.Cursor {
			return position
		}
	}
	invariant.Require(false, "focused form field is hidden")
	return 0
}
