package tui

import (
	"reflect"
	"testing"
)

func TestInvalidThemeDoesNotChangeCurrentTheme(t *testing.T) {
	model := testModel()
	before := model.theme
	if err := model.SetTheme("invalid"); err == nil {
		t.Fatal("invalid theme accepted")
	}
	if !reflect.DeepEqual(before, model.theme) {
		t.Fatal("invalid theme partially changed the palette")
	}
}
