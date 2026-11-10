package tui

import (
	"os"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFormProjectionRejectsInvalidIndices(t *testing.T) {
	for _, test := range []struct {
		name    string
		indices []int
		cursor  int
	}{
		{"empty", nil, 0},
		{"negative", []int{-1}, 0},
		{"out of range", []int{2}, 0},
		{"duplicate", []int{0, 0}, 0},
		{"hidden focus", []int{0}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := testModel()
			model.openForm("Test", "", []field{{"One", "", false}, {"Two", "", false}},
				false, func([]string) tea.Cmd { return nil })
			model.form.VisibleFields = func([]field) []int { return test.indices }
			model.form.Cursor = test.cursor
			defer func() {
				if recover() == nil {
					t.Fatal("invalid form projection did not fail its contract")
				}
			}()
			model.form.assertValid()
		})
	}
}

func TestEnterDoesNotSaveAPasswordFile(t *testing.T) {
	model := testModel()
	model.settings.PasswordFile = t.TempDir() + "/password"
	model.savePasswordForm()
	model.form.Fields[0].setText("yes")
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.form == nil {
		t.Fatal("Enter submitted a sensitive confirmation")
	}
	if _, err := os.Stat(model.settings.PasswordFile); !os.IsNotExist(err) {
		t.Fatal("Enter wrote the password file", err)
	}
}

func TestConnectionPasswordKerberosShowsConfigButNotACache(t *testing.T) {
	model := testModel()
	model.connectionForm()
	current := model.form
	current.Fields[connectionDNSAuthField].setText("kerberos")
	visible := map[int]bool{}
	for _, index := range current.fieldIndices() {
		visible[index] = true
	}
	if !visible[connectionKerberosConfigField] || !visible[connectionPasswordField] ||
		visible[connectionCacheField] {
		t.Fatal("password-based Kerberos exposes the wrong credentials/settings")
	}
}
