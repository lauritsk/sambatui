package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/invariant"
	"github.com/lauritsk/sambatui/internal/lifecycle"
)

type field struct {
	Label  string
	Value  any // string, or auth.Secret for a password; never plaintext secret storage.
	Secret bool
}

func (currentField field) text() string {
	switch value := currentField.Value.(type) {
	case string:
		return value
	case auth.Secret:
		return value.Reveal()
	default:
		panic("invalid form field value type")
	}
}

func (currentField *field) setText(text string) {
	if currentField.Secret {
		currentField.Value = auth.NewSecret(text)
	} else {
		currentField.Value = text
	}
}

func (currentField field) String() string {
	if currentField.Secret {
		return currentField.Label + ": [redacted]"
	}
	return currentField.Label + ": " + Literal(currentField.text())
}

func (currentField field) GoString() string {
	return currentField.String()
}

func (currentField field) Format(state fmt.State, verb rune) {
	io.WriteString(state, currentField.String())
}

func (currentField field) MarshalJSON() ([]byte, error) {
	return json.Marshal(currentField.String())
}

type form struct {
	Title, Context string
	Fields         []field
	Cursor         int
	ContextOffset  int
	Accept         func([]string) tea.Cmd
	Write          bool
	EnterSubmits   bool
	ShowScope      bool
	VisibleFields  func([]field) []int
	Choices        map[int][]string
	Items          []string
	ItemLabels     map[string]string
	ItemCursor     int
	Owner          *lifecycle.Flow
	Carets         map[int]int
}

func newSecret(text string) auth.Secret {
	return auth.NewSecret(text)
}

func (model *Model) openForm(
	title, context string,
	fields []field,
	write bool,
	accept func([]string) tea.Cmd,
) {
	if len(fields) == 0 {
		panic("form requires at least one field")
	}
	invariant.Require(len(fields) <= formFieldsMax, "form has too many fields")
	invariant.Require(accept != nil, "form requires an accept callback")
	if err := validateViewText(context); err != nil {
		model.rejectFlow(err)
		return
	}
	for index := range fields {
		if len(fields[index].text()) > formFieldBytesMax {
			model.rejectFlow(errors.New("form field exceeds 1 MiB; refine the target"))
			return
		}
		if _, ok := fields[index].Value.(auth.Secret); ok {
			fields[index].Secret = true
		}
		if fields[index].Secret {
			fields[index].setText(fields[index].text())
		}
	}
	submit := func(values []string) tea.Cmd {
		invariant.Require(len(values) == len(fields), "submitted form field count changed")
		return accept(values)
	}
	model.form = &form{Title: title, Context: context, Fields: fields, Write: write, Accept: submit}
	if write {
		invariant.Require(model.flow != nil, "write form requires a reservation")
		model.form.Owner = model.flow
	}
	model.status = ""
}

func (model *Model) closeForm() {
	if model.form != nil && model.form.Write && model.flow != nil {
		model.flow.Abort()
		model.flow = nil
	}
	model.form = nil
	model.status = ""
}

const formFieldBytesMax = 1 << 20

func (model *Model) updateForm(message tea.KeyMsg) tea.Cmd {
	if model.form.Items != nil {
		return model.updatePicker(message)
	}
	return model.updateFormField(message)
}

func (model *Model) updateFormField(message tea.KeyMsg) tea.Cmd {
	currentForm := model.form
	currentForm.assertValid()
	indices := currentForm.fieldIndices()
	position := currentForm.cursorPosition(indices)
	switch message.String() {
	case "pgdown", "pgup":
		height := model.bodyHeight()
		width, _ := model.modalContentSize(height)
		_, contextHeight := formGeometry(currentForm, width, height)
		page := wrappedPage(currentForm.Context, width, 0, max(1, contextHeight))
		last := max(0, page.totalRows-max(1, contextHeight))
		delta := max(1, contextHeight)
		if message.String() == "pgup" {
			delta = -delta
		}
		currentForm.ContextOffset = max(0, min(last, min(currentForm.ContextOffset, last)+delta))
		return nil
	case "esc":
		model.closeForm()
		return nil
	case "ctrl+s":
		return model.submitForm()
	case "enter":
		if currentForm.EnterSubmits {
			return model.submitForm()
		}
		fallthrough
	case "tab", "down":
		currentForm.Cursor = indices[(position+1)%len(indices)]
	case "shift+tab", "up":
		currentForm.Cursor = indices[(position+len(indices)-1)%len(indices)]
	default:
		if len(currentForm.Choices[currentForm.Cursor]) > 0 {
			currentForm.updateChoice(message)
		} else {
			model.editFormField(message)
		}
	}
	return nil
}

func (model *Model) submitForm() tea.Cmd {
	current := model.form
	current.assertValid()
	width, _ := model.modalContentSize(model.bodyHeight())
	_, contextHeight := formGeometry(current, width, model.bodyHeight())
	if current.Context != "" && (contextHeight == 0 || model.width < 20) {
		model.status = "Resize to review the preview"
		return nil
	}
	values := make([]string, len(current.Fields))
	for index, field := range current.Fields {
		values[index] = field.text()
	}
	generation, readID := model.state.Snapshot().Generation, model.readID
	model.form = nil
	model.submitting = current
	defer func() { model.submitting = nil }()
	command := current.Accept(values)
	if command == nil && model.form == nil && model.status != "" &&
		model.status == model.lastError && model.state.Current(generation) &&
		model.readID == readID {
		if !current.Write || current.Owner == model.flow {
			model.form = current
			model.errorUnread = false
		}
	}
	return command
}

// Reject pastes atomically; never partially change a confirmation.
func formInput(current field, input []rune) (string, error) {
	if len(input) > formFieldBytesMax {
		return "", errors.New("form input exceeds 1 MiB")
	}
	if len(current.text()) > formFieldBytesMax {
		return "", errors.New("existing form value exceeds 1 MiB")
	}
	var value strings.Builder
	value.Grow(min(formFieldBytesMax, len(current.text())+len(input)))
	value.WriteString(current.text())
	for _, character := range input {
		if current.Secret || (!unicode.IsControl(character) && !unicode.Is(unicode.Cf, character)) {
			sizeBytes := utf8.RuneLen(character)
			if sizeBytes < 0 {
				sizeBytes = utf8.RuneLen(utf8.RuneError)
			}
			if sizeBytes > formFieldBytesMax-value.Len() {
				return "", errors.New("form input exceeds 1 MiB")
			}
			value.WriteRune(character)
		}
	}
	return value.String(), nil
}
