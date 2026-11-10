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
	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/invariant"
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
	// Form shape is a programmer invariant, not untrusted input. A malformed
	// form must fail here, before cursor arithmetic can divide by zero.
	if len(fields) == 0 {
		panic("form requires at least one field")
	}
	invariant.Require(len(fields) <= formFieldsMax, "form has too many fields")
	invariant.Require(accept != nil, "form requires an accept callback")
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
	model.status = "Tab/Enter next · Ctrl+S submit · Ctrl+U clear field · Esc cancel"
}

func (model *Model) closeForm() {
	if model.form != nil && model.form.Write && model.flow != nil {
		model.flow.Abort()
		model.flow = nil
	}
	model.form = nil
	model.status = "Form cancelled; no write dispatched."
}

const formFieldBytesMax = 1 << 20

func (model *Model) updateForm(message tea.KeyMsg) tea.Cmd {
	currentForm := model.form
	currentForm.assertValid()
	switch message.String() {
	case "pgdown":
		currentForm.ContextOffset = min(
			len(currentForm.Context), currentForm.ContextOffset+max(1, (model.height-12)/2),
		)
		return nil
	case "pgup":
		currentForm.ContextOffset = max(0, currentForm.ContextOffset-max(1, (model.height-12)/2))
		return nil
	case "esc":
		model.closeForm()
		return nil
	case "ctrl+s":
		values := make([]string, 0, len(currentForm.Fields))
		for _, currentField := range currentForm.Fields {
			values = append(values, currentField.text())
		}
		model.form = nil
		return currentForm.Accept(values)
	case "tab", "enter":
		currentForm.Cursor = (currentForm.Cursor + 1) % len(currentForm.Fields)
	case "shift+tab":
		count := len(currentForm.Fields)
		currentForm.Cursor = (currentForm.Cursor + count - 1) % count
	case "ctrl+u":
		currentForm.Fields[currentForm.Cursor].setText("")
	case "backspace", "ctrl+h":
		characters := []rune(currentForm.Fields[currentForm.Cursor].text())
		if len(characters) > 0 {
			currentForm.Fields[currentForm.Cursor].setText(string(characters[:len(characters)-1]))
		}
	default:
		if message.Type == tea.KeyRunes {
			value, err := formInput(currentForm.Fields[currentForm.Cursor], message.Runes)
			if err != nil {
				model.error(err)
				return nil
			}
			currentForm.Fields[currentForm.Cursor].setText(value)
		}
	}
	return nil
}

// Batch each input message into one copy. Repeated string concatenation made
// a large paste quadratic, and a partial paste must never change a confirmation.
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

func (model *Model) formView() string {
	currentForm := model.form
	out := Literal(currentForm.Title) + "\n"
	wrapped := []string{}
	for _, line := range strings.Split(currentForm.Context, "\n") {
		wrapped = append(wrapped, ansi.Wrap(Literal(line), max(20, model.width-2), " "))
	}
	lines := strings.Split(strings.Join(wrapped, "\n"), "\n")
	page := max(2, model.height-14)
	offset := min(currentForm.ContextOffset, max(0, len(lines)-page))
	for _, line := range lines[offset:min(len(lines), offset+page)] {
		out += line + "\n"
	}
	if len(lines) > page {
		out += fmt.Sprintf(
			"Context lines %d–%d/%d · PgUp/PgDn scroll complete preview\n",
			offset+1,
			min(len(lines), offset+page),
			len(lines),
		)
	}
	start := max(0, currentForm.Cursor-5)
	for index := start; index < min(len(currentForm.Fields), start+6); index++ {
		field := currentForm.Fields[index]
		mark := "  "
		if index == currentForm.Cursor {
			mark = "> "
		}
		value := Literal(field.text())
		if field.Secret {
			value = strings.Repeat("•", len([]rune(field.text())))
		}
		out += mark + Literal(field.Label) + ": " + value + "\n"
	}
	return out + "Tab/Enter next · Ctrl+S submit · Ctrl+U clear · Esc cancel"
}
