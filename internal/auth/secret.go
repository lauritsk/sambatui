package auth

import (
	"fmt"
	"io"
)

// fmt's invalid-verb (%p) fallback can bypass Formatter and reflect through
// unexported fields. Keep immutable plaintext behind a pointer, not inline.
type (
	Secret      struct{ value *secretValue }
	secretValue struct{ plaintext string }
)

func NewSecret(value string) Secret {
	if value == "" {
		return Secret{}
	}
	return Secret{&secretValue{value}}
}

func (s Secret) Reveal() string {
	if s.value == nil {
		return ""
	}
	return s.value.plaintext
}
func (Secret) String() string                    { return "[redacted]" }
func (Secret) GoString() string                  { return "[redacted]" }
func (Secret) Format(state fmt.State, verb rune) { io.WriteString(state, "[redacted]") }
func (Secret) MarshalJSON() ([]byte, error)      { return []byte(`"[redacted]"`), nil }
