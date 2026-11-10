package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/auth"
)

func TestErrorRetentionBudgetIncludesRedactionExpansion(t *testing.T) {
	for _, size := range []int{errorTextBytesMax, errorTextBytesMax + 1} {
		model := testModel()
		model.error(errors.New(strings.Repeat("x", size)))
		if len(model.lastError) > errorTextBytesMax {
			t.Fatal("oversize error retained")
		}
		if (model.lastError == strings.Repeat("x", size)) != (size == errorTextBytesMax) {
			t.Fatal("error budget boundary was not enforced")
		}
	}
	model := testModel()
	model.settings.Password = auth.NewSecret("xy")
	model.error(errors.New(strings.Repeat("xy", errorTextBytesMax/2)))
	if strings.Contains(model.lastError, "xy") ||
		!strings.Contains(model.lastError, "Redacted error exceeds") {
		t.Fatal("redaction expansion bypassed the retention budget")
	}
}
