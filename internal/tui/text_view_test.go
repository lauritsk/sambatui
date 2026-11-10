package tui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestWrappedPageMatchesCompleteProjection(t *testing.T) {
	for _, text := range []string{
		"", "\n", "first\nsecond\nthird\n", strings.Repeat("界é🇪🇪 ", 50),
		"hostile\x1b]52;c;data\a\n" + strings.Repeat("long line ", 100),
	} {
		for _, width := range []int{1, 20, 40, terminalColumnsMax} {
			complete := []string{}
			for line := range strings.SplitSeq(text, "\n") {
				wrapped := ansi.Wrap(Literal(line), width, " ")
				complete = append(complete, strings.Split(wrapped, "\n")...)
			}
			for _, height := range []int{1, 3, terminalRowsMax} {
				for _, offset := range []int{0, 1, len(complete) / 2, len(complete) + 100} {
					page := wrappedPage(text, width, offset, height)
					start := min(offset, max(0, len(complete)-height))
					want := make([]string, height)
					copy(want, complete[start:min(len(complete), start+height)])
					if page.startRow != start || page.totalRows != len(complete) ||
						!reflect.DeepEqual(page.lines, want) {
						t.Fatalf("width=%d height=%d offset=%d: %+v != %q",
							width, height, offset, page, want)
					}
				}
			}
		}
	}
}

func TestWrappedPageRetainsOnlyViewportRows(t *testing.T) {
	text := strings.Repeat("row\n", 100000)
	page := wrappedPage(text, 40, 999999, 3)
	if len(page.lines) != 3 || page.totalRows != 100001 || page.startRow != 99998 {
		t.Fatal("large text did not clamp to a bounded page", page)
	}
	if !reflect.DeepEqual(page.lines, []string{"row", "row", ""}) {
		t.Fatal("tail ring changed row order", page.lines)
	}
}
