package tui

import (
	"errors"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/lauritsk/sambatui/internal/invariant"
)

// Reject oversized previews; never truncate a write confirmation.
const viewTextBytesMax = 16 << 20

type textPage struct {
	lines               []string
	startRow, totalRows int
}

func validateViewText(text string) error {
	if len(text) > viewTextBytesMax {
		return errors.New("preview exceeds 16 MiB; refine the target before reviewing")
	}
	return nil
}

// Retain the requested page and the tail to clamp stale offsets without a second reflow.
func wrappedPage(text string, width, offset, height int) textPage {
	invariant.Require(len(text) <= viewTextBytesMax, "unvalidated preview text")
	invariant.Require(width > 0 && width <= terminalColumnsMax, "invalid preview width")
	invariant.Require(height > 0 && height <= terminalRowsMax, "invalid preview height")
	invariant.Require(offset >= 0, "negative preview offset")
	page := textPage{lines: make([]string, height)}
	tail := make([]string, height)
	for line := range strings.SplitSeq(text, "\n") {
		wrapped := ansi.Wrap(Literal(line), width, " ")
		for row := range strings.SplitSeq(wrapped, "\n") {
			if page.totalRows >= offset && page.totalRows-offset < height {
				page.lines[page.totalRows-offset] = row
			}
			tail[page.totalRows%height] = row
			page.totalRows++
		}
	}
	page.startRow = min(offset, max(0, page.totalRows-height))
	if page.startRow != offset {
		for index := 0; index < min(height, page.totalRows); index++ {
			page.lines[index] = tail[(page.startRow+index)%height]
		}
	}
	// Do not let a visible row retain a multi-megabyte wrapped logical line.
	for index := range page.lines {
		page.lines[index] = strings.Clone(page.lines[index])
	}
	invariant.Require(page.totalRows > 0, "preview must contain at least one logical row")
	invariant.Require(page.totalRows <= 6*len(text)+1, "preview expansion exceeds budget")
	invariant.Require(len(page.lines) == height, "preview page changed its viewport")
	return page
}
