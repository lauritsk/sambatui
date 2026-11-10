package backend

import (
	"strings"
	"testing"

	"github.com/lauritsk/sambatui/internal/config"
)

func TestPlanBudgetBeforeClonePreviewAndDispatch(t *testing.T) {
	action := Action{Kind: "dns_add", Zone: "lab.invalid", Name: "x", Type: "A", Value: "192.0.2.1"}
	base := len(action.Kind) + len(action.Zone) + len(action.Name) + len(action.Type) + len(action.Value)
	for _, extra := range []int{0, 1} {
		plan := Plan{
			Title: strings.Repeat("x", planBytesMax-base+extra), Actions: []Action{action},
		}
		err := plan.Validate(config.Defaults())
		if extra == 0 {
			if err != nil || plan.Clone().Title != plan.Title || plan.Preview() == "" {
				t.Fatal("exact plan budget rejected", err)
			}
		} else {
			if err == nil {
				t.Fatal("unbounded plan accepted")
			}
			for _, operation := range []func(){
				func() { plan.Clone() },
				func() { plan.Preview() },
			} {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("unchecked allocation boundary accepted an oversized plan")
						}
					}()
					operation()
				}()
			}
		}
	}
}

func TestInspectionReportBudgetIsAtomic(t *testing.T) {
	report := &inspectionReport{}
	if _, err := report.Write([]byte(strings.Repeat("x", reportBytesMax))); err != nil {
		t.Fatal(err)
	}
	if _, err := report.Write([]byte("y")); err == nil {
		t.Fatal("unbounded inspection report accepted")
	}
	if report.text.Len() != reportBytesMax {
		t.Fatal("rejected report was partially appended")
	}
}
