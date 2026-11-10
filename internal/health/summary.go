package health

import "fmt"

func Rank(severity string) int {
	switch severity {
	case "error":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// Dashboard keeps unsuccessful/limited checks separate from clean results.
// completed contains only checks for which all required evidence was read.
func Dashboard(rows []Finding, completed map[int]bool) []Finding {
	summaries := make([]Finding, 0, 7+len(rows))
	for check := 1; check <= 7; check++ {
		counts := map[string]int{}
		worst := "info"
		total := 0
		for _, r := range rows {
			if r.Check == check {
				total++
				counts[r.Severity]++
				if Rank(r.Severity) < Rank(worst) {
					worst = r.Severity
				}
			}
		}
		status := "completed"
		if !completed[check] {
			status = "failed, incomplete or limited; do not conclude clean"
			worst = "error"
		}
		summaries = append(summaries, Finding{Check: check, Severity: worst, Object: Labels[check-1], Finding: "Check summary: " + status, Evidence: fmt.Sprintf("%d findings; high=%d medium=%d low=%d", total, counts["high"], counts["medium"], counts["low"])})
	}
	return append(summaries, rows...)
}
