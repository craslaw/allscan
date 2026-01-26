package parsers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ============================================================================
// OpenSSF Scorecard Parser
// ============================================================================

// ScorecardParser parses OpenSSF Scorecard results.
// Scorecard assesses open source project security practices.
type ScorecardParser struct{}

type scorecardOutput struct {
	Date      string  `json:"date"`
	Score     float64 `json:"score"`
	Scorecard struct {
		Version string `json:"version"`
	} `json:"scorecard"`
	Checks []struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Reason string `json:"reason"`
	} `json:"checks"`
}

func (p *ScorecardParser) Name() string { return "scorecard" }
func (p *ScorecardParser) Type() string { return "Scorecard" }
func (p *ScorecardParser) Icon() string { return "🛡️" }

// Parse reads scorecard JSON and returns a summary.
// Scores are mapped: 0-3=Critical, 4-5=High, 6-7=Medium, 8-9=Low, 10=pass (Info)
func (p *ScorecardParser) Parse(data []byte) (FindingSummary, error) {
	var output scorecardOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	for _, check := range output.Checks {
		// Skip checks that returned -1 (inconclusive/not applicable)
		if check.Score < 0 {
			continue
		}
		summary.Total++
		switch {
		case check.Score <= 3:
			summary.Critical++
		case check.Score <= 5:
			summary.High++
		case check.Score <= 7:
			summary.Medium++
		case check.Score <= 9:
			summary.Low++
		default: // score == 10
			summary.Info++
		}
	}

	return summary, nil
}

// Verify ScorecardParser implements ResultParser
var _ ResultParser = (*ScorecardParser)(nil)

// PrintScorecardReport prints a detailed scorecard report to stdout.
// This provides human-readable output beyond the standard summary.
func PrintScorecardReport(outputPath string) error {
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}

	var output scorecardOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}

	// ANSI colors
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		dim    = "\033[2m"
		red    = "\033[31m"
		green  = "\033[32m"
		yellow = "\033[33m"
		cyan   = "\033[36m"
	)

	fmt.Printf("\n%s%s════════════════════════════════════════════════════════════════%s\n", cyan, bold, reset)
	fmt.Printf("%s%s 🛡️  OpenSSF Scorecard Report %s\n", bold, cyan, reset)
	fmt.Printf("%s%s════════════════════════════════════════════════════════════════%s\n", cyan, bold, reset)

	// Overall score with color
	scoreColor := red
	if output.Score >= 7 {
		scoreColor = green
	} else if output.Score >= 4 {
		scoreColor = yellow
	}
	fmt.Printf("\n  %sOverall Score:%s %s%s%.1f / 10%s\n", bold, reset, scoreColor, bold, output.Score, reset)
	fmt.Printf("  %sScorecard Version:%s %s\n", dim, reset, output.Scorecard.Version)

	fmt.Printf("\n  %s%sIndividual Checks:%s\n", bold, cyan, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────────────%s\n", dim, reset)

	for _, check := range output.Checks {
		// Color based on score
		color := red
		icon := "🔴"
		if check.Score < 0 {
			color = dim
			icon = "⚪"
		} else if check.Score >= 8 {
			color = green
			icon = "🟢"
		} else if check.Score >= 5 {
			color = yellow
			icon = "🟡"
		} else if check.Score >= 3 {
			color = yellow
			icon = "🟠"
		}

		scoreStr := fmt.Sprintf("%2d", check.Score)
		if check.Score < 0 {
			scoreStr = " ?"
		}

		fmt.Printf("  %s %s%-25s%s %s%s/10%s  %s%s%s\n",
			icon,
			bold, check.Name, reset,
			color, scoreStr, reset,
			dim, truncateReason(check.Reason, 40), reset)
	}

	fmt.Printf("  %s────────────────────────────────────────────────────────────%s\n\n", dim, reset)

	return nil
}

// truncateReason shortens the reason string for display
func truncateReason(reason string, maxLen int) string {
	reason = strings.Split(reason, "\n")[0] // First line only
	if len(reason) > maxLen {
		return reason[:maxLen-3] + "..."
	}
	return reason
}
