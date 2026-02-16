package parsers

import (
	"encoding/json"
	"strings"
)

// ============================================================================
// Gosec Parser - Go Security Checker
// ============================================================================

// GosecParser parses Gosec SAST scan results.
// Gosec inspects Go source code for security problems.
type GosecParser struct{}

type gosecOutput struct {
	Issues []struct {
		Severity string `json:"severity"`
	} `json:"Issues"`
	Stats struct {
		Found int `json:"found"`
	} `json:"Stats"`
}

func (p *GosecParser) Name() string { return "gosec" }
func (p *GosecParser) Type() string { return "SAST" }
func (p *GosecParser) Icon() string { return "🔍" }

func (p *GosecParser) Parse(data []byte) (FindingSummary, error) {
	var output gosecOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	for _, issue := range output.Issues {
		summary.Total++
		switch strings.ToUpper(issue.Severity) {
		case "HIGH":
			summary.High++
		case "MEDIUM":
			summary.Medium++
		case "LOW":
			summary.Low++
		}
	}

	return summary, nil
}

// Verify GosecParser implements SASTParser
var _ SASTParser = (*GosecParser)(nil)
