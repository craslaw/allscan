package parsers

import (
	"encoding/json"
)

// ============================================================================
// Gitleaks Parser - Secret Detection Scanner
// ============================================================================

// GitleaksParser parses Gitleaks secret detection results.
// Gitleaks detects hardcoded secrets like passwords, API keys, and tokens.
type GitleaksParser struct{}

type gitleaksOutput []struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
}

func (p *GitleaksParser) Name() string { return "gitleaks" }
func (p *GitleaksParser) Type() string { return "Secrets" }
func (p *GitleaksParser) Icon() string { return "🔑" }

func (p *GitleaksParser) Parse(data []byte) (FindingSummary, error) {
	var output gitleaksOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	summary.Total = len(output)
	summary.High = len(output) // Treat all secrets as high severity

	return summary, nil
}

// Verify GitleaksParser implements SecretsParser
var _ SecretsParser = (*GitleaksParser)(nil)
