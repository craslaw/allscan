package parsers

import (
	"bytes"
	"encoding/json"
)

// ============================================================================
// TruffleHog Parser - Secret Detection Scanner
// ============================================================================

// TrufflehogParser parses TruffleHog secret detection results.
// TruffleHog outputs NDJSON (one JSON object per line) to stdout.
// Verified secrets are mapped to Critical severity, unverified to Medium.
type TrufflehogParser struct{}

type trufflehogFinding struct {
	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
}

func (p *TrufflehogParser) Name() string { return "trufflehog" }
func (p *TrufflehogParser) Type() string { return "Secrets" }
func (p *TrufflehogParser) Icon() string { return "🔑" }

func (p *TrufflehogParser) Parse(data []byte) (FindingSummary, error) {
	var summary FindingSummary

	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var finding trufflehogFinding
		if err := dec.Decode(&finding); err != nil {
			return summary, err
		}
		summary.Total++
		if finding.Verified {
			summary.Critical++
		} else {
			summary.Medium++
		}
	}

	return summary, nil
}

// Verify TrufflehogParser implements SecretsParser
var _ SecretsParser = (*TrufflehogParser)(nil)
