package parsers

import (
	"encoding/json"
	"strings"
)

// ============================================================================
// Grype Parser - Anchore Grype SCA Scanner
// ============================================================================

// GrypeParser parses Anchore Grype SCA scan results.
// Grype analyzes container images and filesystems for vulnerabilities.
type GrypeParser struct{}

type grypeOutput struct {
	Matches []struct {
		Vulnerability struct {
			Severity string `json:"severity"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

func (p *GrypeParser) Name() string { return "grype" }
func (p *GrypeParser) Type() string { return "SCA" }
func (p *GrypeParser) Icon() string { return "📦" }

func (p *GrypeParser) Parse(data []byte) (FindingSummary, error) {
	var output grypeOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	for _, match := range output.Matches {
		summary.Total++
		switch strings.ToLower(match.Vulnerability.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
	}

	return summary, nil
}

// Verify GrypeParser implements SCAParser
var _ SCAParser = (*GrypeParser)(nil)

// ============================================================================
// OSV-Scanner Parser - Google OSV Scanner
// ============================================================================

// OSVScannerParser parses Google OSV-Scanner results.
// OSV-Scanner checks dependencies against the Open Source Vulnerabilities database.
type OSVScannerParser struct{}

type osvOutput struct {
	Results []struct {
		Packages []struct {
			Groups []struct {
				MaxSeverity string `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

func (p *OSVScannerParser) Name() string { return "osv-scanner" }
func (p *OSVScannerParser) Type() string { return "SCA" }
func (p *OSVScannerParser) Icon() string { return "🔎" }

func (p *OSVScannerParser) Parse(data []byte) (FindingSummary, error) {
	var output osvOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	for _, result := range output.Results {
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				summary.Total++
				switch strings.ToLower(group.MaxSeverity) {
				case "critical":
					summary.Critical++
				case "high":
					summary.High++
				case "medium":
					summary.Medium++
				case "low":
					summary.Low++
				default:
					summary.Info++
				}
			}
		}
	}

	return summary, nil
}

// Verify OSVScannerParser implements SCAParser
var _ SCAParser = (*OSVScannerParser)(nil)
