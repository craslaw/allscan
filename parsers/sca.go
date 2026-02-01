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

// ============================================================================
// Socket Parser - Socket.dev Supply Chain Security Scanner
// ============================================================================

// SocketParser parses Socket.dev CLI scan results.
// Socket analyzes dependencies for supply chain risks, CVEs, and security issues.
type SocketParser struct{}

// socketOutput represents the Socket CLI JSON output structure
type socketOutput struct {
	// Socket outputs alerts/issues with severity levels
	Alerts []struct {
		Severity string `json:"severity"`
		Type     string `json:"type"`
	} `json:"alerts"`
	// Alternative structure: issues array
	Issues []struct {
		Severity string `json:"severity"`
		Type     string `json:"type"`
	} `json:"issues"`
	// Alternative structure: findings array (common format)
	Findings []struct {
		Severity string `json:"severity"`
	} `json:"findings"`
	// Alternative: results with nested vulnerabilities
	Results []struct {
		Alerts []struct {
			Severity string `json:"severity"`
		} `json:"alerts"`
	} `json:"results"`
}

func (p *SocketParser) Name() string { return "socket" }
func (p *SocketParser) Type() string { return "SCA" }
func (p *SocketParser) Icon() string { return "🔌" }

func (p *SocketParser) Parse(data []byte) (FindingSummary, error) {
	var output socketOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	// Count from alerts array
	for _, alert := range output.Alerts {
		summary.Total++
		countSeverity(&summary, alert.Severity)
	}

	// Count from issues array
	for _, issue := range output.Issues {
		summary.Total++
		countSeverity(&summary, issue.Severity)
	}

	// Count from findings array
	for _, finding := range output.Findings {
		summary.Total++
		countSeverity(&summary, finding.Severity)
	}

	// Count from nested results
	for _, result := range output.Results {
		for _, alert := range result.Alerts {
			summary.Total++
			countSeverity(&summary, alert.Severity)
		}
	}

	return summary, nil
}

// countSeverity increments the appropriate severity counter
func countSeverity(summary *FindingSummary, severity string) {
	switch strings.ToLower(severity) {
	case "critical":
		summary.Critical++
	case "high":
		summary.High++
	case "medium", "moderate":
		summary.Medium++
	case "low":
		summary.Low++
	default:
		summary.Info++
	}
}

// Verify SocketParser implements SCAParser
var _ SCAParser = (*SocketParser)(nil)
