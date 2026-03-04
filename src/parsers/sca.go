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
// SCA Finding Extraction & Reachability Cross-Reference
// ============================================================================

// SCAFinding represents a single SCA finding with its vulnerability IDs and severity.
type SCAFinding struct {
	IDs      []string // All vulnerability IDs (CVE, GHSA, etc.)
	Severity string   // Normalized severity: critical, high, medium, low, or info
}

// EnrichedSummary extends FindingSummary with per-severity reachable counts
// and an overall reachability breakdown.
type EnrichedSummary struct {
	FindingSummary
	CriticalReachable int
	HighReachable     int
	MediumReachable   int
	LowReachable      int
	InfoReachable     int
	Breakdown         ReachabilityBreakdown
}

// grypeOutputFull is used for extracting vulnerability IDs from grype JSON output.
type grypeOutputFull struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

// ExtractGrypeFindings extracts vulnerability IDs and severities from grype JSON output.
func ExtractGrypeFindings(data []byte) ([]SCAFinding, error) {
	var output grypeOutputFull
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}

	findings := make([]SCAFinding, 0, len(output.Matches))
	for _, match := range output.Matches {
		findings = append(findings, SCAFinding{
			IDs:      []string{match.Vulnerability.ID},
			Severity: normalizeSeverity(match.Vulnerability.Severity),
		})
	}
	return findings, nil
}

// osvOutputFull is used for extracting vulnerability IDs from osv-scanner JSON output.
type osvOutputFull struct {
	Results []struct {
		Packages []struct {
			Groups []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// ExtractOSVScannerFindings extracts vulnerability IDs and severities from osv-scanner JSON output.
func ExtractOSVScannerFindings(data []byte) ([]SCAFinding, error) {
	var output osvOutputFull
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}

	var findings []SCAFinding
	for _, result := range output.Results {
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				findings = append(findings, SCAFinding{
					IDs:      group.IDs,
					Severity: normalizeSeverity(group.MaxSeverity),
				})
			}
		}
	}
	return findings, nil
}

// CrossReferenceReachability cross-references SCA findings with a reachability index
// and returns an enriched summary with per-severity reachable counts.
func CrossReferenceReachability(findings []SCAFinding, idx ReachabilityIndex) EnrichedSummary {
	var enriched EnrichedSummary

	for _, f := range findings {
		enriched.Total++

		// Count by severity
		switch f.Severity {
		case "critical":
			enriched.Critical++
		case "high":
			enriched.High++
		case "medium":
			enriched.Medium++
		case "low":
			enriched.Low++
		default:
			enriched.Info++
		}

		// Look up reachability: if any ID in the finding is known, use that.
		// Reachable wins if any ID is reachable.
		findingReachable := false
		findingKnown := false
		for _, id := range f.IDs {
			reachable, known := idx.Lookup(id)
			if known {
				findingKnown = true
				if reachable {
					findingReachable = true
					break
				}
			}
		}

		if !findingKnown {
			enriched.Breakdown.Unknown++
			continue
		}

		if findingReachable {
			enriched.Breakdown.Reachable++
			switch f.Severity {
			case "critical":
				enriched.CriticalReachable++
			case "high":
				enriched.HighReachable++
			case "medium":
				enriched.MediumReachable++
			case "low":
				enriched.LowReachable++
			default:
				enriched.InfoReachable++
			}
		} else {
			enriched.Breakdown.Unreachable++
		}
	}

	return enriched
}

// normalizeSeverity converts a severity string to lowercase canonical form.
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}
