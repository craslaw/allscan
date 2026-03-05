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

func (p *OSVScannerParser) Name() string { return "osv-scanner" }
func (p *OSVScannerParser) Type() string { return "SCA" }
func (p *OSVScannerParser) Icon() string { return "🔎" }

func (p *OSVScannerParser) Parse(data []byte) (FindingSummary, error) {
	var output osvOutputFull
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	for _, result := range output.Results {
		for _, pkg := range result.Packages {
			vulnMap := buildVulnSeverityMap(pkg.Vulnerabilities)
			for _, group := range pkg.Groups {
				summary.Total++
				switch resolveGroupSeverity(group.MaxSeverity, group.Aliases, vulnMap) {
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

// osvGroup represents a vulnerability group in osv-scanner output.
// ids contains only the primary advisory ID(s); aliases contains all IDs including CVE/GHSA aliases.
type osvGroup struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

// osvVulnerability represents a single vulnerability record embedded in osv-scanner output.
// GHSA-prefixed records typically populate database_specific.severity; GO-prefixed records often do not.
type osvVulnerability struct {
	ID               string `json:"id"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// osvOutputFull is used for extracting vulnerability IDs from osv-scanner JSON output.
type osvOutputFull struct {
	Results []struct {
		Packages []struct {
			Groups          []osvGroup         `json:"groups"`
			Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// buildVulnSeverityMap builds a map from vulnerability ID to normalized severity
// using database_specific.severity from each OSV record. Only stores known severities
// (not "info"), so missing entries signal "no severity data available".
func buildVulnSeverityMap(vulns []osvVulnerability) map[string]string {
	m := make(map[string]string, len(vulns))
	for _, v := range vulns {
		if norm := normalizeSeverity(v.DatabaseSpecific.Severity); norm != "info" {
			m[v.ID] = norm
		}
	}
	return m
}

// severityRank returns a numeric rank for severity comparison (higher = more severe).
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// higherSeverity returns whichever of a or b ranks higher.
func higherSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// resolveGroupSeverity returns the best available severity for a vulnerability group.
// It uses max_severity when it carries a real value, then falls back to the highest
// severity found among the group's aliases in the per-package vulnerability records.
// This handles Go advisories (GO-xxxx) that lack CVSS scores but whose GHSA aliases do not.
func resolveGroupSeverity(maxSeverity string, aliases []string, vulnMap map[string]string) string {
	if norm := normalizeSeverity(maxSeverity); norm != "info" {
		return norm
	}
	best := "info"
	for _, id := range aliases {
		if sev, ok := vulnMap[id]; ok {
			best = higherSeverity(best, sev)
		}
	}
	return best
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
			vulnMap := buildVulnSeverityMap(pkg.Vulnerabilities)
			for _, group := range pkg.Groups {
				findings = append(findings, SCAFinding{
					IDs:      group.IDs,
					Severity: resolveGroupSeverity(group.MaxSeverity, group.Aliases, vulnMap),
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

// ExtractOSVScannerAliasGroups extracts all ID groups from OSV-scanner output.
// Each group maps related vulnerability IDs together (e.g., GO-2024-0001, CVE-2024-1234, GHSA-xxxx).
// This makes OSV-scanner the ideal pivot for cross-referencing, since its groups
// correlate IDs across naming schemes that other scanners use individually.
func ExtractOSVScannerAliasGroups(data []byte) [][]string {
	var output osvOutputFull
	if err := json.Unmarshal(data, &output); err != nil {
		return nil
	}

	var groups [][]string
	for _, result := range output.Results {
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				if len(group.IDs) > 1 {
					groups = append(groups, group.IDs)
				}
			}
		}
	}
	return groups
}

// normalizeSeverity converts a severity string to lowercase canonical form.
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}
