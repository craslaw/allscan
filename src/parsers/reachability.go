package parsers

import (
	"bytes"
	"encoding/json"
)

// GovulncheckParser parses govulncheck reachability analysis results.
// govulncheck determines whether vulnerable dependency code paths are actually
// called by the application, distinguishing reachable from unreachable findings.
type GovulncheckParser struct{}

// govulncheckMessage is a combined struct for decoding any govulncheck JSON entry.
// govulncheck outputs a stream of JSON objects, each with exactly one top-level key:
// "config", "progress", "osv", "finding", or "SBOM". This struct captures the
// fields we need from osv and finding entries.
type govulncheckMessage struct {
	OSV *struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	} `json:"osv"`
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []struct {
			Position *struct {
				Filename string `json:"filename"`
				Line     int    `json:"line"`
				Col      int    `json:"col"`
			} `json:"position"`
		} `json:"trace"`
	} `json:"finding"`
}

func (p *GovulncheckParser) Name() string { return "govulncheck" }
func (p *GovulncheckParser) Type() string { return "Reachability" }
func (p *GovulncheckParser) Icon() string { return "🔬" }

func (p *GovulncheckParser) Parse(data []byte) (FindingSummary, error) {
	var summary FindingSummary

	// Track reachability per OSV ID (true = reachable, false = unreachable only)
	osvReachable := make(map[string]bool)

	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var msg govulncheckMessage
		if err := dec.Decode(&msg); err != nil {
			break
		}

		if msg.Finding == nil || msg.Finding.OSV == "" {
			continue
		}

		osvID := msg.Finding.OSV
		reachable := isTraceReachable(msg.Finding.Trace)

		// If any trace for this OSV is reachable, mark it reachable
		if reachable {
			osvReachable[osvID] = true
		} else if _, exists := osvReachable[osvID]; !exists {
			osvReachable[osvID] = false
		}
	}

	// Count: Critical = reachable, Info = unreachable
	for _, reachable := range osvReachable {
		summary.Total++
		if reachable {
			summary.Critical++
		} else {
			summary.Info++
		}
	}

	return summary, nil
}

// isTraceReachable returns true if any frame in the trace has a non-nil position
// (indicating source code in the user's project calls the vulnerable function).
func isTraceReachable(trace []struct {
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Col      int    `json:"col"`
	} `json:"position"`
}) bool {
	for _, frame := range trace {
		if frame.Position != nil {
			return true
		}
	}
	return false
}

// Verify GovulncheckParser implements SCAParser
var _ SCAParser = (*GovulncheckParser)(nil)

// ============================================================================
// Reachability Index — cross-reference govulncheck data with SCA scanners
// ============================================================================

// ReachabilityIndex maps vulnerability IDs (GO-xxxx, CVE-xxxx, GHSA-xxxx)
// to their reachability status (true = reachable, false = unreachable).
type ReachabilityIndex map[string]bool

// ReachabilityBreakdown holds counts of reachable, unreachable, and unknown findings.
type ReachabilityBreakdown struct {
	Reachable   int
	Unreachable int
	Unknown     int
}

// BuildReachabilityIndex parses govulncheck JSON output and builds an index
// mapping all vulnerability IDs (GO-xxxx + CVE/GHSA aliases) to reachability status.
func BuildReachabilityIndex(data []byte) ReachabilityIndex {
	// First pass: build osv ID → reachability from finding entries
	osvReachable := make(map[string]bool)
	// Also collect alias mappings from osv entries
	aliasMap := make(map[string][]string) // GO-ID → [CVE-xxx, GHSA-xxx, ...]

	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var msg govulncheckMessage
		if err := dec.Decode(&msg); err != nil {
			break
		}

		// Collect aliases from osv entries
		if msg.OSV != nil && msg.OSV.ID != "" {
			aliasMap[msg.OSV.ID] = msg.OSV.Aliases
		}

		// Collect reachability from finding entries
		if msg.Finding != nil && msg.Finding.OSV != "" {
			osvID := msg.Finding.OSV
			reachable := isTraceReachable(msg.Finding.Trace)

			if reachable {
				osvReachable[osvID] = true
			} else if _, exists := osvReachable[osvID]; !exists {
				osvReachable[osvID] = false
			}
		}
	}

	// Build the index: map all IDs (GO-xxxx + aliases) to reachability
	idx := make(ReachabilityIndex)
	for osvID, reachable := range osvReachable {
		idx[osvID] = reachable
		for _, alias := range aliasMap[osvID] {
			// If the alias is already mapped as reachable, don't downgrade
			if existing, ok := idx[alias]; ok && existing {
				continue
			}
			idx[alias] = reachable
		}
	}

	return idx
}

// ExpandWithAliasGroups enriches the reachability index using ID alias groups
// (typically from OSV-scanner). For each group, if any ID in the group has a
// known reachability status, that status is propagated to all other IDs in the group.
// Reachable status wins over unreachable when multiple IDs in a group conflict.
func (idx ReachabilityIndex) ExpandWithAliasGroups(groups [][]string) {
	if idx == nil {
		return
	}
	for _, group := range groups {
		// First pass: find if any ID in this group is known
		groupReachable := false
		groupKnown := false
		for _, id := range group {
			if reachable, known := idx[id]; known {
				groupKnown = true
				if reachable {
					groupReachable = true
					break
				}
			}
		}
		if !groupKnown {
			continue
		}
		// Second pass: propagate to all IDs in the group
		for _, id := range group {
			if existing, ok := idx[id]; ok && existing {
				continue // don't downgrade reachable
			}
			idx[id] = groupReachable
		}
	}
}

// Lookup returns the reachability status for a vulnerability ID.
// Returns (reachable, known): known=false if the ID is not in the index.
func (idx ReachabilityIndex) Lookup(vulnID string) (reachable, known bool) {
	if idx == nil {
		return false, false
	}
	reachable, known = idx[vulnID]
	return reachable, known
}
