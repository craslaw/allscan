package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
)

// GovulncheckParser parses govulncheck reachability analysis results.
// govulncheck determines whether vulnerable dependency code paths are actually
// called by the application, distinguishing reachable from unreachable findings.
type GovulncheckParser struct{}

// govulncheckFinding represents a single finding message from govulncheck NDJSON output.
// Each line has one top-level key: "config", "progress", "osv", or "finding".
type govulncheckFinding struct {
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

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var msg govulncheckFinding
		if err := json.Unmarshal(line, &msg); err != nil {
			continue // skip non-JSON lines (progress messages, etc.)
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

// govulncheckOSV parses the osv entry from govulncheck NDJSON to extract
// the vulnerability ID and its aliases (CVE/GHSA mappings).
type govulncheckOSV struct {
	OSV *struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	} `json:"osv"`
}

// BuildReachabilityIndex parses govulncheck NDJSON output and builds an index
// mapping all vulnerability IDs (GO-xxxx + CVE/GHSA aliases) to reachability status.
func BuildReachabilityIndex(data []byte) ReachabilityIndex {
	// First pass: build osv ID → reachability from finding entries
	osvReachable := make(map[string]bool)
	// Also collect alias mappings from osv entries
	aliasMap := make(map[string][]string) // GO-ID → [CVE-xxx, GHSA-xxx, ...]

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		// Try parsing as osv entry (for aliases)
		var osvMsg govulncheckOSV
		if err := json.Unmarshal(line, &osvMsg); err == nil && osvMsg.OSV != nil && osvMsg.OSV.ID != "" {
			aliasMap[osvMsg.OSV.ID] = osvMsg.OSV.Aliases
		}

		// Try parsing as finding entry (for reachability)
		var findingMsg govulncheckFinding
		if err := json.Unmarshal(line, &findingMsg); err != nil {
			continue
		}
		if findingMsg.Finding == nil || findingMsg.Finding.OSV == "" {
			continue
		}

		osvID := findingMsg.Finding.OSV
		reachable := isTraceReachable(findingMsg.Finding.Trace)

		if reachable {
			osvReachable[osvID] = true
		} else if _, exists := osvReachable[osvID]; !exists {
			osvReachable[osvID] = false
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

// Lookup returns the reachability status for a vulnerability ID.
// Returns (reachable, known): known=false if the ID is not in the index.
func (idx ReachabilityIndex) Lookup(vulnID string) (reachable, known bool) {
	if idx == nil {
		return false, false
	}
	reachable, known = idx[vulnID]
	return reachable, known
}
