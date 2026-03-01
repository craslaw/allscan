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
