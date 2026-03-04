package parsers

import "testing"

func TestGrypeParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty matches",
			input: `{"matches": []}`,
			want:  FindingSummary{},
		},
		{
			name: "single critical finding",
			input: `{"matches": [
				{"vulnerability": {"severity": "Critical"}}
			]}`,
			want: FindingSummary{Critical: 1, Total: 1},
		},
		{
			name: "mixed severities",
			input: `{"matches": [
				{"vulnerability": {"severity": "Critical"}},
				{"vulnerability": {"severity": "High"}},
				{"vulnerability": {"severity": "Medium"}},
				{"vulnerability": {"severity": "Low"}},
				{"vulnerability": {"severity": "Negligible"}}
			]}`,
			want: FindingSummary{Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1, Total: 5},
		},
		{
			name: "case insensitive severity",
			input: `{"matches": [
				{"vulnerability": {"severity": "CRITICAL"}},
				{"vulnerability": {"severity": "high"}},
				{"vulnerability": {"severity": "mEdIuM"}}
			]}`,
			want: FindingSummary{Critical: 1, High: 1, Medium: 1, Total: 3},
		},
		{
			name: "unknown severity maps to info",
			input: `{"matches": [
				{"vulnerability": {"severity": "Unknown"}},
				{"vulnerability": {"severity": ""}}
			]}`,
			want: FindingSummary{Info: 2, Total: 2},
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: true,
		},
		{
			name:  "no matches key",
			input: `{}`,
			want:  FindingSummary{},
		},
	}

	parser := &GrypeParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.Parse([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Parse() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractGrypeFindings(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantFirst SCAFinding
		wantErr   bool
	}{
		{
			name:      "empty matches",
			input:     `{"matches": []}`,
			wantCount: 0,
		},
		{
			name: "extracts ID and severity",
			input: `{"matches": [
				{"vulnerability": {"id": "CVE-2024-1234", "severity": "Critical"}},
				{"vulnerability": {"id": "CVE-2024-5678", "severity": "High"}}
			]}`,
			wantCount: 2,
			wantFirst: SCAFinding{IDs: []string{"CVE-2024-1234"}, Severity: "critical"},
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractGrypeFindings([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractGrypeFindings() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != tt.wantCount {
				t.Fatalf("got %d findings, want %d", len(got), tt.wantCount)
			}
			if tt.wantCount > 0 {
				if got[0].IDs[0] != tt.wantFirst.IDs[0] {
					t.Errorf("first ID = %q, want %q", got[0].IDs[0], tt.wantFirst.IDs[0])
				}
				if got[0].Severity != tt.wantFirst.Severity {
					t.Errorf("first Severity = %q, want %q", got[0].Severity, tt.wantFirst.Severity)
				}
			}
		})
	}
}

func TestExtractOSVScannerFindings(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantFirst SCAFinding
		wantErr   bool
	}{
		{
			name:      "empty results",
			input:     `{"results": []}`,
			wantCount: 0,
		},
		{
			name: "extracts IDs and severity from groups",
			input: `{"results": [{"packages": [{"groups": [
				{"ids": ["CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"], "max_severity": "HIGH"}
			]}]}]}`,
			wantCount: 1,
			wantFirst: SCAFinding{IDs: []string{"CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"}, Severity: "high"},
		},
		{
			name:    "invalid JSON",
			input:   `{invalid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractOSVScannerFindings([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractOSVScannerFindings() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != tt.wantCount {
				t.Fatalf("got %d findings, want %d", len(got), tt.wantCount)
			}
			if tt.wantCount > 0 {
				if len(got[0].IDs) != len(tt.wantFirst.IDs) {
					t.Fatalf("first IDs count = %d, want %d", len(got[0].IDs), len(tt.wantFirst.IDs))
				}
				for i, id := range tt.wantFirst.IDs {
					if got[0].IDs[i] != id {
						t.Errorf("first IDs[%d] = %q, want %q", i, got[0].IDs[i], id)
					}
				}
				if got[0].Severity != tt.wantFirst.Severity {
					t.Errorf("first Severity = %q, want %q", got[0].Severity, tt.wantFirst.Severity)
				}
			}
		})
	}
}

func TestCrossReferenceReachability(t *testing.T) {
	tests := []struct {
		name     string
		findings []SCAFinding
		index    ReachabilityIndex
		want     EnrichedSummary
	}{
		{
			name:     "nil index makes all unknown",
			findings: []SCAFinding{{IDs: []string{"CVE-2024-1234"}, Severity: "critical"}},
			index:    nil,
			want: EnrichedSummary{
				FindingSummary: FindingSummary{Critical: 1, Total: 1},
				Breakdown:      ReachabilityBreakdown{Unknown: 1},
			},
		},
		{
			name: "mixed reachability",
			findings: []SCAFinding{
				{IDs: []string{"CVE-2024-1111"}, Severity: "critical"},
				{IDs: []string{"CVE-2024-2222"}, Severity: "high"},
				{IDs: []string{"CVE-2024-3333"}, Severity: "medium"},
			},
			index: ReachabilityIndex{
				"CVE-2024-1111": true,
				"CVE-2024-2222": false,
			},
			want: EnrichedSummary{
				FindingSummary:    FindingSummary{Critical: 1, High: 1, Medium: 1, Total: 3},
				CriticalReachable: 1,
				Breakdown:         ReachabilityBreakdown{Reachable: 1, Unreachable: 1, Unknown: 1},
			},
		},
		{
			name: "multi-ID group with reachable alias",
			findings: []SCAFinding{
				{IDs: []string{"GHSA-xxxx-yyyy-zzzz", "CVE-2024-1234"}, Severity: "high"},
			},
			index: ReachabilityIndex{
				"CVE-2024-1234": true,
			},
			want: EnrichedSummary{
				FindingSummary: FindingSummary{High: 1, Total: 1},
				HighReachable:  1,
				Breakdown:      ReachabilityBreakdown{Reachable: 1},
			},
		},
		{
			name: "per-severity reachable counts",
			findings: []SCAFinding{
				{IDs: []string{"CVE-1"}, Severity: "critical"},
				{IDs: []string{"CVE-2"}, Severity: "high"},
				{IDs: []string{"CVE-3"}, Severity: "medium"},
				{IDs: []string{"CVE-4"}, Severity: "low"},
				{IDs: []string{"CVE-5"}, Severity: "info"},
			},
			index: ReachabilityIndex{
				"CVE-1": true,
				"CVE-2": true,
				"CVE-3": true,
				"CVE-4": true,
				"CVE-5": true,
			},
			want: EnrichedSummary{
				FindingSummary:    FindingSummary{Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1, Total: 5},
				CriticalReachable: 1,
				HighReachable:     1,
				MediumReachable:   1,
				LowReachable:      1,
				InfoReachable:     1,
				Breakdown:         ReachabilityBreakdown{Reachable: 5},
			},
		},
		{
			name:     "empty findings",
			findings: []SCAFinding{},
			index:    ReachabilityIndex{"CVE-1": true},
			want:     EnrichedSummary{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CrossReferenceReachability(tt.findings, tt.index)
			if got != tt.want {
				t.Errorf("CrossReferenceReachability() =\n  %+v\nwant:\n  %+v", got, tt.want)
			}
		})
	}
}

func TestOSVScannerParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty results",
			input: `{"results": []}`,
			want:  FindingSummary{},
		},
		{
			name: "single finding",
			input: `{"results": [{"packages": [{"groups": [{"max_severity": "HIGH"}]}]}]}`,
			want:  FindingSummary{High: 1, Total: 1},
		},
		{
			name: "nested structure with mixed severities",
			input: `{"results": [
				{"packages": [
					{"groups": [
						{"max_severity": "CRITICAL"},
						{"max_severity": "HIGH"}
					]},
					{"groups": [
						{"max_severity": "LOW"}
					]}
				]},
				{"packages": [
					{"groups": [
						{"max_severity": "MEDIUM"}
					]}
				]}
			]}`,
			want: FindingSummary{Critical: 1, High: 1, Medium: 1, Low: 1, Total: 4},
		},
		{
			name: "case insensitive severity",
			input: `{"results": [{"packages": [{"groups": [
				{"max_severity": "critical"},
				{"max_severity": "Critical"}
			]}]}]}`,
			want: FindingSummary{Critical: 2, Total: 2},
		},
		{
			name: "unknown severity maps to info",
			input: `{"results": [{"packages": [{"groups": [
				{"max_severity": "UNKNOWN"}
			]}]}]}`,
			want: FindingSummary{Info: 1, Total: 1},
		},
		{
			name:    "invalid JSON",
			input:   `{invalid`,
			wantErr: true,
		},
		{
			name:  "empty packages",
			input: `{"results": [{"packages": []}]}`,
			want:  FindingSummary{},
		},
		{
			name:  "no results key",
			input: `{}`,
			want:  FindingSummary{},
		},
	}

	parser := &OSVScannerParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.Parse([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Parse() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
