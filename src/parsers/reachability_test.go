package parsers

import "testing"

func TestGovulncheckParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty input",
			input: "",
			want:  FindingSummary{},
		},
		{
			name: "single reachable finding",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":10,"col":5}},{"position":null}]}}
`,
			want: FindingSummary{Critical: 1, Total: 1},
		},
		{
			name: "single unreachable finding",
			input: `{"finding":{"osv":"GO-2024-0002","trace":[{"position":null},{"position":null}]}}
`,
			want: FindingSummary{Info: 1, Total: 1},
		},
		{
			name: "mixed reachable and unreachable",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":10,"col":5}}]}}
{"finding":{"osv":"GO-2024-0002","trace":[{"position":null}]}}
{"finding":{"osv":"GO-2024-0003","trace":[{"position":{"filename":"handler.go","line":20,"col":3}}]}}
`,
			want: FindingSummary{Critical: 2, Info: 1, Total: 3},
		},
		{
			name: "dedup by OSV ID reachable wins",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[{"position":null}]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":10,"col":5}}]}}
`,
			want: FindingSummary{Critical: 1, Total: 1},
		},
		{
			name: "dedup unreachable then unreachable stays unreachable",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[{"position":null}]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":null}]}}
`,
			want: FindingSummary{Info: 1, Total: 1},
		},
		{
			name: "non-finding lines are skipped",
			input: `{"config":{"protocol_version":"v1.0.0"}}
{"progress":{"message":"Scanning your code..."}}
{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-1234"]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
`,
			want: FindingSummary{Critical: 1, Total: 1},
		},
		{
			name: "empty trace is unreachable",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[]}}
`,
			want: FindingSummary{Info: 1, Total: 1},
		},
		{
			name: "empty OSV field is skipped",
			input: `{"finding":{"osv":"","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
`,
			want: FindingSummary{},
		},
		{
			name:  "invalid JSON stops parsing",
			input: `not json at all`,
			want:  FindingSummary{},
		},
		{
			name: "pretty-printed JSON objects",
			input: `{
  "config": {
    "protocol_version": "v1.0.0"
  }
}
{
  "finding": {
    "osv": "GO-2024-0001",
    "trace": [
      {
        "position": {
          "filename": "main.go",
          "line": 10,
          "col": 5
        }
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2024-0002",
    "trace": [
      {
        "position": null
      }
    ]
  }
}
`,
			want: FindingSummary{Critical: 1, Info: 1, Total: 2},
		},
		{
			name: "finding with null trace position fields",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[{"position":null},{"position":null}]}}
{"finding":{"osv":"GO-2024-0002","trace":[{"position":null},{"position":{"filename":"app.go","line":5,"col":1}}]}}
`,
			want: FindingSummary{Critical: 1, Info: 1, Total: 2},
		},
	}

	parser := &GovulncheckParser{}
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

func TestBuildReachabilityIndex(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantIndex    map[string]bool // expected entries in the index
		wantMissing  []string        // IDs expected NOT to be in the index
	}{
		{
			name:      "empty input",
			input:     "",
			wantIndex: map[string]bool{},
		},
		{
			name: "aliases mapped correctly",
			input: `{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-1234","GHSA-xxxx-yyyy-zzzz"]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
`,
			wantIndex: map[string]bool{
				"GO-2024-0001":        true,
				"CVE-2024-1234":       true,
				"GHSA-xxxx-yyyy-zzzz": true,
			},
		},
		{
			name: "unreachable aliases mapped",
			input: `{"osv":{"id":"GO-2024-0002","aliases":["CVE-2024-5678"]}}
{"finding":{"osv":"GO-2024-0002","trace":[{"position":null}]}}
`,
			wantIndex: map[string]bool{
				"GO-2024-0002":  false,
				"CVE-2024-5678": false,
			},
		},
		{
			name: "reachable wins over unreachable",
			input: `{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-1234"]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":null}]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
`,
			wantIndex: map[string]bool{
				"GO-2024-0001":  true,
				"CVE-2024-1234": true,
			},
		},
		{
			name: "findings without osv entries still indexed by GO ID",
			input: `{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
`,
			wantIndex: map[string]bool{
				"GO-2024-0001": true,
			},
		},
		{
			name: "multiple vulns with different reachability",
			input: `{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-1111"]}}
{"osv":{"id":"GO-2024-0002","aliases":["CVE-2024-2222"]}}
{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
{"finding":{"osv":"GO-2024-0002","trace":[{"position":null}]}}
`,
			wantIndex: map[string]bool{
				"GO-2024-0001":  true,
				"CVE-2024-1111": true,
				"GO-2024-0002":  false,
				"CVE-2024-2222": false,
			},
		},
		{
			name: "pretty-printed JSON objects",
			input: `{
  "osv": {
    "id": "GO-2024-0001",
    "aliases": ["CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"]
  }
}
{
  "finding": {
    "osv": "GO-2024-0001",
    "trace": [
      {
        "position": {
          "filename": "main.go",
          "line": 1,
          "col": 1
        }
      }
    ]
  }
}
`,
			wantIndex: map[string]bool{
				"GO-2024-0001":        true,
				"CVE-2024-1234":       true,
				"GHSA-xxxx-yyyy-zzzz": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := BuildReachabilityIndex([]byte(tt.input))

			for id, wantReachable := range tt.wantIndex {
				reachable, known := idx.Lookup(id)
				if !known {
					t.Errorf("Lookup(%q): expected known, got unknown", id)
					continue
				}
				if reachable != wantReachable {
					t.Errorf("Lookup(%q): reachable = %v, want %v", id, reachable, wantReachable)
				}
			}

			for _, id := range tt.wantMissing {
				_, known := idx.Lookup(id)
				if known {
					t.Errorf("Lookup(%q): expected unknown, got known", id)
				}
			}
		})
	}
}

func TestReachabilityIndex_ExpandWithAliasGroups(t *testing.T) {
	tests := []struct {
		name        string
		index       ReachabilityIndex
		groups      [][]string
		wantIndex   map[string]bool
		wantMissing []string
	}{
		{
			name:  "expands GO ID to GHSA via OSV-scanner group",
			index: ReachabilityIndex{"GO-2024-0001": true},
			groups: [][]string{
				{"GO-2024-0001", "CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"},
			},
			wantIndex: map[string]bool{
				"GO-2024-0001":        true,
				"CVE-2024-1234":       true,
				"GHSA-xxxx-yyyy-zzzz": true,
			},
		},
		{
			name:  "unreachable status propagated",
			index: ReachabilityIndex{"GO-2024-0001": false},
			groups: [][]string{
				{"GO-2024-0001", "GHSA-aaaa-bbbb-cccc"},
			},
			wantIndex: map[string]bool{
				"GO-2024-0001":        false,
				"GHSA-aaaa-bbbb-cccc": false,
			},
		},
		{
			name:  "reachable wins when group has mixed status",
			index: ReachabilityIndex{"GO-2024-0001": true, "CVE-2024-1234": false},
			groups: [][]string{
				{"GO-2024-0001", "CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"},
			},
			wantIndex: map[string]bool{
				"GO-2024-0001":        true,
				"CVE-2024-1234":       true, // upgraded: group contains reachable GO-2024-0001
				"GHSA-xxxx-yyyy-zzzz": true,
			},
		},
		{
			name:  "group with no known IDs is skipped",
			index: ReachabilityIndex{"GO-2024-0001": true},
			groups: [][]string{
				{"CVE-2024-9999", "GHSA-zzzz-yyyy-xxxx"},
			},
			wantIndex: map[string]bool{
				"GO-2024-0001": true,
			},
			wantMissing: []string{"CVE-2024-9999", "GHSA-zzzz-yyyy-xxxx"},
		},
		{
			name:   "nil index is safe",
			index:  nil,
			groups: [][]string{{"GO-2024-0001", "CVE-2024-1234"}},
		},
		{
			name:  "multiple groups expanded independently",
			index: ReachabilityIndex{"GO-2024-0001": true, "GO-2024-0002": false},
			groups: [][]string{
				{"GO-2024-0001", "GHSA-aaaa-bbbb-cccc"},
				{"GO-2024-0002", "GHSA-dddd-eeee-ffff"},
			},
			wantIndex: map[string]bool{
				"GO-2024-0001":        true,
				"GHSA-aaaa-bbbb-cccc": true,
				"GO-2024-0002":        false,
				"GHSA-dddd-eeee-ffff": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.index.ExpandWithAliasGroups(tt.groups)

			for id, wantReachable := range tt.wantIndex {
				reachable, known := tt.index.Lookup(id)
				if !known {
					t.Errorf("Lookup(%q): expected known, got unknown", id)
					continue
				}
				if reachable != wantReachable {
					t.Errorf("Lookup(%q): reachable = %v, want %v", id, reachable, wantReachable)
				}
			}

			for _, id := range tt.wantMissing {
				_, known := tt.index.Lookup(id)
				if known {
					t.Errorf("Lookup(%q): expected unknown, got known", id)
				}
			}
		})
	}
}

func TestReachabilityIndex_Lookup(t *testing.T) {
	t.Run("nil index returns unknown", func(t *testing.T) {
		var idx ReachabilityIndex
		reachable, known := idx.Lookup("CVE-2024-1234")
		if known {
			t.Error("expected unknown for nil index")
		}
		if reachable {
			t.Error("expected reachable=false for nil index")
		}
	})

	t.Run("unknown ID returns unknown", func(t *testing.T) {
		idx := ReachabilityIndex{"CVE-2024-1234": true}
		_, known := idx.Lookup("CVE-9999-9999")
		if known {
			t.Error("expected unknown for missing ID")
		}
	})
}
