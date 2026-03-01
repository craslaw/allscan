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
			name: "invalid JSON lines are skipped",
			input: `not json at all
{"finding":{"osv":"GO-2024-0001","trace":[{"position":{"filename":"main.go","line":1,"col":1}}]}}
{bad json}
`,
			want: FindingSummary{Critical: 1, Total: 1},
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
