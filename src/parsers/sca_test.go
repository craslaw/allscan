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
