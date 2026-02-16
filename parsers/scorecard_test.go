package parsers

import "testing"

func TestScorecardParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty checks",
			input: `{"score": 0, "checks": []}`,
			want:  FindingSummary{},
		},
		{
			name: "score 0 is critical",
			input: `{"score": 0, "checks": [{"name": "Binary-Artifacts", "score": 0, "reason": "found"}]}`,
			want:  FindingSummary{Critical: 1, Total: 1},
		},
		{
			name: "score 3 is critical boundary",
			input: `{"score": 3, "checks": [{"name": "Branch-Protection", "score": 3, "reason": "weak"}]}`,
			want:  FindingSummary{Critical: 1, Total: 1},
		},
		{
			name: "score 4 is high",
			input: `{"score": 4, "checks": [{"name": "Code-Review", "score": 4, "reason": "some"}]}`,
			want:  FindingSummary{High: 1, Total: 1},
		},
		{
			name: "score 5 is high boundary",
			input: `{"score": 5, "checks": [{"name": "Code-Review", "score": 5, "reason": "some"}]}`,
			want:  FindingSummary{High: 1, Total: 1},
		},
		{
			name: "score 6 is medium",
			input: `{"score": 6, "checks": [{"name": "Fuzzing", "score": 6, "reason": "partial"}]}`,
			want:  FindingSummary{Medium: 1, Total: 1},
		},
		{
			name: "score 7 is medium boundary",
			input: `{"score": 7, "checks": [{"name": "Fuzzing", "score": 7, "reason": "partial"}]}`,
			want:  FindingSummary{Medium: 1, Total: 1},
		},
		{
			name: "score 8 is low",
			input: `{"score": 8, "checks": [{"name": "License", "score": 8, "reason": "detected"}]}`,
			want:  FindingSummary{Low: 1, Total: 1},
		},
		{
			name: "score 9 is low boundary",
			input: `{"score": 9, "checks": [{"name": "License", "score": 9, "reason": "detected"}]}`,
			want:  FindingSummary{Low: 1, Total: 1},
		},
		{
			name: "score 10 is info (pass)",
			input: `{"score": 10, "checks": [{"name": "Maintained", "score": 10, "reason": "active"}]}`,
			want:  FindingSummary{Info: 1, Total: 1},
		},
		{
			name: "negative score is skipped",
			input: `{"score": 5, "checks": [
				{"name": "CII-Best-Practices", "score": -1, "reason": "not applicable"},
				{"name": "Maintained", "score": 10, "reason": "active"}
			]}`,
			want: FindingSummary{Info: 1, Total: 1},
		},
		{
			name: "mixed scores across all ranges",
			input: `{"score": 5, "checks": [
				{"name": "A", "score": 0, "reason": ""},
				{"name": "B", "score": 5, "reason": ""},
				{"name": "C", "score": 7, "reason": ""},
				{"name": "D", "score": 9, "reason": ""},
				{"name": "E", "score": 10, "reason": ""},
				{"name": "F", "score": -1, "reason": ""}
			]}`,
			want: FindingSummary{Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1, Total: 5},
		},
		{
			name:    "invalid JSON",
			input:   `{bad`,
			wantErr: true,
		},
	}

	parser := &ScorecardParser{}
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

func TestTruncateReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		maxLen int
		want   string
	}{
		{
			name:   "short string unchanged",
			reason: "hello",
			maxLen: 10,
			want:   "hello",
		},
		{
			name:   "exact length unchanged",
			reason: "hello",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "long string truncated",
			reason: "this is a very long reason that should be truncated",
			maxLen: 20,
			want:   "this is a very lo...",
		},
		{
			name:   "multiline uses first line only",
			reason: "first line\nsecond line\nthird line",
			maxLen: 50,
			want:   "first line",
		},
		{
			name:   "multiline first line truncated",
			reason: "this is a long first line\nsecond line",
			maxLen: 15,
			want:   "this is a lo...",
		},
		{
			name:   "empty string",
			reason: "",
			maxLen: 10,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateReason(tt.reason, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateReason(%q, %d) = %q, want %q", tt.reason, tt.maxLen, got, tt.want)
			}
		})
	}
}
