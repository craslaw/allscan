package parsers

import "testing"

func TestGosecParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty issues",
			input: `{"Issues": [], "Stats": {"found": 0}}`,
			want:  FindingSummary{},
		},
		{
			name: "single high finding",
			input: `{"Issues": [{"severity": "HIGH"}], "Stats": {"found": 1}}`,
			want:  FindingSummary{High: 1, Total: 1},
		},
		{
			name: "mixed severities",
			input: `{"Issues": [
				{"severity": "HIGH"},
				{"severity": "MEDIUM"},
				{"severity": "LOW"},
				{"severity": "MEDIUM"}
			], "Stats": {"found": 4}}`,
			want: FindingSummary{High: 1, Medium: 2, Low: 1, Total: 4},
		},
		{
			name: "case insensitive via ToUpper",
			input: `{"Issues": [
				{"severity": "high"},
				{"severity": "Medium"}
			], "Stats": {"found": 2}}`,
			want: FindingSummary{High: 1, Medium: 1, Total: 2},
		},
		{
			name: "unknown severity increments total only",
			input: `{"Issues": [
				{"severity": "CRITICAL"},
				{"severity": "UNKNOWN"}
			], "Stats": {"found": 2}}`,
			// Gosec switch only handles HIGH/MEDIUM/LOW - CRITICAL and UNKNOWN
			// fall through, incrementing Total but no severity bucket
			want: FindingSummary{Total: 2},
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: true,
		},
		{
			name:  "no issues key",
			input: `{}`,
			want:  FindingSummary{},
		},
	}

	parser := &GosecParser{}
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
