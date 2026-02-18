package parsers

import "testing"

func TestGitleaksParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty array",
			input: `[]`,
			want:  FindingSummary{},
		},
		{
			name:  "single secret",
			input: `[{"RuleID": "aws-access-key", "Description": "AWS Access Key"}]`,
			want:  FindingSummary{High: 1, Total: 1},
		},
		{
			name: "multiple secrets",
			input: `[
				{"RuleID": "aws-access-key", "Description": "AWS Access Key"},
				{"RuleID": "github-token", "Description": "GitHub Token"},
				{"RuleID": "private-key", "Description": "Private Key"}
			]`,
			want: FindingSummary{High: 3, Total: 3},
		},
		{
			name:    "invalid JSON",
			input:   `{not an array}`,
			wantErr: true,
		},
	}

	parser := &GitleaksParser{}
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
