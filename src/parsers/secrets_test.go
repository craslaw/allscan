package parsers

import "testing"

func TestTrufflehogParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "empty input",
			input: ``,
			want:  FindingSummary{},
		},
		{
			name:  "single verified secret",
			input: `{"DetectorName":"AWS","Verified":true}`,
			want:  FindingSummary{Critical: 1, Total: 1},
		},
		{
			name:  "single unverified secret",
			input: `{"DetectorName":"AWS","Verified":false}`,
			want:  FindingSummary{Medium: 1, Total: 1},
		},
		{
			name: "mix of verified and unverified",
			input: `{"DetectorName":"AWS","Verified":true}
{"DetectorName":"GitHub","Verified":false}
{"DetectorName":"Slack","Verified":true}
{"DetectorName":"Generic","Verified":false}`,
			want: FindingSummary{Critical: 2, Medium: 2, Total: 4},
		},
		{
			name:    "invalid JSON",
			input:   `{not valid json}`,
			wantErr: true,
		},
	}

	parser := &TrufflehogParser{}
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
