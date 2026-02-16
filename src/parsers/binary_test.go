package parsers

import "testing"

func TestBinaryParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FindingSummary
		wantErr bool
	}{
		{
			name:  "no binaries",
			input: `{"binaries": [], "total": 0}`,
			want:  FindingSummary{},
		},
		{
			name: "single binary",
			input: `{"binaries": [{"path": "lib/foo.so", "size": 1024, "reason": "binary extension: .so"}], "total": 1}`,
			want:  FindingSummary{Medium: 1, Total: 1},
		},
		{
			name: "multiple binaries",
			input: `{"binaries": [
				{"path": "a.exe", "size": 100, "reason": "binary extension: .exe"},
				{"path": "b.dll", "size": 200, "reason": "binary extension: .dll"},
				{"path": "c.bin", "size": 300, "reason": "binary content detected"}
			], "total": 3}`,
			want: FindingSummary{Medium: 3, Total: 3},
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: true,
		},
		{
			name:  "empty object",
			input: `{}`,
			want:  FindingSummary{},
		},
	}

	parser := &BinaryParser{}
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
