package parsers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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

func TestRunBinaryDetector(t *testing.T) {
	// Helper: create a fake binary file in dir with the given name and content.
	writeFile := func(t *testing.T, dir, name string, content []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), content, 0640); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	tests := []struct {
		name      string
		setup     func(t *testing.T, dir string) // populate the temp dir
		sarifMode bool
		wantCount int
	}{
		{
			name: "json mode with binaries",
			setup: func(t *testing.T, dir string) {
				writeFile(t, dir, "foo.exe", []byte("MZ"))
				writeFile(t, dir, "bar.dll", []byte("MZ"))
				writeFile(t, dir, "readme.txt", []byte("hello"))
			},
			sarifMode: false,
			wantCount: 2,
		},
		{
			name: "sarif mode with binaries",
			setup: func(t *testing.T, dir string) {
				writeFile(t, dir, "payload.exe", []byte("MZ"))
				writeFile(t, dir, "lib.so", []byte("ELF"))
			},
			sarifMode: true,
			wantCount: 2,
		},
		{
			name:      "json mode empty directory",
			setup:     func(t *testing.T, dir string) {},
			sarifMode: false,
			wantCount: 0,
		},
		{
			name:      "sarif mode empty directory",
			setup:     func(t *testing.T, dir string) {},
			sarifMode: true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir := t.TempDir()
			tt.setup(t, repoDir)

			outDir := t.TempDir()
			ext := ".json"
			if tt.sarifMode {
				ext = ".sarif"
			}
			outputPath := filepath.Join(outDir, "out"+ext)

			count, err := RunBinaryDetector(repoDir, outputPath, tt.sarifMode)
			if err != nil {
				t.Fatalf("RunBinaryDetector() error = %v", err)
			}
			if count != tt.wantCount {
				t.Errorf("count = %d, want %d", count, tt.wantCount)
			}

			// Verify the output file was written
			data, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("output file not written: %v", err)
			}

			if tt.sarifMode {
				// Validate SARIF structure
				var log sarifLog
				if err := json.Unmarshal(data, &log); err != nil {
					t.Fatalf("SARIF output is not valid JSON: %v", err)
				}
				if log.Version != "2.1.0" {
					t.Errorf("SARIF version = %q, want %q", log.Version, "2.1.0")
				}
				if len(log.Runs) != 1 {
					t.Fatalf("SARIF runs = %d, want 1", len(log.Runs))
				}
				if len(log.Runs[0].Results) != tt.wantCount {
					t.Errorf("SARIF results = %d, want %d", len(log.Runs[0].Results), tt.wantCount)
				}
				for i, r := range log.Runs[0].Results {
					if r.RuleID != "BINARY001" {
						t.Errorf("result[%d].ruleId = %q, want %q", i, r.RuleID, "BINARY001")
					}
					if r.Level != "warning" {
						t.Errorf("result[%d].level = %q, want %q", i, r.Level, "warning")
					}
					if len(r.Locations) == 0 {
						t.Errorf("result[%d] has no locations", i)
					} else {
						uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
						if uri == "" {
							t.Errorf("result[%d] uri is empty", i)
						}
						baseID := r.Locations[0].PhysicalLocation.ArtifactLocation.URIBaseID
						if baseID != "%SRCROOT%" {
							t.Errorf("result[%d] uriBaseId = %q, want %%SRCROOT%%", i, baseID)
						}
					}
				}
			} else {
				// Validate JSON structure
				var out BinaryOutput
				if err := json.Unmarshal(data, &out); err != nil {
					t.Fatalf("JSON output is not valid: %v", err)
				}
				if out.Total != tt.wantCount {
					t.Errorf("JSON total = %d, want %d", out.Total, tt.wantCount)
				}
				if len(out.Binaries) != tt.wantCount {
					t.Errorf("JSON binaries len = %d, want %d", len(out.Binaries), tt.wantCount)
				}
			}
		})
	}
}
