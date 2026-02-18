package parsers

import "testing"

func TestGet(t *testing.T) {
	registered := []struct {
		name       string
		wantName   string
		wantType   string
		wantIconNE bool // icon should be non-empty
	}{
		{name: "grype", wantName: "grype", wantType: "SCA", wantIconNE: true},
		{name: "osv-scanner", wantName: "osv-scanner", wantType: "SCA", wantIconNE: true},
		{name: "gosec", wantName: "gosec", wantType: "SAST", wantIconNE: true},
		{name: "gitleaks", wantName: "gitleaks", wantType: "Secrets", wantIconNE: true},
		{name: "binary-detector", wantName: "binary-detector", wantType: "SCA", wantIconNE: true},
		{name: "scorecard", wantName: "scorecard", wantType: "Scorecard", wantIconNE: true},
	}

	for _, tt := range registered {
		t.Run(tt.name, func(t *testing.T) {
			parser, ok := Get(tt.name)
			if !ok {
				t.Fatalf("Get(%q) returned ok=false, want true", tt.name)
			}
			if parser.Name() != tt.wantName {
				t.Errorf("Name() = %q, want %q", parser.Name(), tt.wantName)
			}
			if parser.Type() != tt.wantType {
				t.Errorf("Type() = %q, want %q", parser.Type(), tt.wantType)
			}
			if tt.wantIconNE && parser.Icon() == "" {
				t.Error("Icon() is empty, want non-empty")
			}
		})
	}

	t.Run("unknown scanner returns false", func(t *testing.T) {
		parser, ok := Get("nonexistent-scanner")
		if ok {
			t.Error("Get(nonexistent) returned ok=true, want false")
		}
		if parser != nil {
			t.Error("Get(nonexistent) returned non-nil parser, want nil")
		}
	})
}
