package main

import (
	"testing"

	"vuln-scanner-orchestrator/parsers"
)

// testParser is a minimal ResultParser for testing coverage computation
type testParser struct {
	name     string
	scanType string
}

func (p *testParser) Parse(data []byte) (parsers.FindingSummary, error) {
	return parsers.FindingSummary{}, nil
}
func (p *testParser) Type() string { return p.scanType }
func (p *testParser) Icon() string { return "🔧" }
func (p *testParser) Name() string { return p.name }

func TestComputeCoverage(t *testing.T) {
	// Register test parsers and clean up after
	testParsers := map[string]*testParser{
		"test-sca-universal":  {name: "test-sca-universal", scanType: "SCA"},
		"test-sast-go":        {name: "test-sast-go", scanType: "SAST"},
		"test-secrets":        {name: "test-secrets", scanType: "Secrets"},
		"test-scorecard":      {name: "test-scorecard", scanType: "Scorecard"},
		"test-sast-universal": {name: "test-sast-universal", scanType: "SAST"},
	}
	for name, p := range testParsers {
		parsers.Register(name, p)
	}
	t.Cleanup(func() {
		// Re-register real parsers that were potentially shadowed (none in this case)
	})

	tests := []struct {
		name     string
		ctx      RepoScanContext
		expected map[string]map[string]CoverageState
	}{
		{
			name: "no languages detected",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{}, FileCounts: map[string]int{}},
			},
			expected: nil,
		},
		{
			name: "nil languages",
			ctx: RepoScanContext{
				Languages: nil,
			},
			expected: nil,
		},
		{
			name: "universal SCA scanner successful",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{"go", "python"}},
				Scanners: []ScannerConfig{
					{Name: "test-sca-universal", Languages: []string{}},
				},
				Results: []ScanResult{
					{Scanner: "test-sca-universal", Success: true},
				},
			},
			expected: map[string]map[string]CoverageState{
				"go":     {"SCA": CoverageOK, "SAST": CoverageNone, "Secrets": CoverageNone},
				"python": {"SCA": CoverageOK, "SAST": CoverageNone, "Secrets": CoverageNone},
			},
		},
		{
			name: "language-specific SAST scanner",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{"go", "python"}},
				Scanners: []ScannerConfig{
					{Name: "test-sast-go", Languages: []string{"go"}},
				},
				Results: []ScanResult{
					{Scanner: "test-sast-go", Success: true},
				},
			},
			expected: map[string]map[string]CoverageState{
				"go":     {"SCA": CoverageNone, "SAST": CoverageOK, "Secrets": CoverageNone},
				"python": {"SCA": CoverageNone, "SAST": CoverageNone, "Secrets": CoverageNone},
			},
		},
		{
			name: "failed scanner shows warning",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{"go"}},
				Scanners: []ScannerConfig{
					{Name: "test-sast-go", Languages: []string{"go"}},
				},
				Results: []ScanResult{
					{Scanner: "test-sast-go", Success: false},
				},
			},
			expected: map[string]map[string]CoverageState{
				"go": {"SCA": CoverageNone, "SAST": CoverageFailed, "Secrets": CoverageNone},
			},
		},
		{
			name: "scorecard excluded from matrix",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{"go"}},
				Scanners: []ScannerConfig{
					{Name: "test-scorecard", Languages: []string{}},
				},
				Results: []ScanResult{
					{Scanner: "test-scorecard", Success: true},
				},
			},
			expected: map[string]map[string]CoverageState{
				"go": {"SCA": CoverageNone, "SAST": CoverageNone, "Secrets": CoverageNone},
			},
		},
		{
			name: "mixed: multiple languages, universal + specific scanners, some failures",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{"go", "python", "shell"}},
				Scanners: []ScannerConfig{
					{Name: "test-sca-universal", Languages: []string{}},  // universal SCA
					{Name: "test-sast-go", Languages: []string{"go"}},   // go-only SAST
					{Name: "test-secrets", Languages: []string{}},        // universal secrets
					{Name: "test-scorecard", Languages: []string{}},      // should be excluded
				},
				Results: []ScanResult{
					{Scanner: "test-sca-universal", Success: true},
					{Scanner: "test-sast-go", Success: true},
					{Scanner: "test-secrets", Success: false},
					{Scanner: "test-scorecard", Success: true},
				},
			},
			expected: map[string]map[string]CoverageState{
				"go":     {"SCA": CoverageOK, "SAST": CoverageOK, "Secrets": CoverageFailed},
				"python": {"SCA": CoverageOK, "SAST": CoverageNone, "Secrets": CoverageFailed},
				"shell":  {"SCA": CoverageOK, "SAST": CoverageNone, "Secrets": CoverageFailed},
			},
		},
		{
			name: "success overrides prior failure for same type",
			ctx: RepoScanContext{
				Languages: &DetectedLanguages{Languages: []string{"go"}},
				Scanners: []ScannerConfig{
					{Name: "test-sast-go", Languages: []string{"go"}},
					{Name: "test-sast-universal", Languages: []string{}},
				},
				Results: []ScanResult{
					{Scanner: "test-sast-go", Success: false},
					{Scanner: "test-sast-universal", Success: true},
				},
			},
			expected: map[string]map[string]CoverageState{
				"go": {"SCA": CoverageNone, "SAST": CoverageOK, "Secrets": CoverageNone},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeCoverage(tt.ctx)

			if tt.expected == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected coverage map, got nil")
			}

			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d languages, got %d", len(tt.expected), len(got))
			}

			for lang, expectedTypes := range tt.expected {
				gotTypes, ok := got[lang]
				if !ok {
					t.Errorf("missing language %q in coverage", lang)
					continue
				}
				for scanType, expectedState := range expectedTypes {
					gotState, ok := gotTypes[scanType]
					if !ok {
						t.Errorf("missing scan type %q for language %q", scanType, lang)
						continue
					}
					if gotState != expectedState {
						t.Errorf("language %q, type %q: expected %d, got %d",
							lang, scanType, expectedState, gotState)
					}
				}
			}
		})
	}
}
