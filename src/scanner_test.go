package main

import "testing"

func TestIsScannerCompatible(t *testing.T) {
	tests := []struct {
		name     string
		scanner  ScannerConfig
		detected *DetectedLanguages
		want     bool
	}{
		{
			name:     "universal scanner (empty Languages) always compatible",
			scanner:  ScannerConfig{Languages: []string{}},
			detected: &DetectedLanguages{Languages: []string{"go"}},
			want:     true,
		},
		{
			name:     "universal scanner with no detected languages",
			scanner:  ScannerConfig{Languages: []string{}},
			detected: &DetectedLanguages{Languages: []string{}},
			want:     true,
		},
		{
			name:     "specific scanner with matching language",
			scanner:  ScannerConfig{Languages: []string{"go", "python"}},
			detected: &DetectedLanguages{Languages: []string{"go"}},
			want:     true,
		},
		{
			name:     "specific scanner with no matching language",
			scanner:  ScannerConfig{Languages: []string{"java", "kotlin"}},
			detected: &DetectedLanguages{Languages: []string{"go", "python"}},
			want:     false,
		},
		{
			name:     "specific scanner with no detected languages",
			scanner:  ScannerConfig{Languages: []string{"go"}},
			detected: &DetectedLanguages{Languages: []string{}},
			want:     false,
		},
		{
			name: "conditional language match triggers run",
			scanner: ScannerConfig{
				Languages:            []string{"go"},
				LanguagesConditional: []string{"elixir"},
			},
			detected: &DetectedLanguages{Languages: []string{"elixir"}},
			want:     true,
		},
		{
			name: "no match in languages or conditional",
			scanner: ScannerConfig{
				Languages:            []string{"go"},
				LanguagesConditional: []string{"elixir"},
			},
			detected: &DetectedLanguages{Languages: []string{"java"}},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isScannerCompatible(tt.scanner, tt.detected)
			if got != tt.want {
				t.Errorf("isScannerCompatible() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetScannersForRepo(t *testing.T) {
	allScanners := []ScannerConfig{
		{Name: "grype", Enabled: true, Languages: []string{}},           // universal
		{Name: "gosec", Enabled: true, Languages: []string{"go"}},       // go-specific
		{Name: "disabled", Enabled: false, Languages: []string{}},       // disabled
		{Name: "java-scanner", Enabled: true, Languages: []string{"java"}}, // java-specific
	}

	tests := []struct {
		name      string
		repo      RepositoryConfig
		detected  *DetectedLanguages
		wantNames []string
	}{
		{
			name:      "no repo scanners list uses all enabled compatible",
			repo:      RepositoryConfig{URL: "https://github.com/org/repo"},
			detected:  &DetectedLanguages{Languages: []string{"go"}},
			wantNames: []string{"grype", "gosec"},
		},
		{
			name:      "universal scanner always included",
			repo:      RepositoryConfig{URL: "https://github.com/org/repo"},
			detected:  &DetectedLanguages{Languages: []string{"java"}},
			wantNames: []string{"grype", "java-scanner"},
		},
		{
			name:      "repo with specific scanner names",
			repo:      RepositoryConfig{URL: "https://github.com/org/repo", Scanners: []string{"gosec"}},
			detected:  &DetectedLanguages{Languages: []string{"go"}},
			wantNames: []string{"gosec"},
		},
		{
			name:      "repo-specified scanner excluded if not compatible",
			repo:      RepositoryConfig{URL: "https://github.com/org/repo", Scanners: []string{"gosec"}},
			detected:  &DetectedLanguages{Languages: []string{"java"}},
			wantNames: nil,
		},
		{
			name:      "disabled scanner excluded even if named",
			repo:      RepositoryConfig{URL: "https://github.com/org/repo", Scanners: []string{"disabled"}},
			detected:  &DetectedLanguages{Languages: []string{"go"}},
			wantNames: nil,
		},
		{
			name:      "no detected languages excludes language-specific scanners",
			repo:      RepositoryConfig{URL: "https://github.com/org/repo"},
			detected:  &DetectedLanguages{Languages: []string{}},
			wantNames: []string{"grype"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Scanners: allScanners}
			got := getScannersForRepo(config, tt.repo, tt.detected)

			gotNames := make([]string, len(got))
			for i, s := range got {
				gotNames[i] = s.Name
			}

			if len(gotNames) != len(tt.wantNames) {
				t.Errorf("getScannersForRepo() returned %v, want %v", gotNames, tt.wantNames)
				return
			}
			for i := range gotNames {
				if gotNames[i] != tt.wantNames[i] {
					t.Errorf("scanner[%d] = %q, want %q", i, gotNames[i], tt.wantNames[i])
				}
			}
		})
	}
}

func TestCheckRequiredEnv(t *testing.T) {
	tests := []struct {
		name     string
		required []string
		envVars  map[string]string
		want     string
	}{
		{
			name:     "no required vars",
			required: []string{},
			want:     "",
		},
		{
			name:     "all vars set",
			required: []string{"TEST_VAR_A", "TEST_VAR_B"},
			envVars:  map[string]string{"TEST_VAR_A": "val1", "TEST_VAR_B": "val2"},
			want:     "",
		},
		{
			name:     "first var missing",
			required: []string{"MISSING_VAR", "TEST_VAR_C"},
			envVars:  map[string]string{"TEST_VAR_C": "val"},
			want:     "MISSING_VAR",
		},
		{
			name:     "second var missing",
			required: []string{"TEST_VAR_D", "ALSO_MISSING"},
			envVars:  map[string]string{"TEST_VAR_D": "val"},
			want:     "ALSO_MISSING",
		},
		{
			name:     "nil required list",
			required: nil,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}
			got := checkRequiredEnv(tt.required)
			if got != tt.want {
				t.Errorf("checkRequiredEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}
