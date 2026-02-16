package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTimeouts(t *testing.T) {
	tests := []struct {
		name        string
		scanners    []ScannerConfig
		wantErr     bool
		wantTimeout time.Duration // checked for first scanner
	}{
		{
			name:        "empty timeout defaults to 5m",
			scanners:    []ScannerConfig{{Name: "test", Timeout: ""}},
			wantTimeout: 5 * time.Minute,
		},
		{
			name:        "valid 10m timeout",
			scanners:    []ScannerConfig{{Name: "test", Timeout: "10m"}},
			wantTimeout: 10 * time.Minute,
		},
		{
			name:        "valid 30s timeout",
			scanners:    []ScannerConfig{{Name: "test", Timeout: "30s"}},
			wantTimeout: 30 * time.Second,
		},
		{
			name:        "valid compound duration",
			scanners:    []ScannerConfig{{Name: "test", Timeout: "1h30m"}},
			wantTimeout: 90 * time.Minute,
		},
		{
			name:     "invalid timeout string",
			scanners: []ScannerConfig{{Name: "bad-scanner", Timeout: "not-a-duration"}},
			wantErr:  true,
		},
		{
			name: "multiple scanners mixed timeouts",
			scanners: []ScannerConfig{
				{Name: "a", Timeout: ""},
				{Name: "b", Timeout: "2m"},
			},
			wantTimeout: 5 * time.Minute, // first scanner default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Scanners: tt.scanners}
			err := parseTimeouts(config)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTimeouts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && config.Scanners[0].timeout != tt.wantTimeout {
				t.Errorf("timeout = %v, want %v", config.Scanners[0].timeout, tt.wantTimeout)
			}
		})
	}

	// Verify second scanner in "multiple scanners" case
	t.Run("multiple scanners second timeout", func(t *testing.T) {
		config := &Config{Scanners: []ScannerConfig{
			{Name: "a", Timeout: ""},
			{Name: "b", Timeout: "2m"},
		}}
		if err := parseTimeouts(config); err != nil {
			t.Fatalf("parseTimeouts() error = %v", err)
		}
		if config.Scanners[1].timeout != 2*time.Minute {
			t.Errorf("second scanner timeout = %v, want %v", config.Scanners[1].timeout, 2*time.Minute)
		}
	})
}

func TestCountEnabledScanners(t *testing.T) {
	tests := []struct {
		name     string
		scanners []ScannerConfig
		want     int
	}{
		{
			name:     "all enabled",
			scanners: []ScannerConfig{{Enabled: true}, {Enabled: true}, {Enabled: true}},
			want:     3,
		},
		{
			name:     "none enabled",
			scanners: []ScannerConfig{{Enabled: false}, {Enabled: false}},
			want:     0,
		},
		{
			name:     "mixed",
			scanners: []ScannerConfig{{Enabled: true}, {Enabled: false}, {Enabled: true}},
			want:     2,
		},
		{
			name:     "empty list",
			scanners: []ScannerConfig{},
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Scanners: tt.scanners}
			got := countEnabledScanners(config)
			if got != tt.want {
				t.Errorf("countEnabledScanners() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("valid config with all fields", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "scanners.yaml")
		yaml := `
global:
  workspace: "/custom/workspace"
  results_dir: "/custom/results"
  max_concurrent: 5
  fail_fast: true
scanners:
  - name: "test-scanner"
    enabled: true
    command: "scanner"
    timeout: "3m"
`
		os.WriteFile(configPath, []byte(yaml), 0644)

		config, err := loadConfig(configPath)
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}
		if config.Global.Workspace != "/custom/workspace" {
			t.Errorf("Workspace = %q, want %q", config.Global.Workspace, "/custom/workspace")
		}
		if config.Global.ResultsDir != "/custom/results" {
			t.Errorf("ResultsDir = %q, want %q", config.Global.ResultsDir, "/custom/results")
		}
		if config.Global.MaxConcurrent != 5 {
			t.Errorf("MaxConcurrent = %d, want %d", config.Global.MaxConcurrent, 5)
		}
		if !config.Global.FailFast {
			t.Error("FailFast = false, want true")
		}
		if len(config.Scanners) != 1 {
			t.Fatalf("len(Scanners) = %d, want 1", len(config.Scanners))
		}
		if config.Scanners[0].Name != "test-scanner" {
			t.Errorf("Scanner name = %q, want %q", config.Scanners[0].Name, "test-scanner")
		}
	})

	t.Run("defaults applied for missing optional fields", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "scanners.yaml")
		yaml := `
scanners:
  - name: "test"
    enabled: true
`
		os.WriteFile(configPath, []byte(yaml), 0644)

		config, err := loadConfig(configPath)
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}
		if config.Global.Workspace != "/tmp/scanner-workspace" {
			t.Errorf("Workspace default = %q, want %q", config.Global.Workspace, "/tmp/scanner-workspace")
		}
		if config.Global.ResultsDir != "./scan-results" {
			t.Errorf("ResultsDir default = %q, want %q", config.Global.ResultsDir, "./scan-results")
		}
		if config.Global.MaxConcurrent != 3 {
			t.Errorf("MaxConcurrent default = %d, want %d", config.Global.MaxConcurrent, 3)
		}
	})

	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := loadConfig("/nonexistent/path/config.yaml")
		if err == nil {
			t.Error("loadConfig() expected error for non-existent file, got nil")
		}
	})

	t.Run("invalid YAML returns error", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "bad.yaml")
		os.WriteFile(configPath, []byte("not: valid: yaml: [[["), 0644)

		_, err := loadConfig(configPath)
		if err == nil {
			t.Error("loadConfig() expected error for invalid YAML, got nil")
		}
	})
}

func TestLoadRepositories(t *testing.T) {
	t.Run("valid repositories", func(t *testing.T) {
		dir := t.TempDir()
		repoPath := filepath.Join(dir, "repositories.yaml")
		yaml := `
repositories:
  - url: "https://github.com/org/repo1"
    branch: "main"
  - url: "https://github.com/org/repo2"
    branch: "develop"
    scanners:
      - grype
      - gosec
`
		os.WriteFile(repoPath, []byte(yaml), 0644)

		repos, err := loadRepositories(repoPath)
		if err != nil {
			t.Fatalf("loadRepositories() error = %v", err)
		}
		if len(repos) != 2 {
			t.Fatalf("len(repos) = %d, want 2", len(repos))
		}
		if repos[0].URL != "https://github.com/org/repo1" {
			t.Errorf("repos[0].URL = %q, want %q", repos[0].URL, "https://github.com/org/repo1")
		}
		if repos[1].Branch != "develop" {
			t.Errorf("repos[1].Branch = %q, want %q", repos[1].Branch, "develop")
		}
		if len(repos[1].Scanners) != 2 {
			t.Errorf("repos[1].Scanners = %v, want [grype gosec]", repos[1].Scanners)
		}
	})

	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := loadRepositories("/nonexistent/repos.yaml")
		if err == nil {
			t.Error("loadRepositories() expected error for non-existent file, got nil")
		}
	})
}

func TestValidateRepositoryConfig(t *testing.T) {
	tests := []struct {
		name    string
		repo    RepositoryConfig
		wantErr bool
	}{
		// Positive cases
		{
			name:    "valid branch only",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Branch: "main"},
			wantErr: false,
		},
		{
			name:    "valid version only",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Version: "v1.0.0"},
			wantErr: false,
		},
		{
			name:    "valid commit only (short)",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Commit: "abc1234"},
			wantErr: false,
		},
		{
			name:    "valid commit only (full)",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Commit: "abc1234def5678abc1234def5678abc1234def56"},
			wantErr: false,
		},
		{
			name:    "valid version and commit",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Version: "v1.0.0", Commit: "abc1234"},
			wantErr: false,
		},
		{
			name:    "valid all fields",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Branch: "main", Version: "v1.0.0", Commit: "abc1234"},
			wantErr: false,
		},
		// Negative cases
		{
			name:    "missing URL",
			repo:    RepositoryConfig{Branch: "main"},
			wantErr: true,
		},
		{
			name:    "missing all refs",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo"},
			wantErr: true,
		},
		{
			name:    "commit too short",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Commit: "abc"},
			wantErr: true,
		},
		{
			name:    "commit too long",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Commit: strings.Repeat("a", 41)},
			wantErr: true,
		},
		{
			name:    "commit invalid chars",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Commit: "xyz1234"},
			wantErr: true,
		},
		{
			name:    "commit with special chars",
			repo:    RepositoryConfig{URL: "https://github.com/org/repo", Commit: "abc-123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepositoryConfig(tt.repo)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRepositoryConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRepositoriesWithVersions(t *testing.T) {
	t.Run("parse version and commit fields", func(t *testing.T) {
		dir := t.TempDir()
		repoPath := filepath.Join(dir, "repositories.yaml")
		yaml := `
repositories:
  - url: "https://github.com/org/repo1"
    version: "v1.2.3"
  - url: "https://github.com/org/repo2"
    commit: "abc1234"
  - url: "https://github.com/org/repo3"
    version: "v2.0.0"
    commit: "def5678"
  - url: "https://github.com/org/repo4"
    branch: "develop"
`
		os.WriteFile(repoPath, []byte(yaml), 0644)

		repos, err := loadRepositories(repoPath)
		if err != nil {
			t.Fatalf("loadRepositories() error = %v", err)
		}
		if len(repos) != 4 {
			t.Fatalf("len(repos) = %d, want 4", len(repos))
		}

		// Check version only
		if repos[0].Version != "v1.2.3" {
			t.Errorf("repos[0].Version = %q, want %q", repos[0].Version, "v1.2.3")
		}
		if repos[0].Commit != "" {
			t.Errorf("repos[0].Commit = %q, want empty", repos[0].Commit)
		}

		// Check commit only
		if repos[1].Commit != "abc1234" {
			t.Errorf("repos[1].Commit = %q, want %q", repos[1].Commit, "abc1234")
		}
		if repos[1].Version != "" {
			t.Errorf("repos[1].Version = %q, want empty", repos[1].Version)
		}

		// Check both version and commit
		if repos[2].Version != "v2.0.0" {
			t.Errorf("repos[2].Version = %q, want %q", repos[2].Version, "v2.0.0")
		}
		if repos[2].Commit != "def5678" {
			t.Errorf("repos[2].Commit = %q, want %q", repos[2].Commit, "def5678")
		}

		// Check branch only
		if repos[3].Branch != "develop" {
			t.Errorf("repos[3].Branch = %q, want %q", repos[3].Branch, "develop")
		}
	})
}
