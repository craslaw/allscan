package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsVersionTag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"semver with v prefix", "v1.2.3", true},
		{"semver without v prefix", "1.2.3", true},
		{"major minor only", "v1.2", true},
		{"major only with v", "v1", false},
		{"prerelease", "v1.2.3-rc1", true},
		{"branch name main", "main", false},
		{"branch name develop", "develop", false},
		{"feature branch", "feature/add-sbom", false},
		{"empty string", "", false},
		{"just v", "v", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVersionTag(tt.input)
			if got != tt.expected {
				t.Errorf("isVersionTag(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuildSBOMFilename(t *testing.T) {
	tests := []struct {
		name       string
		repoName   string
		commitHash string
		branchTag  string
		wantPrefix string // filename before the date portion
		wantSuffix string
	}{
		{
			name:       "version tag",
			repoName:   "grype",
			commitHash: "abc1234",
			branchTag:  "v0.87.0",
			wantPrefix: "grype_v0.87.0_abc1234_",
			wantSuffix: ".cdx.json",
		},
		{
			name:       "branch only",
			repoName:   "allscan",
			commitHash: "def5678",
			branchTag:  "main",
			wantPrefix: "allscan_def5678_",
			wantSuffix: ".cdx.json",
		},
		{
			name:       "empty branchTag",
			repoName:   "myrepo",
			commitHash: "1234567",
			branchTag:  "",
			wantPrefix: "myrepo_1234567_",
			wantSuffix: ".cdx.json",
		},
		{
			name:       "feature branch",
			repoName:   "myrepo",
			commitHash: "aaa1111",
			branchTag:  "feature/sbom",
			wantPrefix: "myrepo_aaa1111_",
			wantSuffix: ".cdx.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSBOMFilename(tt.repoName, tt.commitHash, tt.branchTag)
			if len(got) < len(tt.wantPrefix)+len(tt.wantSuffix) {
				t.Fatalf("buildSBOMFilename() = %q, too short", got)
			}
			if got[:len(tt.wantPrefix)] != tt.wantPrefix {
				t.Errorf("buildSBOMFilename() prefix = %q, want %q", got[:len(tt.wantPrefix)], tt.wantPrefix)
			}
			if got[len(got)-len(tt.wantSuffix):] != tt.wantSuffix {
				t.Errorf("buildSBOMFilename() suffix = %q, want %q", got[len(got)-len(tt.wantSuffix):], tt.wantSuffix)
			}
		})
	}
}

func TestFindExistingSBOM(t *testing.T) {
	t.Run("finds matching SBOM by repo+version+commit", func(t *testing.T) {
		dir := t.TempDir()
		existing := "grype_v0.87.0_abc1234_2026-02-20.cdx.json"
		if err := os.WriteFile(filepath.Join(dir, existing), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}

		got := findExistingSBOM(dir, "grype", "abc1234", "v0.87.0")
		if filepath.Base(got) != existing {
			t.Errorf("findExistingSBOM() = %q, want %q", filepath.Base(got), existing)
		}
	})

	t.Run("finds matching SBOM for branch target", func(t *testing.T) {
		dir := t.TempDir()
		existing := "allscan_def5678_2026-02-20.cdx.json"
		if err := os.WriteFile(filepath.Join(dir, existing), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}

		got := findExistingSBOM(dir, "allscan", "def5678", "main")
		if filepath.Base(got) != existing {
			t.Errorf("findExistingSBOM() = %q, want %q", filepath.Base(got), existing)
		}
	})

	t.Run("returns empty when no match", func(t *testing.T) {
		dir := t.TempDir()
		// Create an SBOM for a different commit
		if err := os.WriteFile(filepath.Join(dir, "grype_v0.87.0_xxx9999_2026-02-20.cdx.json"), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}

		got := findExistingSBOM(dir, "grype", "abc1234", "v0.87.0")
		if got != "" {
			t.Errorf("findExistingSBOM() = %q, want empty string", got)
		}
	})

	t.Run("returns empty for empty directory", func(t *testing.T) {
		dir := t.TempDir()
		got := findExistingSBOM(dir, "grype", "abc1234", "v0.87.0")
		if got != "" {
			t.Errorf("findExistingSBOM() = %q, want empty string", got)
		}
	})

	t.Run("ignores date when matching", func(t *testing.T) {
		dir := t.TempDir()
		// Same repo+version+commit but different date should still match
		existing := "grype_v0.87.0_abc1234_2026-01-15.cdx.json"
		if err := os.WriteFile(filepath.Join(dir, existing), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}

		got := findExistingSBOM(dir, "grype", "abc1234", "v0.87.0")
		if filepath.Base(got) != existing {
			t.Errorf("findExistingSBOM() = %q, want %q", filepath.Base(got), existing)
		}
	})
}
