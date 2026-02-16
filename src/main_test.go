package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetCommitHash(t *testing.T) {
	t.Run("returns short hash from git repo", func(t *testing.T) {
		// Create a temp git repo
		dir := t.TempDir()

		// Initialize git repo
		cmd := exec.Command("git", "init")
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git init failed: %v", err)
		}

		// Configure git user for commit
		cmd = exec.Command("git", "config", "user.email", "test@test.com")
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git config email failed: %v", err)
		}
		cmd = exec.Command("git", "config", "user.name", "Test User")
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git config name failed: %v", err)
		}

		// Create a file and commit
		testFile := filepath.Join(dir, "test.txt")
		if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		cmd = exec.Command("git", "add", "test.txt")
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git add failed: %v", err)
		}

		cmd = exec.Command("git", "commit", "-m", "initial commit")
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("git commit failed: %v", err)
		}

		// Test getCommitHash
		hash, err := getCommitHash(dir)
		if err != nil {
			t.Fatalf("getCommitHash() error = %v", err)
		}

		// Hash should be 7 characters (short format)
		if len(hash) < 7 {
			t.Errorf("getCommitHash() returned hash too short: %q", hash)
		}

		// Hash should be hex characters only
		for _, c := range hash {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("getCommitHash() returned non-hex character: %q", hash)
				break
			}
		}
	})

	t.Run("returns error for non-git directory", func(t *testing.T) {
		dir := t.TempDir()
		_, err := getCommitHash(dir)
		if err == nil {
			t.Error("getCommitHash() expected error for non-git directory, got nil")
		}
	})
}

func TestValidateVersionCommit(t *testing.T) {
	// Create a temp git repo with a tag
	dir := t.TempDir()

	// Initialize and configure git
	cmds := [][]string{
		{"git", "init"},
		{"git", "config", "user.email", "test@test.com"},
		{"git", "config", "user.name", "Test User"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s failed: %v", args[0], err)
		}
	}

	// Create initial commit
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("v1"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	cmd := exec.Command("git", "add", "test.txt")
	cmd.Dir = dir
	cmd.Run()
	cmd = exec.Command("git", "commit", "-m", "v1")
	cmd.Dir = dir
	cmd.Run()

	// Create a tag
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git tag failed: %v", err)
	}

	// Get the commit hash for v1.0.0
	cmd = exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse failed: %v", err)
	}
	tagCommit := strings.TrimSpace(string(output))

	t.Run("matching commit produces no warning", func(t *testing.T) {
		// This should not produce a warning (no way to capture log output easily in test)
		// Just verify it doesn't panic
		validateVersionCommit(dir, "v1.0.0", tagCommit)
	})

	t.Run("non-existent tag is handled gracefully", func(t *testing.T) {
		// Should not panic for non-existent tag
		validateVersionCommit(dir, "v999.0.0", "abc1234")
	})

	t.Run("non-git directory is handled gracefully", func(t *testing.T) {
		nonGitDir := t.TempDir()
		// Should not panic for non-git directory
		validateVersionCommit(nonGitDir, "v1.0.0", "abc1234")
	})
}

func TestIsValidCachedRepo(t *testing.T) {
	t.Run("returns false for non-existent directory", func(t *testing.T) {
		if isValidCachedRepo("/nonexistent/path", "https://github.com/org/repo") {
			t.Error("isValidCachedRepo() = true, want false for non-existent directory")
		}
	})

	t.Run("returns false for non-git directory", func(t *testing.T) {
		dir := t.TempDir()
		if isValidCachedRepo(dir, "https://github.com/org/repo") {
			t.Error("isValidCachedRepo() = true, want false for non-git directory")
		}
	})

	t.Run("returns true for matching remote", func(t *testing.T) {
		dir := t.TempDir()

		// Initialize git repo with remote
		cmd := exec.Command("git", "init")
		cmd.Dir = dir
		cmd.Run()

		expectedURL := "https://github.com/org/repo"
		cmd = exec.Command("git", "remote", "add", "origin", expectedURL)
		cmd.Dir = dir
		cmd.Run()

		if !isValidCachedRepo(dir, expectedURL) {
			t.Error("isValidCachedRepo() = false, want true for matching remote")
		}
	})

	t.Run("returns false for mismatched remote", func(t *testing.T) {
		dir := t.TempDir()

		// Initialize git repo with different remote
		cmd := exec.Command("git", "init")
		cmd.Dir = dir
		cmd.Run()

		cmd = exec.Command("git", "remote", "add", "origin", "https://github.com/other/repo")
		cmd.Dir = dir
		cmd.Run()

		if isValidCachedRepo(dir, "https://github.com/org/repo") {
			t.Error("isValidCachedRepo() = true, want false for mismatched remote")
		}
	})

	t.Run("handles .git suffix normalization", func(t *testing.T) {
		dir := t.TempDir()

		// Initialize git repo
		cmd := exec.Command("git", "init")
		cmd.Dir = dir
		cmd.Run()

		cmd = exec.Command("git", "remote", "add", "origin", "https://github.com/org/repo.git")
		cmd.Dir = dir
		cmd.Run()

		// Should match even without .git suffix
		if !isValidCachedRepo(dir, "https://github.com/org/repo") {
			t.Error("isValidCachedRepo() = false, want true (should handle .git suffix)")
		}
	})
}
