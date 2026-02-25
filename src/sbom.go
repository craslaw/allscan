package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// versionTagPattern matches version-like tags (e.g., v1.2.3, 1.2, v1.0.0-rc1)
var versionTagPattern = regexp.MustCompile(`^v?\d+(\.\d+)`)

// isVersionTag returns true if branchTag looks like a version tag (e.g., v1.2.3)
func isVersionTag(branchTag string) bool {
	return versionTagPattern.MatchString(branchTag)
}

// buildSBOMFilename constructs a filename for the SBOM based on repo metadata.
// Pattern: {repoName}_{version}_{commitHash}_{date}.cdx.json for version tags
//          {repoName}_{commitHash}_{date}.cdx.json for branch-only targets
func buildSBOMFilename(repoName, commitHash, branchTag string) string {
	date := time.Now().Format("2006-01-02")

	if isVersionTag(branchTag) {
		return fmt.Sprintf("%s_%s_%s_%s.cdx.json", repoName, branchTag, commitHash, date)
	}
	return fmt.Sprintf("%s_%s_%s.cdx.json", repoName, commitHash, date)
}

// findExistingSBOM looks for an existing SBOM in sbomDir that matches the given
// repo name, commit hash, and version tag. It ignores the date portion so that
// re-running against the same commit reuses the existing SBOM.
// Returns the full path if found, empty string otherwise.
func findExistingSBOM(sbomDir, repoName, commitHash, branchTag string) string {
	entries, err := os.ReadDir(sbomDir)
	if err != nil {
		return ""
	}

	// Build the prefix to match (everything before the date)
	var prefix string
	if isVersionTag(branchTag) {
		prefix = fmt.Sprintf("%s_%s_%s_", repoName, branchTag, commitHash)
	} else {
		prefix = fmt.Sprintf("%s_%s_", repoName, commitHash)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".cdx.json") {
			return filepath.Join(sbomDir, name)
		}
	}

	return ""
}

// generateSBOM generates a CycloneDX SBOM for a repository using Syft.
// It first checks for an existing SBOM matching the same repo+version+commit
// and reuses it if found. Returns the path to the SBOM file.
func generateSBOM(resultsDir, repoPath, repoName, commitHash, branchTag string) (string, error) {
	sbomDir := filepath.Join(resultsDir, "sboms")

	// Convert to absolute path
	absDir, err := filepath.Abs(sbomDir)
	if err != nil {
		absDir = sbomDir
	}

	// Check for existing SBOM
	if existing := findExistingSBOM(absDir, repoName, commitHash, branchTag); existing != "" {
		log.Printf("  📋 Reusing existing SBOM: %s", filepath.Base(existing))
		return existing, nil
	}

	// Ensure sbom directory exists
	if err := os.MkdirAll(absDir, 0750); err != nil {
		return "", fmt.Errorf("creating sbom directory: %w", err)
	}

	// Build output filename and path
	filename := buildSBOMFilename(repoName, commitHash, branchTag)
	outputPath := filepath.Join(absDir, filename)

	log.Printf("  📋 Generating SBOM with Syft...")

	// Run syft scan
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "syft", "scan", "dir:.", "-o", "cyclonedx-json="+outputPath)
	cmd.Dir = repoPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("syft scan failed: %w\n%s", err, output)
	}

	log.Printf("    ✅ SBOM generated: %s", filename)
	return outputPath, nil
}
