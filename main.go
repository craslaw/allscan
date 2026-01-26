// Allscan - Declarative security scanning for git repositories
//
// This tool orchestrates multiple security scanners against git repositories,
// aggregates results, and optionally uploads findings to DefectDojo.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const resultsMaxAge = 7 * 24 * time.Hour // 7 days

// checkAllRequiredEnv checks required environment variables for all enabled scanners.
// Returns a map of scanner name -> missing env var name for any that are missing.
func checkAllRequiredEnv(config *Config) map[string]string {
	missing := make(map[string]string)
	for _, scanner := range config.Scanners {
		if !scanner.Enabled {
			continue
		}
		for _, envVar := range scanner.RequiredEnv {
			if os.Getenv(envVar) == "" {
				missing[scanner.Name] = envVar
				break // Only report first missing var per scanner
			}
		}
	}
	return missing
}

// promptContinue asks the user if they want to continue and returns their choice.
func promptContinue(missing map[string]string) bool {
	fmt.Println("\n⚠️  Missing required environment variables:")
	for scanner, envVar := range missing {
		fmt.Printf("   • %s%s%s%s requires %s%s%s\n", ColorBold, ColorCyan, scanner, ColorReset, ColorYellow, envVar, ColorReset)
	}
	fmt.Print("\nContinue without these scanners? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// isValidCachedRepo checks if a directory is a valid git repo with the expected remote URL
func isValidCachedRepo(repoPath, expectedURL string) bool {
	// Check if directory exists
	info, err := os.Stat(repoPath)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check if it's a git repo with the correct remote
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Normalize URLs for comparison (trim whitespace, handle .git suffix)
	actualURL := strings.TrimSpace(string(output))
	actualURL = strings.TrimSuffix(actualURL, ".git")
	expectedNormalized := strings.TrimSuffix(expectedURL, ".git")

	return actualURL == expectedNormalized
}

// cloneRepository performs a shallow clone of the target repository, or updates an existing cached clone
func cloneRepository(config *Config, repo RepositoryConfig) (string, error) {
	// Extract repo name from URL
	parts := strings.Split(repo.URL, "/")
	repoName := parts[len(parts)-2] + "/" + strings.TrimSuffix(parts[len(parts)-1], ".git")

	repoPath := filepath.Join(config.Global.Workspace, repoName)

	// Check if repo already exists with correct remote
	if isValidCachedRepo(repoPath, repo.URL) {
		log.Printf("  📦 Updating cached repo: %s (branch: %s)...", repoName, repo.Branch)

		// Fetch latest changes
		fetchCmd := exec.Command("git", "fetch", "origin", repo.Branch, "--depth=1")
		fetchCmd.Dir = repoPath
		if _, err := fetchCmd.CombinedOutput(); err != nil {
			log.Printf("    ⚠️  Fetch failed, will re-clone: %v", err)
			// Fall through to fresh clone
		} else {
			// Reset to fetched branch
			resetCmd := exec.Command("git", "reset", "--hard", "origin/"+repo.Branch)
			resetCmd.Dir = repoPath
			if output, err := resetCmd.CombinedOutput(); err != nil {
				return "", fmt.Errorf("git reset failed: %w\n%s", err, output)
			}
			return repoPath, nil
		}
	}

	// Remove if exists (either not valid cache or fetch failed)
	if err := os.RemoveAll(repoPath); err != nil {
		log.Printf("    ⚠️  Couldn't remove old repository: %v", err)
	}

	// Fresh clone
	log.Printf("  📥 Cloning %s (branch: %s)...", repoName, repo.Branch)
	cmd := exec.Command("git", "clone", "--depth=1", "--branch", repo.Branch, repo.URL, repoPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone failed: %w\n%s", err, output)
	}

	return repoPath, nil
}

// runScans clones/updates repositories and runs scanners against them
func runScans(config *Config) []ScanResult {
	var results []ScanResult

	for _, repo := range config.Repositories {
		log.Printf("\n📦 Processing repository: %s", repo.URL)

		// Clone or update repository
		repoPath, err := cloneRepository(config, repo)
		if err != nil {
			log.Printf("❌ Failed to clone %s: %v", repo.URL, err)
			continue
		}

		// Run scanners on this repo
		repoResults := runScannersOnRepo(config, repo, repoPath)
		results = append(results, repoResults...)

		// Check for fail-fast across all results
		for _, result := range repoResults {
			if !result.Success && config.Global.FailFast {
				return results
			}
		}
	}

	return results
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "scanners.yaml", "Path to config file")
	reposPath := flag.String("repos", "repositories.yaml", "Path to repositories config file")
	dryRun := flag.Bool("dry-run", false, "Print what would be done without executing")
	local := flag.Bool("local", false, "Scan current directory instead of cloning repos (skips upload)")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Parse timeouts
	if err := parseTimeouts(config); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Check required environment variables for all enabled scanners
	if missing := checkAllRequiredEnv(config); len(missing) > 0 {
		if !promptContinue(missing) {
			log.Fatalf("Aborted: missing required environment variables")
		}
	}

	// Local mode: scan current directory
	if *local {
		runLocalMode(config, *dryRun)
		return
	}

	// Remote mode: load and scan repositories
	repositories, err := loadRepositories(*reposPath)
	if err != nil {
		log.Fatalf("Failed to load repositories: %v", err)
	}
	config.Repositories = repositories

	log.Printf("🔍 Vulnerability Scanner Orchestrator")
	log.Printf("Config: %s", *configPath)
	log.Printf("Enabled scanners: %d", countEnabledScanners(config))
	log.Printf("Target repos: %d", len(config.Repositories))

	if *dryRun {
		log.Printf("DRY RUN MODE - No scans will be executed")
		printDryRun(config)
		return
	}

	// Create workspace and results dirs
	if err := setupDirectories(config); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	// Cleanup old scan results
	cleanupOldResults(config.Global.ResultsDir)

	// Run scans
	results := runScans(config)

	// Print summary
	printSummary(results)

	// Upload results (if configured)
	if config.Global.UploadEndpoint != "" {
		uploadResults(config, results)
	}
}

// runLocalMode scans the current directory without cloning or uploading
func runLocalMode(config *Config, dryRun bool) {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}

	// Get directory name for display
	dirName := filepath.Base(cwd)

	log.Printf("🔍 Vulnerability Scanner Orchestrator")
	log.Printf("📂 Local mode: scanning %s", cwd)
	log.Printf("Enabled scanners: %d", countEnabledScanners(config))

	if dryRun {
		log.Printf("DRY RUN MODE - No scans will be executed")
		log.Printf("\nEnabled Scanners:")
		for _, scanner := range config.Scanners {
			if scanner.Enabled {
				log.Printf("  - %s (timeout: %s)", scanner.Name, scanner.Timeout)
				log.Printf("    Command: %s %s", scanner.Command, strings.Join(scanner.Args, " "))
			}
		}
		return
	}

	// Create results directory
	if err := setupDirectories(config); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	// Cleanup old scan results
	cleanupOldResults(config.Global.ResultsDir)

	// Run scans on current directory
	results := runLocalScans(config, cwd, dirName)

	// Print summary
	printSummary(results)

	// Note: No upload in local mode
	log.Printf("📝 Local mode: results saved to %s (upload skipped)", config.Global.ResultsDir)
}

// printDryRun displays what would be executed without running anything
func printDryRun(config *Config) {
	log.Printf("\n=== DRY RUN ===\n")

	log.Printf("Global Configuration:")
	log.Printf("  Workspace: %s", config.Global.Workspace)
	log.Printf("  Results Dir: %s", config.Global.ResultsDir)
	log.Printf("  Upload Endpoint: %s", config.Global.UploadEndpoint)
	log.Printf("  Max Concurrent: %d", config.Global.MaxConcurrent)
	log.Printf("  Fail Fast: %v", config.Global.FailFast)

	log.Printf("\nEnabled Scanners:")
	for _, scanner := range config.Scanners {
		if scanner.Enabled {
			log.Printf("  - %s (timeout: %s)", scanner.Name, scanner.Timeout)
			log.Printf("    Command: %s %s", scanner.Command, strings.Join(scanner.Args, " "))
		}
	}

	log.Printf("\nRepositories:")
	for _, repo := range config.Repositories {
		log.Printf("  - %s (branch: %s)", repo.URL, repo.Branch)
		if len(repo.Scanners) > 0 {
			log.Printf("    Scanners: %v", repo.Scanners)
		} else {
			log.Printf("    Scanners: all enabled")
		}
	}
}

// cleanupOldResults removes scan result files older than resultsMaxAge
func cleanupOldResults(resultsDir string) {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  Failed to cleanup old results: %v", err)
		}
		return
	}

	cutoff := time.Now().Add(-resultsMaxAge)
	removed := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(resultsDir, entry.Name())); err == nil {
				removed++
			}
		}
	}

	if removed > 0 {
		log.Printf("🧹 Cleaned up %d old scan result(s)", removed)
	}
}
