// Allscan - Declarative security scanning for git repositories
//
// This tool orchestrates multiple security scanners against git repositories,
// aggregates results, and optionally uploads findings to DefectDojo.
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
)

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
