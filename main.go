// Allscan - Declarative security scanning for git repositories
//
// This tool orchestrates multiple security scanners against git repositories,
// aggregates results, and optionally uploads findings to DefectDojo.
package main

import (
	"flag"
	"log"
	"strings"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "scanners.yaml", "Path to config file")
	reposPath := flag.String("repos", "repositories.yaml", "Path to repositories config file")
	dryRun := flag.Bool("dry-run", false, "Print what would be done without executing")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load repositories
	repositories, err := loadRepositories(*reposPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	config.Repositories = repositories

	// Parse timeouts
	if err := parseTimeouts(config); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

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
