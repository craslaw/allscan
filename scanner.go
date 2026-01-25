package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"vuln-scanner-orchestrator/parsers"
)

// runScans executes all configured scanners against all repositories
func runScans(config *Config) []ScanResult {
	var results []ScanResult

	for _, repo := range config.Repositories {
		log.Printf("\n📦 Processing repository: %s", repo.URL)

		// Clone repository
		repoPath, err := cloneRepository(config, repo)
		if err != nil {
			log.Printf("❌ Failed to clone %s: %v", repo.URL, err)
			continue
		}

		// Determine which scanners to run
		scannersToRun := getScannersForRepo(config, repo)

		// Run each scanner
		for _, scanner := range scannersToRun {
			result := runScanner(config, scanner, repo, repoPath)
			results = append(results, result)

			if !result.Success && config.Global.FailFast {
				log.Printf("⚠️  Fail-fast enabled, stopping after error")
				return results
			}
		}

		// Clean up repository clone
		err = os.RemoveAll(repoPath)
		if err != nil {
			fmt.Printf("Couldn't remove repository clone: %v\n", err)
		}
	}

	return results
}

// runLocalScans executes all enabled scanners against the current directory
func runLocalScans(config *Config, repoPath string, repoName string) []ScanResult {
	var results []ScanResult

	log.Printf("\n📂 Scanning local directory: %s", repoPath)

	// Get all enabled scanners
	var scannersToRun []ScannerConfig
	for _, scanner := range config.Scanners {
		if scanner.Enabled {
			scannersToRun = append(scannersToRun, scanner)
		}
	}

	// Create a fake repo config for the local directory
	localRepo := RepositoryConfig{
		URL:    "local://" + repoPath,
		Branch: "local",
	}

	// Run each scanner
	for _, scanner := range scannersToRun {
		result := runScannerLocal(config, scanner, localRepo, repoPath, repoName)
		results = append(results, result)

		if !result.Success && config.Global.FailFast {
			log.Printf("⚠️  Fail-fast enabled, stopping after error")
			return results
		}
	}

	return results
}

// runScannerLocal executes a single scanner against a local directory
func runScannerLocal(config *Config, scanner ScannerConfig, repo RepositoryConfig, repoPath string, repoName string) ScanResult {
	start := time.Now()

	// Create output path
	timestamp := time.Now().Format("20060102-150405")
	outputFilename := fmt.Sprintf("%s_%s_%s.json", repoName, scanner.Name, timestamp)

	// Convert to absolute path
	resultsDir, err := filepath.Abs(config.Global.ResultsDir)
	if err != nil {
		resultsDir = config.Global.ResultsDir
	}
	outputPath := filepath.Join(resultsDir, outputFilename)

	// Ensure output directory exists
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		log.Printf("    ❌ Failed to create results directory %s: %v", resultsDir, err)
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      false,
			Error:        fmt.Errorf("creating results directory: %w", err),
			Duration:     time.Since(start),
			DojoScanType: scanner.DojoScanType,
		}
	}

	log.Printf("  🔎 Running %s...", scanner.Name)

	// Handle built-in scanners
	if scanner.Command == "builtin:binary-detector" {
		count, err := parsers.RunBinaryDetector(repoPath, outputPath)
		duration := time.Since(start)
		if err != nil {
			log.Printf("    ❌ %s failed: %v", scanner.Name, err)
			return ScanResult{
				Scanner:      scanner.Name,
				Repository:   repo.URL,
				OutputPath:   outputPath,
				Success:      false,
				Error:        err,
				Duration:     duration,
				DojoScanType: scanner.DojoScanType,
			}
		}
		if count > 0 {
			log.Printf("    ✅ %s completed in %v (found %d binaries)", scanner.Name, duration, count)
		} else {
			log.Printf("    ✅ %s completed in %v", scanner.Name, duration)
		}
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      true,
			Duration:     duration,
			DojoScanType: scanner.DojoScanType,
		}
	}

	// Check if scanner binary exists
	if _, err := exec.LookPath(scanner.Command); err != nil {
		log.Printf("    ❌ Scanner %s not found in PATH", scanner.Command)
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      false,
			Error:        fmt.Errorf("scanner not found: %w", err),
			Duration:     time.Since(start),
			DojoScanType: scanner.DojoScanType,
		}
	}

	// Use local args if defined, otherwise fall back to standard args
	sourceArgs := scanner.Args
	if len(scanner.ArgsLocal) > 0 {
		sourceArgs = scanner.ArgsLocal
	}

	// Prepare arguments with template substitution
	args := make([]string, len(sourceArgs))
	for i, arg := range sourceArgs {
		args[i] = strings.ReplaceAll(arg, "{{output}}", outputPath)
	}

	// Create command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), scanner.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, scanner.Command, args...)
	cmd.Dir = repoPath

	// Capture output
	output, err := cmd.CombinedOutput()

	duration := time.Since(start)

	if err != nil {
		// Some scanners return non-zero on findings, check if output file was created
		if _, statErr := os.Stat(outputPath); statErr == nil {
			log.Printf("    ✅ %s completed in %v (with findings)", scanner.Name, duration)
			return ScanResult{
				Scanner:      scanner.Name,
				Repository:   repo.URL,
				OutputPath:   outputPath,
				Success:      true,
				Duration:     duration,
				DojoScanType: scanner.DojoScanType,
			}
		}

		log.Printf("    ❌ %s failed: %v", scanner.Name, err)
		if len(output) > 0 {
			log.Printf("    Output: %s", string(output))
		}

		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      false,
			Error:        err,
			Duration:     duration,
			DojoScanType: scanner.DojoScanType,
		}
	}

	log.Printf("    ✅ %s completed in %v", scanner.Name, duration)
	return ScanResult{
		Scanner:      scanner.Name,
		Repository:   repo.URL,
		OutputPath:   outputPath,
		Success:      true,
		Duration:     duration,
		DojoScanType: scanner.DojoScanType,
	}
}

// cloneRepository performs a shallow clone of the target repository
func cloneRepository(config *Config, repo RepositoryConfig) (string, error) {
	// Extract repo name from URL
	parts := strings.Split(repo.URL, "/")
	repoName := strings.TrimSuffix(parts[len(parts)-1], ".git")

	repoPath := filepath.Join(config.Global.Workspace, repoName)

	// Remove if exists
	err := os.RemoveAll(repoPath)
	if err != nil {
		fmt.Printf("Couldn't remove repository clone: %v\n", err)
	}

	// Clone
	log.Printf("  Cloning %s (branch: %s)...", repoName, repo.Branch)
	cmd := exec.Command("git", "clone", "--depth=1", "--branch", repo.Branch, repo.URL, repoPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone failed: %w\n%s", err, output)
	}

	return repoPath, nil
}

// getScannersForRepo determines which scanners to run on a repository
func getScannersForRepo(config *Config, repo RepositoryConfig) []ScannerConfig {
	var scanners []ScannerConfig

	// If repo specifies scanners, use only those
	if len(repo.Scanners) > 0 {
		for _, name := range repo.Scanners {
			for _, scanner := range config.Scanners {
				if scanner.Name == name && scanner.Enabled {
					scanners = append(scanners, scanner)
					break
				}
			}
		}
		return scanners
	}

	// Otherwise use all enabled scanners
	for _, scanner := range config.Scanners {
		if scanner.Enabled {
			scanners = append(scanners, scanner)
		}
	}

	return scanners
}

// runScanner executes a single scanner against a repository
func runScanner(config *Config, scanner ScannerConfig, repo RepositoryConfig, repoPath string) ScanResult {
	start := time.Now()

	// Extract repo name for output file
	parts := strings.Split(repo.URL, "/")
	repoName := strings.TrimSuffix(parts[len(parts)-1], ".git")

	// Create output path
	timestamp := time.Now().Format("20060102-150405")
	outputFilename := fmt.Sprintf("%s_%s_%s.json", repoName, scanner.Name, timestamp)

	// Convert to absolute path
	resultsDir, err := filepath.Abs(config.Global.ResultsDir)
	if err != nil {
		resultsDir = config.Global.ResultsDir
	}
	outputPath := filepath.Join(resultsDir, outputFilename)

	// Ensure output directory exists (create if needed)
	if err := os.MkdirAll(resultsDir, 0750); err != nil {
		log.Printf("    ❌ Failed to create results directory %s: %v", resultsDir, err)
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      false,
			Error:        fmt.Errorf("creating results directory: %w", err),
			Duration:     time.Since(start),
			DojoScanType: scanner.DojoScanType,
		}
	}

	log.Printf("  🔎 Running %s...", scanner.Name)

	// Handle built-in scanners
	if scanner.Command == "builtin:binary-detector" {
		count, err := parsers.RunBinaryDetector(repoPath, outputPath)
		duration := time.Since(start)
		if err != nil {
			log.Printf("    ❌ %s failed: %v", scanner.Name, err)
			return ScanResult{
				Scanner:      scanner.Name,
				Repository:   repo.URL,
				OutputPath:   outputPath,
				Success:      false,
				Error:        err,
				Duration:     duration,
				DojoScanType: scanner.DojoScanType,
			}
		}
		if count > 0 {
			log.Printf("    ✅ %s completed in %v (found %d binaries)", scanner.Name, duration, count)
		} else {
			log.Printf("    ✅ %s completed in %v", scanner.Name, duration)
		}
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      true,
			Duration:     duration,
			DojoScanType: scanner.DojoScanType,
		}
	}

	// Check if scanner binary exists
	if _, err := exec.LookPath(scanner.Command); err != nil {
		log.Printf("    ❌ Scanner %s not found in PATH", scanner.Command)
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      false,
			Error:        fmt.Errorf("scanner not found: %w", err),
			Duration:     time.Since(start),
			DojoScanType: scanner.DojoScanType,
		}
	}

	// Prepare arguments with template substitution
	args := make([]string, len(scanner.Args))
	for i, arg := range scanner.Args {
		args[i] = strings.ReplaceAll(arg, "{{output}}", outputPath)
	}

	// Create command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), scanner.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, scanner.Command, args...)
	cmd.Dir = repoPath

	// Capture output
	output, err := cmd.CombinedOutput()

	duration := time.Since(start)

	if err != nil {
		// Some scanners return non-zero on findings, check if output file was created
		if _, statErr := os.Stat(outputPath); statErr == nil {
			log.Printf("    ✅ %s completed in %v (with findings)", scanner.Name, duration)
			return ScanResult{
				Scanner:      scanner.Name,
				Repository:   repo.URL,
				OutputPath:   outputPath,
				Success:      true,
				Duration:     duration,
				DojoScanType: scanner.DojoScanType,
			}
		}

		log.Printf("    ❌ %s failed: %v", scanner.Name, err)
		if len(output) > 0 {
			log.Printf("    Output: %s", string(output))
		}

		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			OutputPath:   outputPath,
			Success:      false,
			Error:        err,
			Duration:     duration,
			DojoScanType: scanner.DojoScanType,
		}
	}

	log.Printf("    ✅ %s completed in %v", scanner.Name, duration)
	return ScanResult{
		Scanner:      scanner.Name,
		Repository:   repo.URL,
		OutputPath:   outputPath,
		Success:      true,
		Duration:     duration,
		DojoScanType: scanner.DojoScanType,
	}
}
