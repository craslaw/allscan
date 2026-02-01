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

// checkRequiredEnv verifies that all required environment variables are set.
// Returns the name of the first missing variable, or empty string if all are set.
func checkRequiredEnv(required []string) string {
	for _, envVar := range required {
		if os.Getenv(envVar) == "" {
			return envVar
		}
	}
	return ""
}

// runScannersOnRepo executes all applicable scanners against a single repository
func runScannersOnRepo(config *Config, repo RepositoryConfig, repoPath string) []ScanResult {
	var results []ScanResult

	// Detect languages in the repository
	detected, err := detectLanguages(repoPath)
	if err != nil {
		log.Printf("  ⚠️  Failed to detect languages: %v", err)
		detected = &DetectedLanguages{Languages: []string{}, FileCounts: map[string]int{}}
	} else {
		logDetectedLanguages(detected)
	}

	// Determine which scanners to run based on repo config and detected languages
	scannersToRun := getScannersForRepo(config, repo, detected)

	// Run each scanner
	for _, scanner := range scannersToRun {
		result := runScanner(config, scanner, repo, repoPath)
		results = append(results, result)

		if !result.Success && config.Global.FailFast {
			log.Printf("⚠️  Fail-fast enabled, stopping after error")
			return results
		}
	}

	return results
}

// runLocalScans executes all enabled scanners against the current directory
func runLocalScans(config *Config, repoPath string, repoName string) []ScanResult {
	var results []ScanResult

	log.Printf("\n📂 Scanning local directory: %s", repoPath)

	// Detect languages in the directory
	detected, err := detectLanguages(repoPath)
	if err != nil {
		log.Printf("  ⚠️  Failed to detect languages: %v", err)
		detected = &DetectedLanguages{Languages: []string{}, FileCounts: map[string]int{}}
	} else {
		logDetectedLanguages(detected)
	}

	// Create a fake repo config for the local directory
	localRepo := RepositoryConfig{
		URL:    "local://" + repoPath,
		Branch: "local",
	}

	// Get scanners compatible with detected languages
	scannersToRun := getScannersForRepo(config, localRepo, detected)

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

	// Check required environment variables before doing any work
	if missing := checkRequiredEnv(scanner.RequiredEnv); missing != "" {
		log.Printf("    ⏭️  Skipping %s: required env var %s not set", scanner.Name, missing)
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			Success:      false,
			Error:        fmt.Errorf("required environment variable %s not set", missing),
			Duration:     time.Since(start),
			DojoScanType: scanner.DojoScanType,
		}
	}

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
		arg = strings.ReplaceAll(arg, "{{output}}", outputPath)
		arg = strings.ReplaceAll(arg, "{{repo}}", repo.URL)
		args[i] = arg
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


// getScannersForRepo determines which scanners to run on a repository
// It filters based on repo-specific scanner list, enabled status, and language compatibility
func getScannersForRepo(config *Config, repo RepositoryConfig, detected *DetectedLanguages) []ScannerConfig {
	var scanners []ScannerConfig

	// If repo specifies scanners, use only those (still filtered by language)
	if len(repo.Scanners) > 0 {
		for _, name := range repo.Scanners {
			for _, scanner := range config.Scanners {
				if scanner.Name == name && scanner.Enabled {
					if isScannerCompatible(scanner, detected) {
						scanners = append(scanners, scanner)
					} else {
						log.Printf("    ⏭️  Skipping %s: no compatible languages detected", scanner.Name)
					}
					break
				}
			}
		}
		return scanners
	}

	// Otherwise use all enabled scanners that are compatible with detected languages
	for _, scanner := range config.Scanners {
		if scanner.Enabled {
			if isScannerCompatible(scanner, detected) {
				scanners = append(scanners, scanner)
			} else {
				log.Printf("    ⏭️  Skipping %s: no compatible languages detected", scanner.Name)
			}
		}
	}

	return scanners
}

// isScannerCompatible checks if a scanner should run based on detected languages
// Scanners with empty Languages list are considered universal and always run
func isScannerCompatible(scanner ScannerConfig, detected *DetectedLanguages) bool {
	// If scanner has no language restrictions, it's compatible with everything
	if len(scanner.Languages) == 0 {
		return true
	}

	// If no languages were detected but scanner requires specific languages, skip it
	if len(detected.Languages) == 0 {
		return false
	}

	// Check if any of the scanner's supported languages were detected
	return detected.hasAnyLanguage(scanner.Languages)
}

// runScanner executes a single scanner against a repository
func runScanner(config *Config, scanner ScannerConfig, repo RepositoryConfig, repoPath string) ScanResult {
	start := time.Now()

	// Check required environment variables before doing any work
	if missing := checkRequiredEnv(scanner.RequiredEnv); missing != "" {
		log.Printf("    ⏭️  Skipping %s: required env var %s not set", scanner.Name, missing)
		return ScanResult{
			Scanner:      scanner.Name,
			Repository:   repo.URL,
			Success:      false,
			Error:        fmt.Errorf("required environment variable %s not set", missing),
			Duration:     time.Since(start),
			DojoScanType: scanner.DojoScanType,
		}
	}

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
		arg = strings.ReplaceAll(arg, "{{output}}", outputPath)
		arg = strings.ReplaceAll(arg, "{{repo}}", repo.URL)
		args[i] = arg
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
