package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"allscan/parsers"
)

// selectArgs picks the right args for a scanner based on SARIF and local mode.
// Priority chain:
//   SARIF+local: args_sarif_local > args_sarif > args_local > args
//   SARIF+repo:  args_sarif > args
//   JSON+local:  args_local > args
//   JSON+repo:   args
// Returns (args, isSarif) where isSarif is true only when SARIF-specific args were selected.
func selectArgs(scanner ScannerConfig, sarifMode, localMode bool) ([]string, bool) {
	if sarifMode {
		if localMode {
			if len(scanner.ArgsSarifLocal) > 0 {
				return scanner.ArgsSarifLocal, true
			}
			if len(scanner.ArgsSarif) > 0 {
				return scanner.ArgsSarif, true
			}
			// Fall back to non-SARIF local/default args
			if len(scanner.ArgsLocal) > 0 {
				return scanner.ArgsLocal, false
			}
			return scanner.Args, false
		}
		if len(scanner.ArgsSarif) > 0 {
			return scanner.ArgsSarif, true
		}
		return scanner.Args, false
	}
	if localMode && len(scanner.ArgsLocal) > 0 {
		return scanner.ArgsLocal, false
	}
	return scanner.Args, false
}

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

// isLocalRepo returns true if the repository uses the local:// URL scheme.
func isLocalRepo(repo RepositoryConfig) bool {
	return strings.HasPrefix(repo.URL, "local://")
}

// repoName extracts a short name from the repository config.
// For local repos it returns the directory base name; for remote URLs the last path segment.
func repoName(repo RepositoryConfig) string {
	if isLocalRepo(repo) {
		return filepath.Base(strings.TrimPrefix(repo.URL, "local://"))
	}
	parts := strings.Split(repo.URL, "/")
	return strings.TrimSuffix(parts[len(parts)-1], ".git")
}

// runScannersOnRepo executes all applicable scanners against a single repository
func runScannersOnRepo(config *Config, repo RepositoryConfig, repoPath, commitHash, branchTag, sbomPath string) RepoScanContext {
	var results []ScanResult

	// Detect languages in the repository (tries GitHub API first, then filesystem)
	detected, err := detectLanguages(repoPath, repo.URL)
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
		result := runScanner(config, scanner, repo, repoPath, commitHash, branchTag, sbomPath)
		results = append(results, result)

		if !result.Success && config.Global.FailFast {
			log.Printf("⚠️  Fail-fast enabled, stopping after error")
			break
		}
	}

	return RepoScanContext{
		RepoURL:   repo.URL,
		Results:   results,
		Languages: detected,
		Scanners:  scannersToRun,
		SBOMPath:  sbomPath,
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
// Scanners with empty Languages list are considered universal and always run.
// Scanners also run if a detected language matches LanguagesConditional.
func isScannerCompatible(scanner ScannerConfig, detected *DetectedLanguages) bool {
	// If scanner has no language restrictions, it's compatible with everything
	if len(scanner.Languages) == 0 {
		return true
	}

	// If no languages were detected but scanner requires specific languages, skip it
	if len(detected.Languages) == 0 {
		return false
	}

	// Check full language support first
	if detected.hasAnyLanguage(scanner.Languages) {
		return true
	}

	// Also run if any conditionally-supported language is detected
	return detected.hasAnyLanguage(scanner.LanguagesConditional)
}

// runScanner executes a single scanner against a repository
func runScanner(config *Config, scanner ScannerConfig, repo RepositoryConfig, repoPath, commitHash, branchTag, sbomPath string) ScanResult {
	start := time.Now()

	// Select args based on SARIF and local mode
	localMode := isLocalRepo(repo)
	selectedArgs, isSarif := selectArgs(scanner, config.Global.SarifMode, localMode)

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
			CommitHash:   commitHash,
			BranchTag:    branchTag,
		}
	}

	// Extract repo name for output file
	name := repoName(repo)

	// Create output path with appropriate extension
	timestamp := time.Now().Format("20060102-150405")
	ext := ".json"
	if isSarif {
		ext = ".sarif"
	}
	outputFilename := fmt.Sprintf("%s_%s_%s%s", name, scanner.Name, timestamp, ext)

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
			CommitHash:   commitHash,
			BranchTag:    branchTag,
		}
	}

	log.Printf("  🔎 Running %s...", scanner.Name)

	// Handle built-in scanners
	if scanner.Command == "builtin:binary-detector" {
		builtinSarif := config.Global.SarifMode
		actualOutputPath := outputPath
		if builtinSarif {
			actualOutputPath = strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".sarif"
		}
		count, err := parsers.RunBinaryDetector(repoPath, actualOutputPath, builtinSarif)
		duration := time.Since(start)
		if err != nil {
			log.Printf("    ❌ %s failed: %v", scanner.Name, err)
			return ScanResult{
				Scanner:      scanner.Name,
				Repository:   repo.URL,
				OutputPath:   actualOutputPath,
				Success:      false,
				Error:        err,
				Duration:     duration,
				DojoScanType: scanner.DojoScanType,
				CommitHash:   commitHash,
				BranchTag:    branchTag,
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
			OutputPath:   actualOutputPath,
			Success:      true,
			Duration:     duration,
			DojoScanType: scanner.DojoScanType,
			CommitHash:   commitHash,
			BranchTag:    branchTag,
			IsSarif:      builtinSarif,
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
			CommitHash:   commitHash,
			BranchTag:    branchTag,
		}
	}

	// Check if this scanner writes to {{output}} itself or is stdout-only
	stdoutOnly := true
	for _, arg := range selectedArgs {
		if strings.Contains(arg, "{{output}}") {
			stdoutOnly = false
			break
		}
	}

	// Prepare arguments with template substitution
	args := make([]string, len(selectedArgs))
	for i, arg := range selectedArgs {
		arg = strings.ReplaceAll(arg, "{{output}}", outputPath)
		arg = strings.ReplaceAll(arg, "{{repo}}", repo.URL)
		arg = strings.ReplaceAll(arg, "{{sbom}}", sbomPath)
		args[i] = arg
	}

	// Create command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), scanner.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, scanner.Command, args...)
	cmd.Dir = repoPath

	// Capture output — for stdout-only scanners, keep stdout separate from stderr
	// so that progress messages on stderr don't corrupt the JSON output.
	var output []byte
	if stdoutOnly {
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()
		output = stdout.Bytes()
	} else {
		output, err = cmd.CombinedOutput()
	}

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
				CommitHash:   commitHash,
				BranchTag:    branchTag,
				IsSarif:      isSarif,
			}
		}

		// Stdout-only scanners that exit non-zero may still have valid output
		if stdoutOnly && len(output) > 0 {
			if writeErr := os.WriteFile(outputPath, output, 0644); writeErr == nil {
				log.Printf("    ✅ %s completed in %v (with findings)", scanner.Name, duration)
				return ScanResult{
					Scanner:      scanner.Name,
					Repository:   repo.URL,
					OutputPath:   outputPath,
					Success:      true,
					Duration:     duration,
					DojoScanType: scanner.DojoScanType,
					CommitHash:   commitHash,
					BranchTag:    branchTag,
					IsSarif:      isSarif,
				}
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
			CommitHash:   commitHash,
			BranchTag:    branchTag,
			IsSarif:      isSarif,
			NDJSON:       scanner.NDJSON,
		}
	}

	// Stdout-only scanners: write captured stdout to the output file
	if stdoutOnly && len(output) > 0 {
		if writeErr := os.WriteFile(outputPath, output, 0644); writeErr != nil {
			log.Printf("    ⚠️  %s completed but failed to write output: %v", scanner.Name, writeErr)
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
		CommitHash:   commitHash,
		BranchTag:    branchTag,
		IsSarif:      isSarif,
		NDJSON:       scanner.NDJSON,
	}
}
