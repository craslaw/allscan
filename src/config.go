package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// commitHashPattern matches valid git commit hashes (7-40 hex characters)
var commitHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// Config holds the complete application configuration
type Config struct {
	Global       GlobalConfig       `yaml:"global"`
	Scanners     []ScannerConfig    `yaml:"scanners"`
	Repositories []RepositoryConfig `yaml:"repositories"`
}

// GlobalConfig holds global settings for the scanner orchestrator
type GlobalConfig struct {
	Workspace      string `yaml:"workspace"`
	ResultsDir     string `yaml:"results_dir"`
	UploadEndpoint string `yaml:"upload_endpoint"`
	MaxConcurrent  int    `yaml:"max_concurrent"`
	FailFast       bool   `yaml:"fail_fast"`
}

// ScannerConfig defines a security scanner and its execution parameters
type ScannerConfig struct {
	Name         string        `yaml:"name"`
	Enabled      bool          `yaml:"enabled"`
	Command      string        `yaml:"command"`
	Args         []string      `yaml:"args"`
	ArgsLocal    []string      `yaml:"args_local"`    // Optional: override args for --local mode
	FilePatterns          []string      `yaml:"file_patterns"`
	Languages             []string      `yaml:"languages"`              // Languages with full support (empty = all languages)
	LanguagesConditional  []string      `yaml:"languages_conditional"`  // Languages with conditional support (requires specific package manager files)
	Timeout      string        `yaml:"timeout"`
	timeout      time.Duration // parsed timeout (unexported)
	DojoScanType string        `yaml:"dojo_scan_type"`
	RequiredEnv  []string      `yaml:"required_env"` // Environment variables that must be set
}

// RepositoryConfig defines a target repository to scan
type RepositoryConfig struct {
	URL      string   `yaml:"url"`
	Branch   string   `yaml:"branch"`
	Version  string   `yaml:"version,omitempty"`  // Tag name (e.g., "v1.2.3") - highest precedence
	Commit   string   `yaml:"commit,omitempty"`   // Commit SHA (7-40 hex chars)
	Scanners []string `yaml:"scanners"`           // Optional: specific scanners to run
}

// ScanResult holds the outcome of running a scanner on a repository
type ScanResult struct {
	Scanner      string
	Repository   string
	OutputPath   string
	Success      bool
	Error        error
	Duration     time.Duration
	DojoScanType string
	CommitHash   string // Actual commit hash scanned (short format)
	BranchTag    string // Branch or tag name (for DefectDojo)
}

// RepoScanContext bundles scan results with the language and scanner metadata
// needed to render a per-repo coverage matrix in the summary.
type RepoScanContext struct {
	RepoURL   string
	Results   []ScanResult
	Languages *DetectedLanguages
	Scanners  []ScannerConfig // scanners selected to run on this repo
	SBOMPath  string          // path to generated CycloneDX SBOM (empty if generation failed)
}

// ValidateRepositoryConfig validates a repository configuration
func ValidateRepositoryConfig(repo RepositoryConfig) error {
	// URL is required
	if repo.URL == "" {
		return fmt.Errorf("repository URL is required")
	}

	// At least one of branch/version/commit must be specified
	if repo.Branch == "" && repo.Version == "" && repo.Commit == "" {
		return fmt.Errorf("at least one of branch, version, or commit must be specified")
	}

	// Validate commit hash format if provided
	if repo.Commit != "" {
		if !commitHashPattern.MatchString(repo.Commit) {
			return fmt.Errorf("invalid commit hash %q: must be 7-40 hexadecimal characters", repo.Commit)
		}
	}

	return nil
}

// loadConfig reads and parses the scanner configuration file
func loadConfig(path string) (*Config, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Set defaults
	if config.Global.Workspace == "" {
		config.Global.Workspace = "/tmp/scanner-workspace"
	}
	if config.Global.ResultsDir == "" {
		config.Global.ResultsDir = "./scan-results"
	}
	if config.Global.MaxConcurrent == 0 {
		config.Global.MaxConcurrent = 3
	}

	return &config, nil
}

// loadRepositories reads and parses the repositories configuration file
func loadRepositories(path string) ([]RepositoryConfig, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading repositories file: %w", err)
	}

	var repoConfig struct {
		Repositories []RepositoryConfig `yaml:"repositories"`
	}

	if err := yaml.Unmarshal(data, &repoConfig); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	return repoConfig.Repositories, nil
}

// parseTimeouts parses timeout strings into time.Duration for each scanner
func parseTimeouts(config *Config) error {
	for i := range config.Scanners {
		if config.Scanners[i].Timeout == "" {
			config.Scanners[i].timeout = 5 * time.Minute
			continue
		}
		duration, err := time.ParseDuration(config.Scanners[i].Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout for %s: %w", config.Scanners[i].Name, err)
		}
		config.Scanners[i].timeout = duration
	}
	return nil
}

// countEnabledScanners returns the number of enabled scanners
func countEnabledScanners(config *Config) int {
	count := 0
	for _, s := range config.Scanners {
		if s.Enabled {
			count++
		}
	}
	return count
}

// setupDirectories creates workspace and results directories
func setupDirectories(config *Config) error {
	dirs := []string{
		config.Global.Workspace,
		config.Global.ResultsDir,
		filepath.Join(config.Global.ResultsDir, "sboms"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	return nil
}
