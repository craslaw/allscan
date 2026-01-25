package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

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
	FilePatterns []string      `yaml:"file_patterns"`
	Timeout      string        `yaml:"timeout"`
	timeout      time.Duration // parsed timeout (unexported)
	DojoScanType string        `yaml:"dojo_scan_type"`
}

// RepositoryConfig defines a target repository to scan
type RepositoryConfig struct {
	URL      string   `yaml:"url"`
	Branch   string   `yaml:"branch"`
	Scanners []string `yaml:"scanners"` // Optional: specific scanners to run
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
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	return nil
}
