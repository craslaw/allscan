package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config structs
type Config struct {
	Global       GlobalConfig       `yaml:"global"`
	Scanners     []ScannerConfig    `yaml:"scanners"`
	Repositories []RepositoryConfig `yaml:"repositories"`
}

type GlobalConfig struct {
	Workspace      string `yaml:"workspace"`
	ResultsDir     string `yaml:"results_dir"`
	UploadEndpoint string `yaml:"upload_endpoint"`
	MaxConcurrent  int    `yaml:"max_concurrent"`
	FailFast       bool   `yaml:"fail_fast"`
}

type ScannerConfig struct {
	Name         string        `yaml:"name"`
	Enabled      bool          `yaml:"enabled"`
	Command      string        `yaml:"command"`
	Args         []string      `yaml:"args"`
	FilePatterns []string      `yaml:"file_patterns"`
	Timeout      string        `yaml:"timeout"`
	timeout      time.Duration // parsed timeout
}

// Target Repositories
type RepositoryConfig struct {
	URL      string   `yaml:"url"`
	Branch   string   `yaml:"branch"`
	Scanners []string `yaml:"scanners"`
}

type ScanResult struct {
	Scanner    string
	Repository string
	OutputPath string
	Success    bool
	Error      error
	Duration   time.Duration
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "scanners.yaml", "Path to configuration file")
	dryRun := flag.Bool("dry-run", false, "Print what would be done without executing")
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

func loadConfig(path string) (*Config, error) {
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

func countEnabledScanners(config *Config) int {
	count := 0
	for _, s := range config.Scanners {
		if s.Enabled {
			count++
		}
	}
	return count
}

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

// Create workspace and results directories
func setupDirectories(config *Config) error {
	dirs := []string{
		config.Global.Workspace,
		config.Global.ResultsDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	return nil
}

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
		os.RemoveAll(repoPath)
	}

	return results
}

func cloneRepository(config *Config, repo RepositoryConfig) (string, error) {
	// Extract repo name from URL
	parts := strings.Split(repo.URL, "/")
	repoName := strings.TrimSuffix(parts[len(parts)-1], ".git")

	repoPath := filepath.Join(config.Global.Workspace, repoName)

	// Remove if exists
	os.RemoveAll(repoPath)

	// Clone
	log.Printf("  Cloning %s (branch: %s)...", repoName, repo.Branch)
	cmd := exec.Command("git", "clone", "--depth=1", "--branch", repo.Branch, repo.URL, repoPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone failed: %w\n%s", err, output)
	}

	return repoPath, nil
}

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
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Printf("    ❌ Failed to create results directory %s: %v", resultsDir, err)
		return ScanResult{
			Scanner:    scanner.Name,
			Repository: repo.URL,
			OutputPath: outputPath,
			Success:    false,
			Error:      fmt.Errorf("creating results directory: %w", err),
			Duration:   time.Since(start),
		}
	}

	log.Printf("  🔎 Running %s...", scanner.Name)

	// Check if scanner binary exists
	if _, err := exec.LookPath(scanner.Command); err != nil {
		log.Printf("    ❌ Scanner %s not found in PATH", scanner.Command)
		return ScanResult{
			Scanner:    scanner.Name,
			Repository: repo.URL,
			OutputPath: outputPath,
			Success:    false,
			Error:      fmt.Errorf("scanner not found: %w", err),
			Duration:   time.Since(start),
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
				Scanner:    scanner.Name,
				Repository: repo.URL,
				OutputPath: outputPath,
				Success:    true,
				Duration:   duration,
			}
		}

		log.Printf("    ❌ %s failed: %v", scanner.Name, err)
		if len(output) > 0 {
			log.Printf("    Output: %s", string(output))
		}

		return ScanResult{
			Scanner:    scanner.Name,
			Repository: repo.URL,
			OutputPath: outputPath,
			Success:    false,
			Error:      err,
			Duration:   duration,
		}
	}

	log.Printf("    ✅ %s completed in %v", scanner.Name, duration)
	return ScanResult{
		Scanner:    scanner.Name,
		Repository: repo.URL,
		OutputPath: outputPath,
		Success:    true,
		Duration:   duration,
	}
}

func printSummary(results []ScanResult) {
	separator := strings.Repeat("=", 60)
	log.Print("\n" + separator + "\n")
	log.Println("📊 SCAN SUMMARY")
	log.Print(separator + "\n")

	successful := 0
	failed := 0
	totalDuration := time.Duration(0)

	for _, result := range results {
		totalDuration += result.Duration
		if result.Success {
			successful++
			log.Printf("✅ %s on %s: SUCCESS (%v)", 
				result.Scanner, result.Repository, result.Duration)
		} else {
			failed++
			log.Printf("❌ %s on %s: FAILED (%v) - %v", 
				result.Scanner, result.Repository, result.Duration, result.Error)
		}
	}

	log.Print(separator + "\n")
	log.Printf("Total scans: %d", len(results))
	log.Printf("Successful: %d", successful)
	log.Printf("Failed: %d", failed)
	log.Printf("Total time: %v", totalDuration)
	log.Print(separator + "\n")
}

func uploadResults(config *Config, results []ScanResult) {
	log.Printf("\n📤 Uploading results to %s", config.Global.UploadEndpoint)

	// Get authorization token from environment
	authToken := os.Getenv("VULN_MGMT_API_TOKEN")
	if authToken == "" {
		log.Printf("⚠️  VULN_MGMT_API_TOKEN not set, skipping upload")
		return
	}

	successCount := 0
	failCount := 0

	for _, result := range results {
		if !result.Success {
			log.Printf("  ⏭️  Skipping %s (scan failed)", result.OutputPath)
			continue
		}

		if err := uploadSingleResult(config, result, authToken); err != nil {
			log.Printf("  ❌ Failed to upload %s: %v", result.OutputPath, err)
			failCount++
		} else {
			log.Printf("  ✅ Uploaded %s", result.OutputPath)
			successCount++
		}
	}

	log.Printf("\n📊 Upload Summary: %d successful, %d failed", successCount, failCount)
}

// Create a new scan upload request builder with sensible defaults
func BuildUploadRequest() *UploadRequestBuilder {
	return &UploadRequestBuilder{
		fields:  make(map[string]string),
		timeout: 30 * time.Second,
	}
}

func uploadSingleResult(config *Config, result ScanResult, authToken string) error {
	// Open the scan result file
	file, err := os.Open(result.OutputPath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	fields := map[string]string{
		"scan_date":           time.Now().Format("2006-01-02"),
		"product_name":        extractProductName(result.Repository),
		"engagement_name":     fmt.Sprintf("%s-%s", extractProductName(result.Repository), result.Scanner),
		"scan_type":           mapScannerToScanType(result.Scanner),
		"auto_create_context": "true",
		"product_type_name":   "Research and Development",
		"do_not_reactivate":   "true",
	}

	// Build upload request using the Fluent Builder pattern
	builder := BuildUploadRequest().
		WithFile(file, filepath.Base(result.OutputPath)).
		WithAuthToken(authToken).
		WithEndpoint(config.Global.UploadEndpoint).
		AddFields(fields)
	return builder.Send()
}

type UploadRequestBuilder struct {
	fields    map[string]string
	file      io.Reader
	filename  string
	authToken string
	endpoint  string
	timeout   time.Duration
}

// Set the file to upload
func (b *UploadRequestBuilder) WithFile(file io.Reader, filename string) *UploadRequestBuilder {
	b.file = file
	b.filename = filename
	return b
}

// Set the auth token
func (b *UploadRequestBuilder) WithAuthToken(token string) *UploadRequestBuilder {
	b.authToken = token
	return b
}

// Set the upload endpoint URL
func (b *UploadRequestBuilder) WithEndpoint(endpoint string) *UploadRequestBuilder {
	b.endpoint = endpoint
	return b
}

// Set custom timeout (default: 30s)
func (b *UploadRequestBuilder) WithTimeout(timeout time.Duration) *UploadRequestBuilder {
	b.timeout = timeout
	return b
}

// Add multiple form fields to the request at once
func (b *UploadRequestBuilder) AddFields(fields map[string]string) *UploadRequestBuilder {
	for name, value := range fields {
		b.fields[name] = value
	}
	return b
}

// Build the request without sending
func (b *UploadRequestBuilder) Build() (*http.Request, error) {
	if b.endpoint == "" {
		return nil, fmt.Errorf("upload endpoint not set")
	}
	if b.file == nil {
		return nil, fmt.Errorf("file not set")
	}

	// Create multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add all form fields
	for name, value := range b.fields {
		if err := writer.WriteField(name, value); err != nil {
			return nil, fmt.Errorf("writing field %s: %w", name, err)
		}
	}

	// Add the file
	part, err := writer.CreateFormFile("file", b.filename)
	if err != nil {
		return nil, fmt.Errorf("creating form file: %w", err)
	}

	if _, err := io.Copy(part, b.file); err != nil {
		return nil, fmt.Errorf("copying file data: %w", err)
	}

	// Close the multipart writer to finalize the form data
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing writer: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", b.endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if b.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", b.authToken))
	}

	return req, nil
}

// Send() Builds then send the request
func (b *UploadRequestBuilder) Send() error {
	req, err := b.Build()
	if err != nil {
		return err
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: b.timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// extractProductName extracts a clean product name from repository URL
func extractProductName(repoURL string) string {
	// Example: https://github.com/your-org/my-repo -> my-repo
	parts := strings.Split(repoURL, "/")
	if len(parts) > 0 {
		repoName := parts[len(parts)-2] + "/" + parts[len(parts)-1]
		repoName = strings.TrimSuffix(repoName, ".git")
		return repoName
	}
	return "unknown"
}

// mapScannerToScanType maps scanner names to vulnerability management scan types
func mapScannerToScanType(scannerName string) string {
	// Map scanner names to common scan type names
	// Adjust these based on your vulnerability management system's scan types
	mapping := map[string]string{
		"gosec":         "Gosec Scanner",
		"semgrep":       "Semgrep Scan",
		"gitleaks":      "Gitleaks Scan",
		"golangci-lint": "Golangci-lint",
	}

	if scanType, ok := mapping[scannerName]; ok {
		return scanType
	}

	// Default: capitalize scanner name
	return strings.Title(scannerName) + " Scan"
}
