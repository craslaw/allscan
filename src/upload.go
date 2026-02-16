package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// uploadResults uploads all successful scan results to DefectDojo
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

		// Skip scanners without a DefectDojo scan type (stdout-only scanners)
		if result.DojoScanType == "" {
			log.Printf("  ⏭️  Skipping %s (no DefectDojo scan type configured)", result.Scanner)
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

// uploadSingleResult uploads a single scan result to DefectDojo
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
		"scan_type":           result.DojoScanType,
		"auto_create_context": "true",
		"product_type_name":   "Research and Development",
		"do_not_reactivate":   "true",
	}

	// Add version information if available
	if result.CommitHash != "" {
		fields["commit_hash"] = result.CommitHash
	}
	if result.BranchTag != "" {
		fields["branch_tag"] = result.BranchTag
	}

	// Build upload request using the Fluent Builder pattern
	builder := BuildUploadRequest().
		WithFile(file, filepath.Base(result.OutputPath)).
		WithAuthToken(authToken).
		WithEndpoint(config.Global.UploadEndpoint).
		AddFields(fields)
	return builder.Send()
}

// extractProductName extracts a clean product name from repository URL
func extractProductName(repoURL string) string {
	// Example: https://github.com/your-org/my-repo -> your-org/my-repo
	parts := strings.Split(repoURL, "/")
	if len(parts) > 0 {
		repoName := parts[len(parts)-2] + "/" + parts[len(parts)-1]
		repoName = strings.TrimSuffix(repoName, ".git")
		return repoName
	}
	return "unknown"
}

// ============================================================================
// Upload Request Builder - Fluent Builder Pattern
// ============================================================================

// UploadRequestBuilder constructs multipart form requests for DefectDojo uploads
type UploadRequestBuilder struct {
	fields    map[string]string
	file      io.Reader
	filename  string
	authToken string
	endpoint  string
	timeout   time.Duration
}

// BuildUploadRequest creates a new upload request builder with sensible defaults
func BuildUploadRequest() *UploadRequestBuilder {
	return &UploadRequestBuilder{
		fields:  make(map[string]string),
		timeout: 30 * time.Second,
	}
}

// WithFile sets the file to upload
func (b *UploadRequestBuilder) WithFile(file io.Reader, filename string) *UploadRequestBuilder {
	b.file = file
	b.filename = filename
	return b
}

// WithAuthToken sets the authentication token
func (b *UploadRequestBuilder) WithAuthToken(token string) *UploadRequestBuilder {
	b.authToken = token
	return b
}

// WithEndpoint sets the upload endpoint URL
func (b *UploadRequestBuilder) WithEndpoint(endpoint string) *UploadRequestBuilder {
	b.endpoint = endpoint
	return b
}

// WithTimeout sets a custom timeout (default: 30s)
func (b *UploadRequestBuilder) WithTimeout(timeout time.Duration) *UploadRequestBuilder {
	b.timeout = timeout
	return b
}

// AddFields adds multiple form fields to the request
func (b *UploadRequestBuilder) AddFields(fields map[string]string) *UploadRequestBuilder {
	for name, value := range fields {
		b.fields[name] = value
	}
	return b
}

// Build constructs the HTTP request without sending it
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

// Send builds and sends the request
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
