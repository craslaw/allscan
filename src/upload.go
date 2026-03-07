package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"allscan/parsers"
)

// uploadResults uploads all successful scan results to DefectDojo.
// If idx is non-nil, SCA scanner uploads are tagged with reachability information.
func uploadResults(config *Config, results []ScanResult, idx parsers.ReachabilityIndex) {
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

		// Compute reachability tags for SCA scanners
		var tags []string
		if idx != nil && (result.Scanner == "grype" || result.Scanner == "osv-scanner") {
			tags = computeReachabilityTags(result, idx)
		}

		if err := uploadSingleResult(config, result, authToken, tags); err != nil {
			log.Printf("  ❌ Failed to upload %s: %v", result.OutputPath, err)
			failCount++
		} else {
			log.Printf("  ✅ Uploaded %s", result.OutputPath)
			successCount++
		}
	}

	log.Printf("\n📊 Upload Summary: %d successful, %d failed", successCount, failCount)
}

// computeReachabilityTags reads an SCA scanner's output and returns DefectDojo tags
// based on reachability cross-referencing.
func computeReachabilityTags(result ScanResult, idx parsers.ReachabilityIndex) []string {
	data, err := os.ReadFile(result.OutputPath)
	if err != nil {
		return nil
	}

	var findings []parsers.SCAFinding
	switch result.Scanner {
	case "grype":
		findings, err = parsers.ExtractGrypeFindings(data)
	case "osv-scanner":
		findings, err = parsers.ExtractOSVScannerFindings(data)
	}
	if err != nil || len(findings) == 0 {
		return nil
	}

	enriched := parsers.CrossReferenceReachability(findings, idx)

	var tags []string
	if enriched.Breakdown.Reachable > 0 {
		tags = append(tags, "reachable")
	}
	if enriched.Breakdown.Unreachable > 0 {
		tags = append(tags, "unreachable")
	}
	return tags
}

// uploadSingleResult uploads a single scan result to DefectDojo.
// Optional tags are added to the upload form fields.
func uploadSingleResult(config *Config, result ScanResult, authToken string, tags []string) error {
	// Open the scan result file
	file, err := os.Open(result.OutputPath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// For NDJSON output, convert to a JSON array that DefectDojo can parse
	var uploadReader io.Reader = file
	if result.NDJSON {
		converted, convertErr := ndjsonToJSONArray(file)
		if convertErr != nil {
			return fmt.Errorf("converting NDJSON to JSON array: %w", convertErr)
		}
		// Skip upload if the converted array has no osv entries (DefectDojo rejects files with no vulnerability data)
		if !containsOSVEntries(converted) {
			log.Printf("  ⏭️  Skipping %s (no findings to upload)", filepath.Base(result.OutputPath))
			return nil
		}
		uploadReader = bytes.NewReader(converted)
	}

	productName := extractProductName(result.Repository)
	if config.Global.ProductOverride != "" {
		productName = config.Global.ProductOverride
	}

	productTypeName := "Research and Development"
	if config.Global.ProductTypeOverride != "" {
		productTypeName = config.Global.ProductTypeOverride
	}

	fields := map[string]string{
		"scan_date":           time.Now().Format("2006-01-02"),
		"product_name":        productName,
		"engagement_name":     fmt.Sprintf("%s-%s", productName, result.Scanner),
		"scan_type":           result.DojoScanType,
		"auto_create_context": "true",
		"product_type_name":   productTypeName,
		"do_not_reactivate":   "true",
	}

	// Add version information if available
	if result.CommitHash != "" {
		fields["commit_hash"] = result.CommitHash
	}
	if result.BranchTag != "" {
		fields["branch_tag"] = result.BranchTag
		fields["version"] = result.BranchTag
	}

	// Add reachability tags if provided
	if len(tags) > 0 {
		fields["tags"] = strings.Join(tags, ",")
	}

	// Build upload request using the Fluent Builder pattern
	builder := BuildUploadRequest().
		WithFile(uploadReader, filepath.Base(result.OutputPath)).
		WithAuthToken(authToken).
		WithEndpoint(config.Global.UploadEndpoint).
		AddFields(fields)
	return builder.Send()
}

// containsOSVEntries reports whether a JSON array (from ndjsonToJSONArray) contains
// at least one entry with an "osv" key, i.e., actual vulnerability findings.
func containsOSVEntries(data []byte) bool {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return false
	}
	for _, entry := range entries {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(entry, &obj); err != nil {
			continue
		}
		if _, ok := obj["osv"]; ok {
			return true
		}
	}
	return false
}

// ndjsonToJSONArray converts concatenated JSON objects into a JSON array.
// DefectDojo expects govulncheck output as a JSON array of objects,
// but govulncheck -format json outputs concatenated JSON objects (which may
// be pretty-printed across multiple lines).
//
// It also works around a DefectDojo parser bug: the parser hardcodes
// affected[0].ecosystem_specific.imports, so osv entries where affected[0]
// lacks imports data cause a crash. We reorder affected entries so the one
// with imports comes first, and drop osv entries with no imports at all.
func ndjsonToJSONArray(r io.Reader) ([]byte, error) {
	var objects []json.RawMessage
	dec := json.NewDecoder(r)
	for dec.More() {
		var obj json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			return nil, err
		}
		fixed, ok := fixOSVForDojo(obj)
		if ok {
			objects = append(objects, fixed)
		}
	}
	return json.Marshal(objects)
}

// fixOSVForDojo adjusts osv entries so DefectDojo's parser can handle them.
// Returns the (possibly modified) object and true if it should be kept,
// or nil and false if it should be dropped.
func fixOSVForDojo(raw json.RawMessage) (json.RawMessage, bool) {
	// Only process osv entries
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return raw, true
	}
	osvRaw, isOSV := envelope["osv"]
	if !isOSV {
		return raw, true
	}

	// Parse the osv object to inspect affected entries
	var osv struct {
		Affected []struct {
			EcosystemSpecific *struct {
				Imports []json.RawMessage `json:"imports"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(osvRaw, &osv); err != nil {
		return raw, true
	}

	// Find which affected entry has imports
	hasImportsIdx := -1
	for i, aff := range osv.Affected {
		if aff.EcosystemSpecific != nil && len(aff.EcosystemSpecific.Imports) > 0 {
			hasImportsIdx = i
			break
		}
	}

	// If no affected entry has imports, drop this osv (DefectDojo will crash)
	if hasImportsIdx == -1 {
		return nil, false
	}

	// If affected[0] already has imports, no fix needed
	if hasImportsIdx == 0 {
		return raw, true
	}

	// Reorder: move the affected entry with imports to index 0.
	// Re-parse the full osv as generic map to preserve all fields.
	var osvMap map[string]interface{}
	if err := json.Unmarshal(osvRaw, &osvMap); err != nil {
		return raw, true
	}
	affected, ok := osvMap["affected"].([]interface{})
	if !ok || hasImportsIdx >= len(affected) {
		return raw, true
	}
	// Swap to front
	affected[0], affected[hasImportsIdx] = affected[hasImportsIdx], affected[0]
	osvMap["affected"] = affected

	newOSV, err := json.Marshal(osvMap)
	if err != nil {
		return raw, true
	}
	envelope["osv"] = newOSV
	result, err := json.Marshal(envelope)
	if err != nil {
		return raw, true
	}
	return result, true
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
