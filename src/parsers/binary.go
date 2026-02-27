package parsers

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// Binary Detector - Detects binary files in repositories
// ============================================================================

// BinaryParser parses binary detection scan results.
// Binary files in source repos can indicate committed build artifacts,
// malware, or other suspicious content.
type BinaryParser struct{}

// BinaryOutput represents the JSON output from the binary detector
type BinaryOutput struct {
	Binaries []BinaryFile `json:"binaries"`
	Total    int          `json:"total"`
}

// BinaryFile represents a detected binary file
type BinaryFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Reason string `json:"reason"` // Why it was flagged (extension, magic bytes, etc.)
}

func (p *BinaryParser) Name() string { return "binary-detector" }
func (p *BinaryParser) Type() string { return "Binary" }
func (p *BinaryParser) Icon() string { return "📀" }

func (p *BinaryParser) Parse(data []byte) (FindingSummary, error) {
	var output BinaryOutput
	var summary FindingSummary

	if err := json.Unmarshal(data, &output); err != nil {
		return summary, err
	}

	summary.Total = output.Total
	// Treat all binaries as medium severity (suspicious but not critical)
	summary.Medium = output.Total

	return summary, nil
}

// Verify BinaryParser implements SCAParser
var _ SCAParser = (*BinaryParser)(nil)

// ============================================================================
// Binary Detector Scanner Logic
// ============================================================================

// Common binary file extensions
var binaryExtensions = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".a": true,
	".o": true, ".obj": true, ".bin": true, ".com": true, ".class": true,
	".pyc": true, ".pyo": true, ".jar": true, ".war": true, ".ear": true,
	".whl": true, ".egg": true, ".deb": true, ".rpm": true, ".msi": true,
	".dmg": true, ".pkg": true, ".app": true, ".ipa": true, ".apk": true,
	".wasm": true, ".node": true,
}

// SARIF 2.1.0 structs (minimal, only what's needed for binary-detector output)
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
}
type sarifDefaultConfig struct {
	Level string `json:"level"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}
type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

// RunBinaryDetector scans for binary files and writes JSON or SARIF output.
// Returns the count of binaries found.
func RunBinaryDetector(repoPath string, outputPath string, sarifMode bool) (int, error) {
	var binaries []BinaryFile

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip directories and hidden paths
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		// Get relative path for cleaner output
		relPath, _ := filepath.Rel(repoPath, path)

		// Check by extension first (fast path)
		ext := strings.ToLower(filepath.Ext(path))
		if binaryExtensions[ext] {
			info, _ := d.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			binaries = append(binaries, BinaryFile{
				Path:   relPath,
				Size:   size,
				Reason: "binary extension: " + ext,
			})
			return nil
		}

		// Check file content for binary data (null bytes in first 8KB)
		if isBinaryFile(path) {
			info, _ := d.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			binaries = append(binaries, BinaryFile{
				Path:   relPath,
				Size:   size,
				Reason: "binary content detected",
			})
		}

		return nil
	})

	if err != nil {
		return 0, err
	}

	var data []byte
	if sarifMode {
		// Build SARIF output
		results := make([]sarifResult, 0, len(binaries))
		for _, b := range binaries {
			results = append(results, sarifResult{
				RuleID: "BINARY001",
				Level:  "warning",
				Message: sarifMessage{
					Text: "Binary file detected: " + b.Reason,
				},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:       b.Path,
							URIBaseID: "%SRCROOT%",
						},
					},
				}},
			})
		}
		log := sarifLog{
			Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
			Version: "2.1.0",
			Runs: []sarifRun{{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name: "binary-detector",
						Rules: []sarifRule{{
							ID:               "BINARY001",
							Name:             "BinaryFileDetected",
							ShortDescription: sarifMessage{Text: "Binary file detected in repository"},
							DefaultConfig:    sarifDefaultConfig{Level: "warning"},
						}},
					},
				},
				Results: results,
			}},
		}
		var err error
		data, err = json.MarshalIndent(log, "", "  ")
		if err != nil {
			return 0, err
		}
	} else {
		// Write JSON output
		output := BinaryOutput{
			Binaries: binaries,
			Total:    len(binaries),
		}
		var err error
		data, err = json.MarshalIndent(output, "", "  ")
		if err != nil {
			return 0, err
		}
	}

	if err := os.WriteFile(outputPath, data, 0640); err != nil {
		return 0, err
	}

	return len(binaries), nil
}

// isBinaryFile checks if a file contains binary data by looking for null bytes
func isBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read first 8KB
	buf := make([]byte, 8192)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	// Check for null bytes (common indicator of binary content)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}

	return false
}
