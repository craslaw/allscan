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
func (p *BinaryParser) Type() string { return "SCA" }
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

// RunBinaryDetector scans for binary files and writes JSON output.
// Returns the count of binaries found.
func RunBinaryDetector(repoPath string, outputPath string) (int, error) {
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

	// Write JSON output
	output := BinaryOutput{
		Binaries: binaries,
		Total:    len(binaries),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return 0, err
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
