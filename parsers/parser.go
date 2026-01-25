// Package parsers provides interfaces and implementations for parsing
// security scanner output files.
package parsers

// FindingSummary holds parsed findings counts by severity for display
type FindingSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// ResultParser is the base interface for all scanner result parsers.
// Implement this interface to add support for new scanners.
type ResultParser interface {
	// Parse reads scanner output and returns a summary of findings
	Parse(data []byte) (FindingSummary, error)

	// Type returns the scanner category: "SCA", "SAST", or "Secrets"
	Type() string

	// Icon returns an emoji icon for display
	Icon() string

	// Name returns the scanner name (must match the name in scanners.yaml)
	Name() string
}

// SCAParser interface for Software Composition Analysis scanners.
// These analyze dependencies for known vulnerabilities.
type SCAParser interface {
	ResultParser
}

// SASTParser interface for Static Application Security Testing scanners.
// These analyze source code for security issues.
type SASTParser interface {
	ResultParser
}

// SecretsParser interface for secret detection scanners.
// These find hardcoded credentials and sensitive data.
type SecretsParser interface {
	ResultParser
}

// Registry maps scanner names to their parser implementations
var registry = map[string]ResultParser{
	"grype":       &GrypeParser{},
	"osv-scanner": &OSVScannerParser{},
	"gosec":       &GosecParser{},
	"gitleaks":    &GitleaksParser{},
}

// Get returns the appropriate parser for a scanner name.
// Returns nil and false if no parser is registered for that scanner.
func Get(scannerName string) (ResultParser, bool) {
	parser, ok := registry[scannerName]
	return parser, ok
}

// Register adds a new parser to the registry.
// Use this to register custom parsers at runtime.
func Register(name string, parser ResultParser) {
	registry[name] = parser
}
