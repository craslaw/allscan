# Interface-Based Scanner Architecture
```
  ┌─────────────────────────────────────────────────────────────────┐  
  │                      ResultParser (interface)                   │  
  │  ├── Parse(data []byte) (FindingSummary, error)                 │   
  │  ├── Type() string    // "SCA", "SAST", "Secrets"               │   
  │  ├── Icon() string                                              │  
  │  └── Name() string                                              │  
  └─────────────────────────────────────────────────────────────────┘  
                                │                                      
            ┌───────────────────┼───────────────────┐                  
            ▼                   ▼                   ▼                  
  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐          
  │   SCAParser     │ │   SASTParser    │ │ SecretsParser   │          
  │   (interface)   │ │   (interface)   │ │   (interface)   │          
  └────────┬────────┘ └────────┬────────┘ └────────┬────────┘          
           │                   │                   │                   
      ┌────┴────┐              │                   │                   
      ▼         ▼              ▼                   ▼                   
  ┌────────┐ ┌────────┐  ┌──────────┐      ┌────────────┐              
  │ Grype  │ │  OSV   │  │  Gosec   │      │  Gitleaks  │              
  │ Parser │ │ Parser │  │  Parser  │      │   Parser   │              
  └────────┘ └────────┘  └──────────┘      └────────────┘              
                                                                       
  Key Components                                                       
  ┌────────────────┬─────────────────────────────────────────────────┐ 
  │   Component    │                     Purpose                     │ 
  ├────────────────┼─────────────────────────────────────────────────┤ 
  │ ResultParser   │ Base interface all parsers implement            │ 
  ├────────────────┼─────────────────────────────────────────────────┤ 
  │ SCAParser      │ Interface for dependency vulnerability scanners │ 
  ├────────────────┼─────────────────────────────────────────────────┤ 
  │ SASTParser     │ Interface for static code analysis scanners     │ 
  ├────────────────┼─────────────────────────────────────────────────┤ 
  │ SecretsParser  │ Interface for secret detection scanners         │ 
  ├────────────────┼─────────────────────────────────────────────────┤ 
  │ parserRegistry │ Maps scanner names to parser implementations    │ 
  ├────────────────┼─────────────────────────────────────────────────┤ 
  │ GetParser()    │ Factory function to get the right parser        │ 
  └────────────────┴─────────────────────────────────────────────────┘ 
```
# Adding a New Scanner

Adding a new scanner requires changes in multiple places. All scanner
binaries MUST be installed declaratively via Nix.

## Step 1: Add Scanner to Nix Flake

Scanner binaries must be available in the `nix develop` shell.

### If scanner is in nixpkgs:
```nix
# flake.nix - add to scanners list
scanners = with pkgs; [
  gosec
  gitleaks
  new-scanner  # Add here
];
```

### If scanner is NOT in nixpkgs (e.g., npm package):
```nix
# flake.nix - create derivation before scanners list
new-scanner = pkgs.buildNpmPackage {
  pname = "new-scanner";
  version = "1.0.0";
  src = pkgs.fetchFromGitHub {
    owner = "org";
    repo = "new-scanner";
    rev = "v1.0.0";
    hash = pkgs.lib.fakeHash;  # Run nix build to get real hash
  };
  npmDepsHash = pkgs.lib.fakeHash;
};

# Then add to scanners list and packages output
```

## Step 2: Create Parser

Create a parser struct implementing `ResultParser` in `parsers/`:

```go
// parsers/sca.go (add to existing file) or create parsers/trivy.go

type TrivyParser struct{}

type trivyOutput struct {
    Results []struct {
        Vulnerabilities []struct {
            Severity string `json:"Severity"`
        } `json:"Vulnerabilities"`
    } `json:"Results"`
}

func (p *TrivyParser) Name() string { return "trivy" }
func (p *TrivyParser) Type() string { return "SCA" }
func (p *TrivyParser) Icon() string { return "🛡️" }

func (p *TrivyParser) Parse(data []byte) (FindingSummary, error) {
    // ... parsing logic
}

var _ SCAParser = (*TrivyParser)(nil)
```

Then register it in `parsers/parser.go`:
```go
var registry = map[string]ResultParser{
    // ... existing
    "trivy": &TrivyParser{},
}
```

## Step 3: Write Parser Tests

Write tests BEFORE implementing the parser (TDD). Add a `parsers/trivy_test.go` file:

```go
func TestTrivyParser_Parse(t *testing.T) {
    p := &TrivyParser{}
    tests := []struct { ... }{ ... }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) { ... })
    }
}
```

Cover these cases:
- Empty input (no findings)
- Multiple findings with mixed severities
- Boundary values for severity mappings
- Invalid JSON (error case)

Run tests to verify:
```bash
cd src && go test -v ./parsers/...
```

## Step 4: Add Scanner Config

Add entry to `scanners.yaml`:
```yaml
- name: "trivy"
  enabled: false
  dojo_scan_type: "Trivy Scan"
  command: "trivy"
  args:
    - "fs"
    - "--format=json"
    - "--output={{output}}"
    - "."
  languages: []  # Empty = universal, or list specific languages
  timeout: "5m"
  required_env: []  # Add env vars if API tokens needed
```

If the scanner supports SARIF output, add `args_sarif` with the SARIF format flags. If `args_local` is also defined, add `args_sarif_local` as well.

### Scanner Args Reference

- `{{output}}` - replaced with the output file path
- `{{sbom}}` - replaced with the generated SBOM path (used by grype: `sbom:{{sbom}}`)
- `{{repo}}` - replaced with the repository URL
- `args_local` - overrides `args` in `--local` mode
- `args_sarif` - overrides `args` in `--sarif` mode
- `args_sarif_local` - overrides `args_sarif` in `--sarif --local` mode
- Priority chain: `args_sarif_local` > `args_sarif` > `args_local` > `args`

### Built-in Scanners

The `binary-detector` scanner uses `builtin:binary-detector` as its command — it has no external binary and is handled directly by the orchestrator.

## Step 5: Integrate with ReachabilityIndex (SCA scanners only)

If the new scanner is an SCA scanner, integrate it with the reachability cross-reference system so that govulncheck findings can be correlated against its results.

### What to implement

You need to provide two functions in your parser file (following the pattern in `parsers/sca.go`):

**1. `ExtractXxxFindings(data []byte) ([]SCAFinding, error)`**

Returns a flat list of `SCAFinding` — one entry per vulnerability group, with all associated IDs (CVE, GHSA, GO-xxxx, etc.) and a normalized severity:

```go
func ExtractTrivyFindings(data []byte) ([]SCAFinding, error) {
    // parse JSON, collect IDs and severity per finding
    findings = append(findings, SCAFinding{
        IDs:      []string{vuln.VulnerabilityID, vuln.CVEID},
        Severity: normalizeSeverity(vuln.Severity),
    })
    return findings, nil
}
```

**2. `ExtractTrivyAliasGroups(data []byte) [][]string` (if the scanner groups aliases)**

If the scanner output groups related IDs together (like OSV-scanner does), extract those groups so the index can be expanded:

```go
func ExtractTrivyAliasGroups(data []byte) [][]string {
    // return [][]string{{"CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"}, ...}
}
```

If the scanner doesn't expose alias groups, skip this function.

### How it wires together

In `src/main.go`, after running all scanners, the reachability cross-reference is performed:

1. `BuildReachabilityIndex(govulncheckOutput)` — builds the index from govulncheck NDJSON
2. `idx.ExpandWithAliasGroups(ExtractOSVScannerAliasGroups(...))` — enriches the index with OSV-scanner alias groups
3. `CrossReferenceReachability(findings, idx)` — returns an `EnrichedSummary` with per-severity reachable counts

Add a similar call for the new scanner alongside the existing ones:

```go
trivyFindings, _ := parsers.ExtractTrivyFindings(trivyOutput)
// Optionally expand index with any alias groups the scanner exposes:
// idx.ExpandWithAliasGroups(parsers.ExtractTrivyAliasGroups(trivyOutput))
trivyEnriched := parsers.CrossReferenceReachability(trivyFindings, idx)
```

### Key types (defined in `parsers/sca.go` and `parsers/reachability.go`)

| Type / Function | Purpose |
|---|---|
| `SCAFinding` | Single finding: `IDs []string` + normalized `Severity string` |
| `ReachabilityIndex` | `map[string]bool` — vuln ID → reachable |
| `BuildReachabilityIndex(data)` | Parses govulncheck NDJSON into the index |
| `idx.ExpandWithAliasGroups(groups)` | Propagates reachability across alias groups |
| `idx.Lookup(vulnID)` | Returns `(reachable, known bool)` for a single ID |
| `CrossReferenceReachability(findings, idx)` | Produces `EnrichedSummary` with reachable counts |
| `EnrichedSummary` | `FindingSummary` + `CriticalReachable`, `HighReachable`, etc. |

The govulncheck index is Go-ecosystem specific, so only Go-aware SCA scanners (Grype, OSV-scanner, Trivy on Go modules) will see non-zero reachable counts. Including a new scanner in this flow is still valuable — findings with unknown IDs simply appear in `Breakdown.Unknown`.

## Step 6: Update Documentation

1. Add scanner to `README.md` compatibility matrix
2. Update this file if adding new parser patterns or reachability integration patterns
