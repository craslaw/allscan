Interface-Based Scanner Architecture                                 
                                                                       
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

## Step 3: Add Scanner Config

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

## Step 4: Update Documentation

1. Add scanner to `README.md` compatibility matrix
2. Update this file if adding new parser patterns
