# Allscan
Declarative security scanning for git repos

## Architecture Overview
```
┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ repositories.yaml│────▶│   main.go        │────▶│  scan-results/  │
│ (what to scan)   │     │ (orchestrator)   │     │  (JSON output)  │
└──────────────────┘     └────────┬─────────┘     └────────┬────────┘
                                  │                        │
┌──────────────────┐              │                        ▼
│ scanners.yaml    │──────────────┘               ┌─────────────────┐
│ (how to scan)    │                              │   DefectDojo    │
└──────────────────┘                              │   (optional)    │
                                                  └─────────────────┘
```

##  Core Workflow
1. Clone - Shallow clones each repository from repositories.yaml
2. Detect - Identifies languages via GitHub API (or filesystem scan as fallback)
3. Select - Chooses compatible scanners based on detected languages
4. Scan - Runs configured scanners against the cloned code
5. Collect - Saves JSON results to scan-results/
6. Upload - Optionally pushes findings to DefectDojo vulnerability management platform

## Scanners

Allscan automatically selects scanners based on detected repository languages. Scanners marked as "Universal" run on all repositories regardless of language.

| Scanner | Type | Default | Languages |
|---------|------|:-------:|-----------|
| gosec | SAST | ✓ | Go |
| golangci-lint | SAST | | Go |
| semgrep | SAST | | Go, Python, JavaScript, TypeScript, Java, Kotlin, Scala, Ruby, PHP, C, C++, C#, Rust, Swift |
| osv-scanner | SCA | ✓ | *Universal* |
| grype | SCA | ✓ | *Universal* |
| trivy | SCA | | *Universal* |
| gitleaks | Secrets | ✓ | *Universal* |
| binary-detector | Binary | ✓ | *Universal* |
| scorecard | Posture | ✓ | *Universal* |

**Legend:**
- **SAST** - Static Application Security Testing (source code analysis)
- **SCA** - Software Composition Analysis (dependency vulnerabilities)
- **Secrets** - Credential and secret detection
- **Binary** - Binary file detection
- **Posture** - Security posture/health metrics (OpenSSF Scorecard)
- **Default ✓** - Enabled by default in `scanners.yaml`
- ***Universal*** - Runs on all repositories regardless of detected language

# Use
1. `nix develop`
2. `export VULN_MGMT_API_TOKEN="your-defectdojo-token"`
3. `nix run`

# Updating
## Updating Scanners
1. `nix flake update`

## Updating Go script dependencies
If adding new vendored dependencies, `nix build` will fail if it can't verify
reproducibility of the dependency. To get the dependency hash and add to the
nix.flake:
1. `nix develop`
2. `go mod tidy`  # Download dependencies and update go.sum
3. `git add go.sum go.mod && git commit -m 'Add Go dependencies'`
4. `nix build 2>&1 | grep "got:" build.log`
5. If step 4 fails, you may need to put a fake hash in the flake.nix so nix
   can lookup the dep and see that it needs to pull the correct one with a
   real hash.

```
orchestrator = pkgs.buildGoModule {
  pname = "scanner-orchestrator";
  version = "1.0.0";
  src = ./.;
  
  # Use Nix's built-in fake hash
  vendorHash = pkgs.lib.fakeSha256;
};
```
6. Retry step 4, then replace the hash in flake.nix with the actual hash
7. `nix run` should now work

# File Structure
## Go
allscan/                                                             
├── main.go           (94 lines)   # CLI entry point                 
├── config.go         (143 lines)  # Config structs and loading      
├── scanner.go        (209 lines)  # Scanner execution logic         
├── upload.go         (218 lines)  # DefectDojo upload logic         
├── summary.go        (157 lines)  # Colorful summary printing       
└── parsers/                                                         
...├── parser.go     (68 lines)   # Interfaces and registry         
...├── sca.go        (112 lines)  # GrypeParser, OSVScannerParser   
...├── sast.go       (53 lines)   # GosecParser                     
...└── secrets.go    (39 lines)   # GitleaksParser

## Nix
The Nix flake manages:
1. Scanner binaries that are stored in `/nix/store`
2. Go dev environment and packaging for the main.go script.

Scan binaries are only available after running `nix develop`.

The Go script built by `nix build` or `nix run` will persist in the local
/nix/store, but it will not have access to any scanners unless you are in the
`nix develop` shell.
