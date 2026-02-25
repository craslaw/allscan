# Allscan
Declarative security scanning for git repos

## Architecture Overview
```
┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ repositories.yaml│────▶│  src/main.go     │────▶│  scan-results/  │
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
3. SBOM - Generates CycloneDX SBOM with Syft (reused if same repo+version+commit exists)
4. Select - Chooses compatible scanners based on detected languages
5. Scan - Runs configured scanners (Grype consumes the SBOM as input)
6. Collect - Saves JSON results to scan-results/, SBOMs to scan-results/sboms/
7. Upload - Optionally pushes findings to DefectDojo vulnerability management platform

## Scanners

Allscan automatically selects scanners based on detected repository languages. Scanners marked as "Universal" run on all repositories regardless of language.

| Scanner | Type | Languages |
|---------|------|-----------|
| syft | SBOM | *Universal* |
| gosec | SAST | Go |
| osv-scanner | SCA | Go, Python, JavaScript, TypeScript, Java, C, C++, Ruby, PHP, Rust, Dart, Elixir, Haskell, R, C# |
| grype | SCA | Go, Python, JavaScript, TypeScript, Java, C, C++, Ruby, PHP, Rust, Swift, Dart |
| gitleaks | Secrets | *Universal* |
| binary-detector | Binary | *Universal* |
| scorecard | Posture | *Universal* |

**Legend:**
- **SBOM** - Software Bill of Materials (CycloneDX JSON, generated before scanners run)
- **SAST** - Static Application Security Testing (source code analysis)
- **SCA** - Software Composition Analysis (dependency vulnerabilities)
- **Secrets** - Credential and secret detection
- **Binary** - Binary file detection
- **Posture** - Security posture/health metrics (OpenSSF Scorecard)
- ***Universal*** - Runs on all repositories regardless of detected language

# Use

All commands must be run from the project root directory.

## Running Allscan

1. Enter the development shell (provides scanner binaries):
   ```bash
   nix develop
   ```

2. (Optional) Set DefectDojo API token for vulnerability upload:
   ```bash
   export VULN_MGMT_API_TOKEN="your-defectdojo-token"
   export GITHUB_TOKEN="your-scorecard-token"
   ```

3. Run the orchestrator:
   ```bash
   nix run                    # Scan repositories from repositories.yaml
   nix run -- --repo https://github.com/owner/repo  # Scan a single repo (auto-detects latest release)
   ```

## Development Mode

For local development and testing:

```bash
# Scan current directory (no cloning or upload)
nix run -- --local

# Dry run (show what would be executed)
nix run -- --dry-run

# Run tests (must run from src/ where go.mod is located)
cd src && go test ./...

# Development with go run (if not using nix run)
cd src && go run . --local --config ../scanners.yaml --repos ../repositories.yaml
```

## Dependency Management & Version Pinning

Allscan scans its own dependencies to ensure supply chain security. The `repositories.yaml` file contains:
- Scanner tool repositories (gosec, gitleaks, etc.)
- Nix flake inputs (flake-utils)
- Go module dependencies (from go.sum)

### Automatic Version Sync

Scanner versions are automatically synchronized with your locked nixpkgs. When you enter the development shell, the shell hook updates `repositories.yaml` with versions from `flake.lock`:

```bash
# Update to latest nixpkgs
nix flake update

# Enter dev shell - repositories.yaml is auto-updated
nix develop
# Output: 📦 Updated repositories.yaml with scanner versions from flake.lock
```

### Version Pinning Options

Each repository entry supports three ways to pin versions:

```yaml
repositories:
  # Pin to a specific tag (highest precedence)
  - url: "https://github.com/owner/repo"
    version: "v1.2.3"

  # Pin to a specific commit hash
  - url: "https://github.com/owner/repo"
    commit: "abc1234"

  # Track latest on branch (default behavior)
  - url: "https://github.com/owner/repo"
    branch: "main"
```

**Precedence:** version tag > commit hash > branch (latest)

### Version Validation

When both `version` and `commit` are specified, allscan validates they match. A warning is displayed if the tag points to a different commit:

```
⚠️  WARNING: Tag v1.0.0 points to def5678, but expected abc1234
```

### SBOM Generation

Allscan generates CycloneDX JSON SBOMs using [Syft](https://github.com/anchore/syft) before running scanners. SBOMs are saved to `scan-results/sboms/` with the naming pattern:

- Version tags: `{repo}_{version}_{commit}_{date}.cdx.json` (e.g., `grype_v0.87.0_abc1234_2026-02-21.cdx.json`)
- Branches: `{repo}_{commit}_{date}.cdx.json` (e.g., `allscan_def5678_2026-02-21.cdx.json`)

SBOMs are persistent artifacts (not cleaned up automatically) and are designed for ingestion into [OpenSSF GUAC](https://guac.sh/). Existing SBOMs matching the same repo+version+commit are reused to avoid regeneration.

Grype consumes the SBOM as input (`grype sbom:<path>`) instead of re-scanning the directory, eliminating redundant work.

### DefectDojo Integration

Version information is included in DefectDojo uploads:
- `branch_tag`: The branch or tag name scanned
- `commit_hash`: The actual commit hash scanned

This enables tracking findings against specific code versions.

# Updating
## Updating Scanners
1. `nix flake update`

## Updating Go script dependencies
If adding new vendored dependencies, `nix build` will fail if it can't verify
reproducibility of the dependency. To get the dependency hash and add to the
nix.flake:
1. `nix develop`
2. `cd src && go mod tidy`  # Download dependencies and update go.sum
3. `git add src/go.sum src/go.mod && git commit -m 'Add Go dependencies'`
4. `nix build 2>&1 | grep "got:" build.log`
5. If step 4 fails, you may need to put a fake hash in the flake.nix so nix
   can lookup the dep and see that it needs to pull the correct one with a
   real hash.

```
orchestrator = pkgs.buildGoModule {
  pname = "scanner-orchestrator";
  version = "1.0.0";
  src = ./src;

  # Use Nix's built-in fake hash
  vendorHash = pkgs.lib.fakeSha256;
};
```
6. Retry step 4, then replace the hash in flake.nix with the actual hash
7. `nix run` should now work

# File Structure
## Go
allscan/
├── src/                          # All Go source code
│   ├── main.go                   # CLI entry point
│   ├── config.go                 # Config structs and loading
│   ├── scanner.go                # Scanner execution logic
│   ├── sbom.go                   # SBOM generation with Syft
│   ├── upload.go                 # DefectDojo upload logic
│   ├── summary.go                # Colorful summary printing
│   ├── language.go               # Language detection
│   ├── go.mod                    # Go module definition
│   ├── go.sum                    # Go dependency checksums
│   ├── *_test.go                 # Unit tests
│   └── parsers/                  # Scanner result parsers
│       ├── parser.go             # Interfaces and registry
│       ├── sca.go                # GrypeParser, OSVScannerParser
│       ├── sast.go               # GosecParser
│       ├── secrets.go            # GitleaksParser
│       ├── binary.go             # BinaryDetectorParser
│       ├── scorecard.go          # ScorecardParser
│       └── *_test.go             # Parser unit tests
├── scanners.yaml                 # Scanner definitions
├── repositories.yaml             # Repository targets
└── flake.nix                     # Nix build configuration

## Nix
The Nix flake manages:
1. Scanner binaries that are stored in `/nix/store`
2. Go dev environment and packaging for the main.go script.

Scan binaries are only available after running `nix develop`.

The Go script built by `nix build` or `nix run` will persist in the local
/nix/store, but it will not have access to any scanners unless you are in the
`nix develop` shell.
