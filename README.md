# Allscan
Declarative security scanning for git repos

See [docs/Architecture.md](docs/Architecture.md) for the system architecture, core workflow, and file structure.

## Scanners

Allscan automatically selects scanners based on detected repository languages. Scanners marked as "Universal" run on all repositories regardless of language.

| Scanner | Type | Languages | SARIF |
|---------|------|-----------|-------|
| syft | SBOM | *Universal* | - |
| gosec | SAST | Go | Yes |
| osv-scanner | SCA | Go, Python, JavaScript, TypeScript, Java, C, C++, Ruby, PHP, Rust, Dart, Elixir, Haskell, R, C# | Yes |
| grype | SCA | Go, Python, JavaScript, TypeScript, Java, C, C++, Ruby, PHP, Rust, Swift, Dart | Yes |
| govulncheck | Reachability | Go | No |
| trufflehog | Secrets | *Universal* | No |
| binary-detector | Binary | *Universal* | No |
| scorecard | Posture | *Universal* | Yes |

**Legend:**
- **SBOM** - Software Bill of Materials (CycloneDX JSON, generated before scanners run)
- **SAST** - Static Application Security Testing (source code analysis)
- **SCA** - Software Composition Analysis (dependency vulnerabilities)
- **Reachability** - Vulnerability reachability analysis (determines if vulnerable code paths are actually called)
- **Secrets** - Credential and secret detection
- **Binary** - Binary file detection
- **Posture** - Security posture/health metrics (OpenSSF Scorecard)
- ***Universal*** - Runs on all repositories regardless of detected language
- **SARIF** - Whether the scanner supports SARIF output via `--sarif` flag (scanners without SARIF support are skipped in SARIF mode)

# Use

All commands must be run from the project root directory.

## Prerequisites

**Required:**
- [Nix](https://nixos.org/download/) with flakes enabled — manages all scanner binaries and the Go build environment.

**Optional:**
- **GitHub token** (`GITHUB_TOKEN`) — used by the Scorecard scanner (required if Scorecard is enabled) and improves language detection via the GitHub API. Without it, language detection falls back to filesystem inspection and Scorecard is skipped.
- **DefectDojo instance** — a running [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) server for uploading findings. Configure the endpoint in `scanners.yaml` under `global.upload_endpoint`. Requires `VULN_MGMT_API_TOKEN` to be set.

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
   nix run                                            # Scan repositories from repositories.yaml
   nix run -- . --repo https://github.com/owner/repo  # Scan a single repo (auto-detects latest release)
   nix run -- . --purl "pkg:npm/express@4.18.2"       # Scan a package by its Package URL (pURL)
   nix run -- . --sarif                               # Output results in SARIF format
   ```

## Development Mode

For local development and testing:

```bash
# Scan current directory (no cloning or upload)
nix run -- . --local

# Preflight check (validate config and environment without running scans)
nix run -- . --preflight

# Run tests (must run from src/ where go.mod is located)
cd src && go test ./...

# Development with go run (if not using nix run)
cd src && go run . --local --config ../scanners.yaml --repos ../repositories.yaml
```

## Dependency Management & Version Pinning

Allscan scans its own dependencies to ensure supply chain security. The `repositories.yaml` file contains:
- Scanner tool repositories (gosec, trufflehog, etc.)
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

### Package URL (pURL) Targets

Repository entries can use a [Package URL](https://github.com/package-url/purl-spec) instead of a direct URL. The pURL is resolved to a source repository at load time:

```yaml
repositories:
  # Scan a GitHub package
  - purl: "pkg:github/gin-gonic/gin@v1.10.0"

  # Scan an npm package (resolved via npm registry)
  - purl: "pkg:npm/express@4.18.2"

  # Use repository_url qualifier for unsupported types
  - purl: "pkg:docker/nginx@1.25?repository_url=https://github.com/nginx/nginx"

  # Override the pURL version with an explicit version
  - purl: "pkg:github/foo/bar@v2.0.0"
    version: "v1.0.0"
```

Supported pURL types: `github`, `golang`, `npm`, `pypi`, `cargo`, `gem`. Any type can use the `repository_url` qualifier.

The `--purl` flag and `--repo` flag can be combined with each other and with `repositories.yaml` entries. When `--repo` or `--purl` are provided without the other, `repositories.yaml` is not loaded (to avoid scanning default targets). Use both flags together or add pURL entries directly to `repositories.yaml` to combine sources.

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
