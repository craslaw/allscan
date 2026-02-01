# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

```bash
# Enter development shell (required for scanner binaries)
nix develop

# Run the orchestrator (scans repositories defined in repositories.yaml)
nix run

# Run in local mode (scan current directory, no upload)
go run . --local

# Dry run (show what would be executed without running)
go run . --dry-run

# Build the Go binary
nix build

# Update scanner versions
nix flake update

# Update Go dependencies (see README.md for vendorHash workflow)
go mod tidy
```

## Architecture

Allscan is a declarative security scanning orchestrator written in Go and managed with Nix.

**Core Flow:**
1. Load `scanners.yaml` (scanner definitions) and `repositories.yaml` (targets)
2. Clone each repository (shallow clone)
3. Run enabled scanners against each repo
4. Parse results and print colorful summary
5. Optionally upload to DefectDojo (requires `VULN_MGMT_API_TOKEN` env var)

**Key Files:**
- `main.go` - CLI entry point, handles `--local`/`--dry-run` flags
- `config.go` - Config structs and YAML loading
- `scanner.go` - Scanner execution with timeout handling
- `upload.go` - DefectDojo upload using fluent builder pattern
- `summary.go` - Colorful terminal output with ANSI codes
- `parsers/` - Interface-based parser system for scanner outputs

**Parser System:**
- `parsers/parser.go` - `ResultParser` interface and registry
- Parsers implement `Parse()`, `Type()` (SCA/SAST/Secrets), `Icon()`, `Name()`
- Registry maps scanner names to implementations via `parsers.Get()`

**Adding a New Scanner:**

When adding a new scanner, you MUST complete ALL of the following steps:

1. **Add to Nix flake** (`flake.nix`):
   - If the scanner is in nixpkgs: add to the `scanners` list
   - If not in nixpkgs: create a `buildNpmPackage`, `buildGoModule`, or appropriate derivation
   - Scanner binaries MUST be installed declaratively via Nix, never manually

2. **Create parser** (`parsers/`):
   - Create parser struct implementing `ResultParser` interface
   - Implement `Parse()`, `Type()`, `Icon()`, `Name()` methods
   - Register in `registry` map in `parsers/parser.go`

3. **Add scanner config** (`scanners.yaml`):
   - Add scanner entry with name, command, args, timeout
   - Set `dojo_scan_type` for DefectDojo integration
   - Add `languages` array (empty `[]` for universal scanners)
   - Add `required_env` if API tokens are needed

4. **Update documentation**:
   - Add scanner to README.md compatibility matrix
   - Update docs/scanners.md if adding new parser patterns

Example for adding a scanner from nixpkgs:
```nix
# In flake.nix, add to scanners list:
scanners = with pkgs; [
  gosec
  new-scanner  # Add here
];
```

Example for adding an npm-based scanner not in nixpkgs:
```nix
# In flake.nix, create derivation:
new-scanner = pkgs.buildNpmPackage {
  pname = "new-scanner";
  version = "x.y.z";
  src = pkgs.fetchFromGitHub { ... };
  npmDepsHash = "sha256-...";
};
# Then add to scanners list (may need to comment out until hashes are computed)
```

**Built-in Scanners:**
- `binary-detector` uses `builtin:binary-detector` command (no external binary)

**Scanner Args:**
- `{{output}}` template is replaced with output file path
- `args_local` overrides `args` in `--local` mode (e.g., gitleaks respects .gitignore locally)
