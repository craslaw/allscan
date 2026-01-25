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
1. Create parser struct implementing `ResultParser` in `parsers/`
2. Register in `registry` map in `parsers/parser.go`
3. Add scanner config to `scanners.yaml` with `dojo_scan_type` for DefectDojo

**Built-in Scanners:**
- `binary-detector` uses `builtin:binary-detector` command (no external binary)

**Scanner Args:**
- `{{output}}` template is replaced with output file path
- `args_local` overrides `args` in `--local` mode (e.g., gitleaks respects .gitignore locally)
