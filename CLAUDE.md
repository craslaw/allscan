# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

**IMPORTANT: Most commands run from the project root** (where `scanners.yaml` and `repositories.yaml` are located).

```bash
# Enter development shell (required for scanner binaries)
nix develop

# Run the orchestrator (scans repositories defined in repositories.yaml)
nix run

# Scan a single repository (auto-detects latest tagged release)
nix run -- --repo https://github.com/owner/repo

# Scan a package by its Package URL (pURL)
nix run -- --purl "pkg:npm/express@4.18.2"

# Run in local mode (scan current directory, no upload)
nix run -- --local

# Output results in SARIF format (for scanners that support it)
nix run -- --sarif

# Dry run (show what would be executed without running)
nix run -- --dry-run

# Build the Go binary
nix build

# Update scanner versions
nix flake update

# Development with go run (must specify config paths)
cd src && go run . --local --config ../scanners.yaml --repos ../repositories.yaml

# Update Go dependencies (run from src/ where go.mod is located)
cd src && go mod tidy
```

## Architecture

Allscan is a declarative security scanning orchestrator written in Go and managed with Nix.

**Core Flow:**
1. Load `scanners.yaml` (scanner definitions) and `repositories.yaml` (targets)
2. Clone each repository (shallow clone)
3. Generate CycloneDX SBOM with Syft (reused if same repo+version+commit exists)
4. Run enabled scanners against each repo (Grype consumes SBOM as input)
5. Parse results and print colorful summary
6. Optionally upload to DefectDojo (requires `VULN_MGMT_API_TOKEN` env var)

**Key Files:**
- `src/main.go` - CLI entry point, handles `--local`/`--dry-run`/`--repo`/`--purl` flags
- `src/config.go` - Config structs and YAML loading
- `src/scanner.go` - Scanner execution with timeout handling
- `src/sbom.go` - SBOM generation with Syft, deduplication, filename building
- `src/purl.go` - Package URL (pURL) parsing and repository resolution
- `src/upload.go` - DefectDojo upload using fluent builder pattern
- `src/summary.go` - Colorful terminal output with ANSI codes
- `src/parsers/` - Interface-based parser system for scanner outputs
- `scanners.yaml` - Scanner definitions (in root)
- `repositories.yaml` - Target repositories (in root)

**Parser System:**
- `src/parsers/parser.go` - `ResultParser` interface and registry
- Parsers implement `Parse()`, `Type()` (SCA/SAST/Secrets), `Icon()`, `Name()`
- Registry maps scanner names to implementations via `parsers.Get()`

**Adding a New Scanner:**

See [docs/scanners.md](docs/scanners.md) for the full step-by-step instructions.

## Documentation Maintenance

**IMPORTANT: When making changes to the repository, you MUST keep documentation synchronized.**

**Update README.md whenever you make:**

1. **File structure changes:**
   - Moving, renaming, or reorganizing source files
   - Adding new directories or changing the project layout
   - Changes to where configuration files are located
   - Example: Moving Go code to `src/` directory requires updating file paths in README.md

2. **Workflow changes that affect human users:**
   - Changes to build commands or how to run the program
   - New command-line flags or options
   - Changes to environment variable requirements
   - Updates to the development setup process
   - Changes to how dependencies are managed
   - Example: If `go run .` changes to `cd src && go run .`, update README.md

3. **Architecture or design changes:**
   - Adding new scanners to the compatibility matrix
   - Changes to how scanners are configured or executed
   - Updates to the core workflow or processing pipeline

**Always update both CLAUDE.md and README.md together** - CLAUDE.md is for AI agents, README.md is for human users. They should reflect the same current state of the project.

## Testing

**Running Tests:**

```bash
# Run all tests (from src/ directory)
cd src && go test ./...

# Verbose output (shows individual test case names)
cd src && go test -v ./...

# Run only parser tests
cd src && go test -v ./parsers/...

# Run only root package tests (config, scanner, language, upload)
cd src && go test -v .

# Run a specific test function
cd src && go test -v -run TestGrypeParser_Parse ./parsers/...

# Run a specific subtest
cd src && go test -v -run TestGrypeParser_Parse/mixed_severities ./parsers/...

# Show test coverage percentage
cd src && go test -cover ./...
```

**Test-Driven Development (TDD) Workflow:**

When adding new functions or features, follow this workflow:

1. **Write a failing test first** in the appropriate `*_test.go` file using table-driven tests
2. **Run the test** to confirm it fails: `cd src && go test -v -run TestNewThing ./...`
3. **Write the minimum code** to make the test pass
4. **Run tests again** to confirm they pass: `cd src && go test -v ./...`
5. **Refactor** while keeping tests green

**Test Conventions:**

- Test files: `foo_test.go` next to `foo.go` in `src/` (parsers tests in `src/parsers/` dir)
- Test functions: `TestFunctionName(t *testing.T)`
- Use table-driven tests with `t.Run()` subtests for multiple cases
- Use `t.TempDir()` for tests that need temporary filesystem access
- Use `t.Setenv()` for tests that check environment variables
- Standard `testing` package only -- no external test libraries
- Always run `cd src && go test ./...` after any code changes to catch regressions
