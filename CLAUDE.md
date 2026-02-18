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

# Run in local mode (scan current directory, no upload)
nix run -- --local

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
3. Run enabled scanners against each repo
4. Parse results and print colorful summary
5. Optionally upload to DefectDojo (requires `VULN_MGMT_API_TOKEN` env var)

**Key Files:**
- `src/main.go` - CLI entry point, handles `--local`/`--dry-run`/`--repo` flags
- `src/config.go` - Config structs and YAML loading
- `src/scanner.go` - Scanner execution with timeout handling
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

When adding a new scanner, you MUST complete ALL of the following steps:

1. **Add to Nix flake** (`flake.nix`):
   - If the scanner is in nixpkgs: add to the `scanners` list
   - If not in nixpkgs: create a `buildNpmPackage`, `buildGoModule`, or appropriate derivation
   - Scanner binaries MUST be installed declaratively via Nix, never manually

2. **Create parser** (`src/parsers/`):
   - Create parser struct implementing `ResultParser` interface
   - Implement `Parse()`, `Type()`, `Icon()`, `Name()` methods
   - Register in `registry` map in `src/parsers/parser.go`

3. **Write parser tests** (`src/parsers/<type>_test.go`):
   - Write tests BEFORE implementing the parser (TDD)
   - Cover: empty input (no findings), multiple findings with mixed severities, boundary values for severity mappings, invalid JSON (error case)
   - Use table-driven tests with `t.Run()` subtests
   - Run `go test -v ./parsers/...` to verify

4. **Add scanner config** (`scanners.yaml`):
   - Add scanner entry with name, command, args, timeout
   - Set `dojo_scan_type` for DefectDojo integration
   - Add `languages` array (empty `[]` for universal scanners)
   - Add `required_env` if API tokens are needed

5. **Update documentation**:
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
