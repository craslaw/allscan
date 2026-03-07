# Allscan Architecture

## Overview

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

## Core Workflow

1. Clone - Shallow clones each repository from repositories.yaml
2. Detect - Identifies languages via GitHub API (or filesystem scan as fallback)
3. SBOM - Generates CycloneDX SBOM with Syft (reused if same repo+version+commit exists)
4. Select - Chooses compatible scanners based on detected languages
5. Scan - Runs configured scanners (Grype consumes the SBOM as input)
6. Collect - Saves JSON results to scan-results/, SBOMs to scan-results/sboms/
7. Upload - Optionally pushes findings to DefectDojo vulnerability management platform

## File Structure

### Go Source (`src/`)

```
allscan/
├── src/                          # All Go source code
│   ├── main.go                   # CLI entry point
│   ├── config.go                 # Config structs and loading
│   ├── scanner.go                # Scanner execution logic
│   ├── sbom.go                   # SBOM generation with Syft
│   ├── purl.go                   # Package URL (pURL) resolution
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
│       ├── secrets.go            # TrufflehogParser
│       ├── binary.go             # BinaryDetectorParser
│       ├── scorecard.go          # ScorecardParser
│       └── *_test.go             # Parser unit tests
├── scanners.yaml                 # Scanner definitions
├── repositories.yaml             # Repository targets
└── flake.nix                     # Nix build configuration
```

### Nix

The Nix flake manages:
1. Scanner binaries that are stored in `/nix/store`
2. Go dev environment and packaging for the main.go script.

Scan binaries are only available after running `nix develop`.

The Go script built by `nix build` or `nix run` will persist in the local
/nix/store, but it will not have access to any scanners unless you are in the
`nix develop` shell.

## Parser System

See [scanners.md](scanners.md) for the interface-based parser architecture and instructions for adding new scanners.
