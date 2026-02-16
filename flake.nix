{
  description = "Vulnerability scanner orchestrator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Scanner packages with their GitHub URLs for version tracking
        scannerInfo = {
          gosec = { pkg = pkgs.gosec; url = "https://github.com/securego/gosec"; };
          gitleaks = { pkg = pkgs.gitleaks; url = "https://github.com/gitleaks/gitleaks"; };
          golangci-lint = { pkg = pkgs.golangci-lint; url = "https://github.com/golangci/golangci-lint"; };
          osv-scanner = { pkg = pkgs.osv-scanner; url = "https://github.com/google/osv-scanner"; };
          grype = { pkg = pkgs.grype; url = "https://github.com/anchore/grype"; };
        };

        # Generate YAML entries for scanner packages
        scannerYamlEntries = pkgs.lib.concatStringsSep "\n" (
          pkgs.lib.mapAttrsToList (name: info: ''  - url: "${info.url}"
    version: "v${info.pkg.version}"'') scannerInfo
        );

        scanners = (pkgs.lib.mapAttrsToList (name: info: info.pkg) scannerInfo) ++ [
          pkgs.git
        ];

        orchestrator = pkgs.buildGoModule {
          pname = "vuln-scanner-orchestrator";
          version = "1.0.0";
          src = ./src;
          vendorHash = "sha256-g+yaVIx4jxpAQ/+WrGKxhVeliYx7nLQe/zsGpxV4Fn4=";

          # Make scanners available at build time
          nativeBuildInputs = scanners;
        };

      in
      {
        packages = {
          default = orchestrator;
          inherit orchestrator;
          scanners-only = pkgs.buildEnv {
            name = "scanners";
            paths = scanners;
          };
        };

        devShells.default = pkgs.mkShell {
          packages = scanners ++ [
            pkgs.go
            pkgs.gopls
            pkgs.gotools
            pkgs.delve
          ];

          shellHook = ''
            # Auto-update scanner versions in repositories.yaml from flake.lock
            cat > repositories.yaml << 'REPOS_EOF'
# Repository targets for security scanning
# Scanner versions are auto-generated from flake.lock - do not edit manually
#
# Pinning options (in order of precedence):
#   version: "v1.2.3"  - Pin to a specific tag
#   commit: "abc1234"  - Pin to a specific commit hash (7-40 hex chars)
#   branch: "main"     - Track latest on branch (default behavior)

repositories:
  # Self-scan
  - url: "https://github.com/craslaw/allscan"
    branch: "main"

  # === AUTO-GENERATED SCANNER VERSIONS FROM LOCKED NIXPKGS ===
${scannerYamlEntries}
  # === END AUTO-GENERATED ===
REPOS_EOF
            echo "📦 Updated repositories.yaml with scanner versions from flake.lock"
          '';
        };

        apps.default = {
          type = "app";
          program = "${orchestrator}/bin/vuln-scanner-orchestrator";
        };
      }
    );
}
