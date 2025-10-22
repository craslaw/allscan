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
        
        scanners = with pkgs; [
          gosec
          gitleaks
          golangci-lint
          git
        ];

        orchestrator = pkgs.buildGoModule {
          pname = "vuln-scanner-orchestrator";
          version = "1.0.0";
          src = ./.;
          vendorHash = null;
          
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
        };

        apps.default = {
          type = "app";
          program = "${orchestrator}/bin/vuln-scanner-orchestrator";
        };
      }
    );
}
