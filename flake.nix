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

        # Socket CLI - Supply chain security scanner (uses pnpm)
        # https://github.com/SocketDev/socket-cli
        #
        # To enable Socket CLI:
        # 1. Run: nix build .#socket-cli 2>&1 | grep "got:"
        # 2. Update the source 'hash' below with the output
        # 3. Run again to get pnpmDeps hash
        # 4. Uncomment socket-cli in the scanners list below
        socket-cli = pkgs.stdenv.mkDerivation (finalAttrs: {
          pname = "socket-cli";
          version = "1.1.50";

          src = pkgs.fetchFromGitHub {
            owner = "SocketDev";
            repo = "socket-cli";
            rev = "v1.1.50";
            # Run: nix build .#socket-cli to get correct hash
            hash = pkgs.lib.fakeHash;
          };

          nativeBuildInputs = [
            pkgs.nodejs
            pkgs.pnpm_9.configHook
            pkgs.pnpm_9
          ];

          # Run: nix build .#socket-cli to get correct hash after fixing src hash
          pnpmDeps = pkgs.pnpm_9.fetchDeps {
            inherit (finalAttrs) pname version src;
            hash = pkgs.lib.fakeHash;
          };

          buildPhase = ''
            runHook preBuild
            pnpm build
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin $out/lib/socket-cli
            cp -r . $out/lib/socket-cli
            ln -s $out/lib/socket-cli/node_modules/.bin/socket $out/bin/socket
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Socket.dev CLI for supply chain security scanning";
            homepage = "https://socket.dev";
            license = licenses.mit;
            mainProgram = "socket";
          };
        });

        scanners = with pkgs; [
          gosec
          gitleaks
          golangci-lint
          git
          osv-scanner
          grype
          # socket-cli  # Uncomment after updating hashes above
        ];

        orchestrator = pkgs.buildGoModule {
          pname = "vuln-scanner-orchestrator";
          version = "1.0.0";
          src = ./.;
          vendorHash = "sha256-g+yaVIx4jxpAQ/+WrGKxhVeliYx7nLQe/zsGpxV4Fn4=";
          
          # Make scanners available at build time
          nativeBuildInputs = scanners;
        };

      in
      {
        packages = {
          default = orchestrator;
          inherit orchestrator socket-cli;
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
