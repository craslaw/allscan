# allscan
Declarative security scanning

# Use
1. `nix develop`
2. `export VULN_MGMT_API_TOKEN="your-defectdojo-token"`
3. `nix run`

# Updating
## Updating Scanners
1. `nix flake update`

## Updating Go script dependencies
If adding new vendored dependencies, `nix build` will fail if it can't verify
reproducibility of the dependency. To get the dependency hash and add to the
nix.flake:
1. `nix develop`
2. `go mod tidy`  # Download dependencies and update go.sum
3. `git add go.sum go.mod && git commit -m 'Add Go dependencies'`
4. `nix build 2>&1 | grep "got:" build.log`
5. If step 4 fails, you may need to put a fake hash in the flake.nix so nix
   can lookup the dep and see that it needs to pull the correct one with a
   real hash.

```
orchestrator = pkgs.buildGoModule {
  pname = "scanner-orchestrator";
  version = "1.0.0";
  src = ./.;
  
  # Use Nix's built-in fake hash
  vendorHash = pkgs.lib.fakeSha256;
};
```
6. Retry step 4, then replace the hash in flake.nix with the actual hash
7. `nix run` should now work

# Architecture
The Nix flake manages:
1. Scanner binaries that are stored in `/nix/store`
2. Go dev environment and packaging for the main.go script.

Scan binaries are only available after running `nix develop`.

The Go script built by `nix build` or `nix run` will persist in the local
/nix/store, but it will not have access to any scanners unless you are in the
`nix develop` shell.
