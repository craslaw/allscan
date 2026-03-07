// Allscan - Declarative security scanning for git repositories
//
// This tool orchestrates multiple security scanners against git repositories,
// aggregates results, and optionally uploads findings to DefectDojo.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"allscan/parsers"
)

const resultsMaxAge = 7 * 24 * time.Hour // 7 days

// resolveFromLsRemote parses the output of "git ls-remote --tags" and returns a RepositoryConfig
// for the latest tag. For annotated tags the ^{} dereferenced commit hash is used.
// Falls back to branch "main" if no tags are present in the output.
func resolveFromLsRemote(url string, output []byte) RepositoryConfig {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	// First pass: find the first non-dereference tag and build a map of
	// tag name → commit hash so annotated tag ^{} lines can override.
	type tagEntry struct {
		name string
		hash string
	}
	var selected *tagEntry
	derefHashes := make(map[string]string) // tag name → dereferenced commit hash

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		hash := parts[0]
		ref := parts[1]

		if base, ok := strings.CutSuffix(ref, "^{}"); ok {
			// Dereferenced commit for an annotated tag — record it
			tagName := strings.TrimPrefix(base, "refs/tags/")
			derefHashes[tagName] = hash
			continue
		}

		if !strings.HasPrefix(ref, "refs/tags/") {
			continue
		}

		// First non-dereference tag is the newest (list is sorted newest-first)
		if selected == nil {
			tagName := strings.TrimPrefix(ref, "refs/tags/")
			selected = &tagEntry{name: tagName, hash: hash}
		}
	}

	if selected == nil {
		log.Printf("ℹ️  No tags found for %s, using branch main", url)
		return RepositoryConfig{URL: url, Branch: "main"}
	}

	// Prefer the dereferenced commit hash for annotated tags
	commitHash := selected.hash
	if deref, ok := derefHashes[selected.name]; ok {
		commitHash = deref
	}
	shortHash := commitHash
	if len(shortHash) > 7 {
		shortHash = shortHash[:7]
	}

	log.Printf("🏷️  Resolved %s → %s (%s)", url, selected.name, shortHash)
	return RepositoryConfig{URL: url, Version: selected.name, Commit: shortHash}
}

// resolveRepoTarget resolves a repository URL to a RepositoryConfig by detecting
// the latest tagged release via git ls-remote. Falls back to branch "main" if no tags exist.
func resolveRepoTarget(url string) RepositoryConfig {
	cmd := exec.Command("git", "ls-remote", "--tags", "--sort=-v:refname", url)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("⚠️  Could not list tags for %s: %v, using branch main", url, err)
		return RepositoryConfig{URL: url, Branch: "main"}
	}
	return resolveFromLsRemote(url, output)
}

// checkAllRequiredEnv checks required environment variables for all enabled scanners
// and for upload if configured. Returns a map of feature name -> missing env var name.
func checkAllRequiredEnv(config *Config, localMode bool) map[string]string {
	missing := make(map[string]string)
	for _, scanner := range config.Scanners {
		if !scanner.Enabled {
			continue
		}
		for _, envVar := range scanner.RequiredEnv {
			if os.Getenv(envVar) == "" {
				missing[scanner.Name] = envVar
				break // Only report first missing var per scanner
			}
		}
	}
	if !localMode && config.Global.UploadEndpoint != "" && os.Getenv("VULN_MGMT_API_TOKEN") == "" {
		missing["DefectDojo upload"] = "VULN_MGMT_API_TOKEN"
	}
	return missing
}

// promptYesNo displays a prompt and returns true if the user answers yes.
func promptYesNo(prompt string) bool {
	fmt.Print(prompt)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "" || response == "y" || response == "yes"
}

// promptContinue asks the user if they want to continue and returns their choice.
func promptContinue(missing map[string]string) bool {
	fmt.Println("\n⚠️  Missing required environment variables:")
	for scanner, envVar := range missing {
		fmt.Printf("   • %s%s%s%s requires %s%s%s\n", ColorBold, ColorCyan, titleCase(scanner), ColorReset, ColorYellow, envVar, ColorReset)
	}
	return promptYesNo("\nContinue anyway? [y/N]: ")
}

// titleCase capitalizes the first letter of each word in a string.
func titleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// isValidCachedRepo checks if a directory is a valid git repo with the expected remote URL
func isValidCachedRepo(repoPath, expectedURL string) bool {
	// Check if directory exists
	info, err := os.Stat(repoPath)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check if it's a git repo with the correct remote
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Normalize URLs for comparison (trim whitespace, handle .git suffix)
	actualURL := strings.TrimSpace(string(output))
	actualURL = strings.TrimSuffix(actualURL, ".git")
	expectedNormalized := strings.TrimSuffix(expectedURL, ".git")

	return actualURL == expectedNormalized
}

// getCommitHash returns the short commit hash of HEAD for a repository
func getCommitHash(repoPath string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// validateVersionCommit checks if a version tag points to the expected commit
// and prints a warning if they don't match
func validateVersionCommit(repoPath, version, expectedCommit string) {
	// Get the commit hash that the tag points to
	cmd := exec.Command("git", "rev-list", "-n", "1", "--abbrev-commit", "tags/"+version)
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		// Tag might not exist or other git error - skip validation
		return
	}

	tagCommit := strings.TrimSpace(string(output))
	// Compare with expected commit (handle both short and full hashes)
	if !strings.HasPrefix(tagCommit, expectedCommit) && !strings.HasPrefix(expectedCommit, tagCommit) {
		log.Printf("%s%s⚠️  WARNING: Tag %s points to %s, but expected %s%s",
			ColorBold, ColorYellow, version, tagCommit, expectedCommit, ColorReset)
	}
}

// cloneRepository performs a shallow clone of the target repository, or updates an existing cached clone
// Returns: repoPath, commitHash (short), branchTag (branch or tag name), error
func cloneRepository(config *Config, repo RepositoryConfig) (repoPath, commitHash, branchTag string, err error) {
	// Extract repo name from URL
	parts := strings.Split(repo.URL, "/")
	repoName := parts[len(parts)-2] + "/" + strings.TrimSuffix(parts[len(parts)-1], ".git")

	repoPath = filepath.Join(config.Global.Workspace, repoName)

	// Determine the ref to use (precedence: version > commit > branch)
	var ref string
	if repo.Version != "" {
		ref = repo.Version
		branchTag = repo.Version
	} else if repo.Commit != "" {
		ref = repo.Commit
		branchTag = repo.Commit
	} else {
		ref = repo.Branch
		branchTag = repo.Branch
		if ref == "" {
			ref = "main"
			branchTag = "main"
		}
	}

	// Version tag checkout - use git clone --branch (works with tags)
	if repo.Version != "" {
		// Remove existing directory for fresh clone
		if err := os.RemoveAll(repoPath); err != nil {
			log.Printf("    ⚠️  Couldn't remove old repository: %v", err)
		}

		log.Printf("  📥 Cloning %s (tag: %s)...", repoName, repo.Version)
		cmd := exec.Command("git", "clone", "--depth=1", "--branch", repo.Version, repo.URL, repoPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			return "", "", "", fmt.Errorf("git clone failed: %w\n%s", err, output)
		}

		// Get the commit hash
		commitHash, err = getCommitHash(repoPath)
		if err != nil {
			return "", "", "", err
		}

		// Validate version/commit if both are specified
		if repo.Commit != "" {
			validateVersionCommit(repoPath, repo.Version, repo.Commit)
		}

		return repoPath, commitHash, branchTag, nil
	}

	// Commit checkout - requires fetch then checkout
	if repo.Commit != "" {
		// Remove existing directory for fresh clone
		if err := os.RemoveAll(repoPath); err != nil {
			log.Printf("    ⚠️  Couldn't remove old repository: %v", err)
		}

		log.Printf("  📥 Cloning %s (commit: %s)...", repoName, repo.Commit)

		// Initialize empty repo and add remote
		if err := os.MkdirAll(repoPath, 0750); err != nil {
			return "", "", "", fmt.Errorf("creating directory: %w", err)
		}

		initCmd := exec.Command("git", "init")
		initCmd.Dir = repoPath
		if output, err := initCmd.CombinedOutput(); err != nil {
			return "", "", "", fmt.Errorf("git init failed: %w\n%s", err, output)
		}

		remoteCmd := exec.Command("git", "remote", "add", "origin", repo.URL)
		remoteCmd.Dir = repoPath
		if output, err := remoteCmd.CombinedOutput(); err != nil {
			return "", "", "", fmt.Errorf("git remote add failed: %w\n%s", err, output)
		}

		// Fetch the specific commit
		fetchCmd := exec.Command("git", "fetch", "--depth=1", "origin", repo.Commit)
		fetchCmd.Dir = repoPath
		if output, err := fetchCmd.CombinedOutput(); err != nil {
			return "", "", "", fmt.Errorf("git fetch failed: %w\n%s", err, output)
		}

		// Checkout the commit
		checkoutCmd := exec.Command("git", "checkout", "FETCH_HEAD")
		checkoutCmd.Dir = repoPath
		if output, err := checkoutCmd.CombinedOutput(); err != nil {
			return "", "", "", fmt.Errorf("git checkout failed: %w\n%s", err, output)
		}

		// Get the actual commit hash (may differ from short hash provided)
		commitHash, err = getCommitHash(repoPath)
		if err != nil {
			return "", "", "", err
		}

		return repoPath, commitHash, branchTag, nil
	}

	// Branch checkout (existing behavior)
	// Check if repo already exists with correct remote
	if isValidCachedRepo(repoPath, repo.URL) {
		log.Printf("  📦 Updating cached repo: %s (branch: %s)...", repoName, ref)

		// Fetch latest changes
		fetchCmd := exec.Command("git", "fetch", "origin", ref, "--depth=1")
		fetchCmd.Dir = repoPath
		if _, err := fetchCmd.CombinedOutput(); err != nil {
			log.Printf("    ⚠️  Fetch failed, will re-clone: %v", err)
			// Fall through to fresh clone
		} else {
			// Reset to fetched branch
			resetCmd := exec.Command("git", "reset", "--hard", "origin/"+ref)
			resetCmd.Dir = repoPath
			if output, err := resetCmd.CombinedOutput(); err != nil {
				return "", "", "", fmt.Errorf("git reset failed: %w\n%s", err, output)
			}

			// Get the commit hash
			commitHash, err = getCommitHash(repoPath)
			if err != nil {
				return "", "", "", err
			}

			return repoPath, commitHash, branchTag, nil
		}
	}

	// Remove if exists (either not valid cache or fetch failed)
	if err := os.RemoveAll(repoPath); err != nil {
		log.Printf("    ⚠️  Couldn't remove old repository: %v", err)
	}

	// Fresh clone
	log.Printf("  📥 Cloning %s (branch: %s)...", repoName, ref)
	cmd := exec.Command("git", "clone", "--depth=1", "--branch", ref, repo.URL, repoPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", "", fmt.Errorf("git clone failed: %w\n%s", err, output)
	}

	// Get the commit hash
	commitHash, err = getCommitHash(repoPath)
	if err != nil {
		return "", "", "", err
	}

	return repoPath, commitHash, branchTag, nil
}

// runScans clones/updates repositories and runs scanners against them
func runScans(config *Config) []RepoScanContext {
	var contexts []RepoScanContext

	for _, repo := range config.Repositories {
		log.Printf("\n📦 Processing repository: %s", repo.URL)

		// Validate repository config
		if err := ValidateRepositoryConfig(repo); err != nil {
			log.Printf("❌ Invalid repository config for %s: %v", repo.URL, err)
			continue
		}

		// Clone or update repository
		repoPath, commitHash, branchTag, err := cloneRepository(config, repo)
		if err != nil {
			log.Printf("❌ Failed to clone %s: %v", repo.URL, err)
			continue
		}

		// Extract repo name for SBOM filename
		parts := strings.Split(repo.URL, "/")
		repoName := strings.TrimSuffix(parts[len(parts)-1], ".git")

		// Use the original pURL version in the SBOM filename when available,
		// so that the user-provided version appears rather than the git tag name
		sbomVersion := branchTag
		if repo.PURLVersion != "" {
			sbomVersion = repo.PURLVersion
		}

		// Generate SBOM (reused by grype via {{sbom}} template)
		sbomPath, sbomErr := generateSBOM(config.Global.ResultsDir, repoPath, repoName, commitHash, sbomVersion)
		if sbomErr != nil {
			log.Printf("  ⚠️  SBOM generation failed: %v", sbomErr)
		}

		// Run scanners on this repo
		ctx := runScannersOnRepo(config, repo, repoPath, commitHash, branchTag, sbomPath)
		contexts = append(contexts, ctx)

		// Check for fail-fast across all results
		for _, result := range ctx.Results {
			if !result.Success && config.Global.FailFast {
				return contexts
			}
		}
	}

	return contexts
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "scanners.yaml", "Path to config file")
	reposPath := flag.String("repos", "repositories.yaml", "Path to repositories config file")
	preflight := flag.Bool("preflight", false, "Validate configuration and check environment without running scans")
	local := flag.Bool("local", false, "Scan current directory instead of cloning repos (skips upload)")
	repo := flag.String("repo", "", "Scan a single repository by URL (uses latest tagged release if available)")
	purlFlag := flag.String("purl", "", "Scan a package by its Package URL (pURL), e.g. pkg:github/owner/repo@v1.0.0")
	product := flag.String("product", "", "Product name for DefectDojo uploads (overrides auto-detected name)")
	sarif := flag.Bool("sarif", false, "Output scan results in SARIF format (for scanners that support it)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: allscan [options]\n\nOptions:\n")
		flag.VisitAll(func(f *flag.Flag) {
			if f.DefValue != "" && f.DefValue != "false" {
				fmt.Fprintf(os.Stderr, "  --%-12s %s (default: %s)\n", f.Name, f.Usage, f.DefValue)
			} else {
				fmt.Fprintf(os.Stderr, "  --%-12s %s\n", f.Name, f.Usage)
			}
		})
		fmt.Fprintf(os.Stderr, "\n")
	}
	flag.Parse()

	// --local is incompatible with --repo and --purl
	if *local && (*repo != "" || *purlFlag != "") {
		log.Fatalf("Flag --local cannot be combined with --repo or --purl")
	}

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Store CLI-only overrides in config
	config.Global.ProductOverride = *product
	config.Global.SarifMode = *sarif

	// Parse timeouts
	if err := parseTimeouts(config); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Local mode: scan current directory
	if *local {
		if *preflight {
			runPreflight(config, true)
			return
		}
		if missing := checkAllRequiredEnv(config, true); len(missing) > 0 {
			if !promptContinue(missing) {
				log.Fatalf("Aborted: missing required environment variables")
			}
		}
		runLocalMode(config)
		return
	}

	// Accumulate targets from all sources: repositories.yaml, --repo, --purl
	var targets []RepositoryConfig

	// Load from repositories.yaml unless --repo or --purl were provided (to avoid
	// scanning the default file's entries when the user only wants specific targets)
	if *repo == "" && *purlFlag == "" {
		repositories, err := loadRepositories(*reposPath)
		if err != nil {
			log.Fatalf("Failed to load repositories: %v", err)
		}
		targets = append(targets, repositories...)
	}

	// Resolve --repo flag
	if *repo != "" {
		target := resolveRepoTarget(*repo)
		targets = append(targets, target)
	}

	// Resolve --purl flag
	if *purlFlag != "" {
		target, err := resolvePURLToTarget(*purlFlag)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if target != nil {
			targets = append(targets, *target)
		}
	}

	// Resolve any pURL entries from repositories.yaml
	targets = resolvePURLEntries(targets)

	config.Repositories = targets

	if *preflight {
		runPreflight(config, false)
		return
	}

	if missing := checkAllRequiredEnv(config, false); len(missing) > 0 {
		if !promptContinue(missing) {
			log.Fatalf("Aborted: missing required environment variables")
		}
	}

	log.Printf("🔍 Vulnerability Scanner Orchestrator")
	log.Printf("Config: %s", *configPath)
	log.Printf("Enabled scanners: %d", countEnabledScanners(config))
	log.Printf("Target repos: %d", len(config.Repositories))

	// Create workspace and results dirs
	if err := setupDirectories(config); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	// Cleanup old scan results
	cleanupOldResults(config.Global.ResultsDir)

	// Run scans
	contexts := runScans(config)

	// Print summary
	printSummary(contexts)

	// Upload results (if configured)
	if config.Global.UploadEndpoint != "" {
		var results []ScanResult
		// Build a combined reachability index from all govulncheck outputs
		var reachIdx parsers.ReachabilityIndex
		for _, ctx := range contexts {
			results = append(results, ctx.Results...)
			if idx := buildReachabilityIndexFromResults(ctx.Results); idx != nil {
				if reachIdx == nil {
					reachIdx = idx
				} else {
					for k, v := range idx {
						if existing, ok := reachIdx[k]; ok && existing {
							continue // don't downgrade reachable
						}
						reachIdx[k] = v
					}
				}
			}
		}
		uploadResults(config, results, reachIdx)
	}
}

// runLocalMode scans the current directory without cloning or uploading
func runLocalMode(config *Config) {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}

	// Get directory name for display
	dirName := filepath.Base(cwd)

	log.Printf("🔍 Vulnerability Scanner Orchestrator")
	log.Printf("📂 Local mode: scanning %s", cwd)
	log.Printf("Enabled scanners: %d", countEnabledScanners(config))

	// Create results directory
	if err := setupDirectories(config); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	// Cleanup old scan results
	cleanupOldResults(config.Global.ResultsDir)

	// Get commit hash for SBOM filename (if in a git repo)
	commitHash, _ := getCommitHash(cwd)
	if commitHash == "" {
		commitHash = "unknown"
	}

	// Generate SBOM (reused by grype via {{sbom}} template)
	sbomPath, sbomErr := generateSBOM(config.Global.ResultsDir, cwd, dirName, commitHash, "local")
	if sbomErr != nil {
		log.Printf("  ⚠️  SBOM generation failed: %v", sbomErr)
	}

	// Create a local repo config for the current directory
	localRepo := RepositoryConfig{
		URL:    "local://" + cwd,
		Branch: "local",
	}

	log.Printf("\n📂 Scanning local directory: %s", cwd)

	// Run scans on current directory
	ctx := runScannersOnRepo(config, localRepo, cwd, "", "", sbomPath)

	// Print summary
	printSummary([]RepoScanContext{ctx})

	// Note: No upload in local mode
	log.Printf("📝 Local mode: results saved to %s (upload skipped)", config.Global.ResultsDir)
}

// runPreflight validates configuration, checks the environment, and prints a
// summary of all configured scanners and repositories without running any scans.
func runPreflight(config *Config, localMode bool) {
	issues := 0

	fmt.Printf("\n%s=== PREFLIGHT CHECK ===%s\n", ColorBold, ColorReset)

	// Global configuration
	fmt.Printf("\n%sGlobal Configuration:%s\n", ColorBold, ColorReset)
	fmt.Printf("  %-18s %s\n", "Workspace:", config.Global.Workspace)
	fmt.Printf("  %-18s %s\n", "Results Dir:", config.Global.ResultsDir)
	fmt.Printf("  %-18s %d\n", "Max Concurrent:", config.Global.MaxConcurrent)
	fmt.Printf("  %-18s %v\n", "Fail Fast:", config.Global.FailFast)
	if config.Global.SarifMode {
		fmt.Printf("  %-18s enabled\n", "SARIF Mode:")
	}
	if config.Global.UploadEndpoint != "" {
		if os.Getenv("VULN_MGMT_API_TOKEN") != "" {
			fmt.Printf("  %-18s %s %s(token: SET)%s\n", "Upload:", config.Global.UploadEndpoint, ColorGreen, ColorReset)
		} else {
			fmt.Printf("  %-18s %s %s(token: NOT SET)%s\n", "Upload:", config.Global.UploadEndpoint, ColorYellow, ColorReset)
			issues++
		}
	} else {
		fmt.Printf("  %-18s (not configured)\n", "Upload:")
	}

	// Binary / environment checks
	fmt.Printf("\n%sEnvironment:%s\n", ColorBold, ColorReset)
	for _, bin := range []string{"git", "syft"} {
		path, err := exec.LookPath(bin)
		if err != nil {
			fmt.Printf("  %s❌  %-8s NOT FOUND%s — is nix develop active?\n", ColorRed, bin, ColorReset)
			issues++
		} else {
			fmt.Printf("  %s✅  %-8s%s %s\n", ColorGreen, bin, ColorReset, path)
		}
	}

	// Directory checks — only print if there is a problem
	for _, d := range []struct{ label, path string }{
		{"Workspace", config.Global.Workspace},
		{"Results Dir", config.Global.ResultsDir},
	} {
		info, err := os.Stat(d.path)
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Printf("  %s⚠️   %s: cannot access %s: %v%s\n", ColorYellow, d.label, d.path, err, ColorReset)
				issues++
			}
			// Does not exist yet — will be created on first run, no issue
		} else if !info.IsDir() {
			fmt.Printf("  %s❌  %s: %s exists but is not a directory%s\n", ColorRed, d.label, d.path, ColorReset)
			issues++
		} else {
			tmp, err := os.CreateTemp(d.path, ".preflight-*")
			if err != nil {
				fmt.Printf("  %s❌  %s: %s is not writable: %v%s\n", ColorRed, d.label, d.path, err, ColorReset)
				issues++
			} else {
				tmp.Close()
				os.Remove(tmp.Name())
			}
		}
	}

	// Stale workspace check
	if info, err := os.Stat(config.Global.Workspace); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(config.Global.Workspace)
		clones := 0
		for _, e := range entries {
			if e.IsDir() {
				clones++
			}
		}
		if clones > 0 {
			fmt.Printf("  %s⚠️  Workspace has %d existing clone(s) in %s (consider cleaning up)%s\n",
				ColorYellow, clones, config.Global.Workspace, ColorReset)
		}
	}

	// Scanners table
	fmt.Printf("\n%sScanners:%s\n", ColorBold, ColorReset)
	fmt.Printf("  %-7s  %-20s %-14s %-50s %-8s %s\n", "STATUS", "NAME", "BINARY", "PATH", "TIMEOUT", "FORMAT")
	fmt.Printf("  %-7s  %-20s %-14s %-50s %-8s %s\n",
		strings.Repeat("─", 6), strings.Repeat("─", 18), strings.Repeat("─", 12),
		strings.Repeat("─", 48), strings.Repeat("─", 7), strings.Repeat("─", 6))

	for _, scanner := range config.Scanners {
		var pathStr, pathColor, statusStr string

		if strings.HasPrefix(scanner.Command, "builtin:") {
			// Built-in scanners have no external binary — always available
			pathStr = "(built-in)"
			pathColor = ColorGreen
			if scanner.Enabled {
				statusStr = ColorGreen + "✅ ON " + ColorReset
			} else {
				statusStr = ColorDim + "⛔ OFF" + ColorReset
			}
		} else {
			binaryPath, err := exec.LookPath(scanner.Command)
			pathStr = binaryPath
			pathColor = ColorGreen
			if !scanner.Enabled {
				statusStr = ColorDim + "⛔ OFF" + ColorReset
			} else if err != nil {
				statusStr = ColorRed + "❌ ON " + ColorReset
			} else {
				statusStr = ColorGreen + "✅ ON " + ColorReset
			}
			if err != nil {
				pathStr = "NOT FOUND"
				pathColor = ColorRed
				if scanner.Enabled {
					issues++
				}
			}
		}

		format := "JSON"
		if scanner.Enabled {
			if _, isSarif := selectArgs(scanner, config.Global.SarifMode, localMode); isSarif {
				format = "SARIF"
			}
		}

		timeout := scanner.Timeout
		if timeout == "" {
			timeout = "5m"
		}

		fmt.Printf("  %s  %-20s %-14s %s%-50s%s %-8s %s\n",
			statusStr, scanner.Name, scanner.Command, pathColor, pathStr, ColorReset, timeout, format)
	}

	// Repositories table (non-local mode only)
	if !localMode && len(config.Repositories) > 0 {
		fmt.Printf("\n%sRepositories (%d):%s\n", ColorBold, len(config.Repositories), ColorReset)
		fmt.Printf("  %-55s %-20s %s\n", "URL", "REF", "SCANNERS")
		fmt.Printf("  %-55s %-20s %s\n", strings.Repeat("─", 53), strings.Repeat("─", 18), strings.Repeat("─", 8))
		for _, repo := range config.Repositories {
			ref := repo.Branch
			if repo.Version != "" {
				ref = repo.Version
			} else if repo.Commit != "" {
				ref = repo.Commit
			}
			scanners := "all enabled"
			if len(repo.Scanners) > 0 {
				scanners = strings.Join(repo.Scanners, ", ")
			}
			fmt.Printf("  %-55s %-20s %s\n", repo.URL, ref, scanners)
		}
	}

	fmt.Println()
	if issues > 0 {
		os.Exit(1)
	}
}

// cleanupOldResults removes scan result files older than resultsMaxAge
func cleanupOldResults(resultsDir string) {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  Failed to cleanup old results: %v", err)
		}
		return
	}

	cutoff := time.Now().Add(-resultsMaxAge)
	removed := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".sarif")) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(resultsDir, entry.Name())); err == nil {
				removed++
			}
		}
	}

	if removed > 0 {
		log.Printf("🧹 Cleaned up %d old scan result(s)", removed)
	}
}
