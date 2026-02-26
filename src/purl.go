package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	packageurl "github.com/package-url/packageurl-go"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// resolvePURL parses a pURL string and resolves it to a repository URL and version.
// Returns the repo URL, version, any warnings, and an error if parsing fails.
func resolvePURL(purlStr string) (repoURL, version string, warnings []string, err error) {
	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid pURL %q: %w", purlStr, err)
	}

	version = purl.Version

	repoURL, warnings = resolveRepoFromPURL(purl)

	return repoURL, version, warnings, nil
}

// resolveRepoFromPURL resolves a repository URL from a parsed pURL.
// It checks the repository_url qualifier first, then dispatches to type-specific resolvers.
func resolveRepoFromPURL(purl packageurl.PackageURL) (string, []string) {
	// Check repository_url qualifier first (works for all types)
	if repoQualifier := purl.Qualifiers.Map()["repository_url"]; repoQualifier != "" {
		return normalizeRepoURL(repoQualifier), nil
	}

	switch purl.Type {
	case "github":
		return resolveGitHubRepo(purl), nil
	case "golang":
		return resolveGolangRepo(purl)
	case "npm":
		return resolveNPMRepo(purl, "https://registry.npmjs.org")
	case "pypi":
		return resolvePyPIRepo(purl, "https://pypi.org")
	case "cargo":
		return resolveCargoRepo(purl, "https://crates.io")
	case "gem":
		return resolveGemRepo(purl, "https://rubygems.org")
	default:
		return "", []string{
			fmt.Sprintf("Unsupported pURL type %q: cannot auto-resolve repository URL", purl.Type),
			fmt.Sprintf("Tip: use the repository_url qualifier, e.g., pkg:%s/%s?repository_url=https://github.com/owner/repo", purl.Type, purl.Name),
		}
	}
}

// resolveGitHubRepo constructs a GitHub URL directly from the pURL namespace and name.
func resolveGitHubRepo(purl packageurl.PackageURL) string {
	return fmt.Sprintf("https://github.com/%s/%s", purl.Namespace, purl.Name)
}

// resolveGolangRepo resolves a Go module pURL to a repository URL.
// For github.com import paths, it constructs the URL directly (trimming to 3 path segments).
// Warns for non-GitHub Go modules.
func resolveGolangRepo(purl packageurl.PackageURL) (string, []string) {
	// Reconstruct the full module path from namespace + name
	modulePath := purl.Namespace
	if modulePath != "" {
		modulePath += "/" + purl.Name
	} else {
		modulePath = purl.Name
	}

	// Handle subpackages by extracting the first path component after the name
	if purl.Subpath != "" {
		// Subpath is already handled by the library; modulePath is the module root
	}

	// For github.com paths, trim to 3 segments: github.com/owner/repo
	if strings.HasPrefix(modulePath, "github.com/") {
		segments := strings.SplitN(modulePath, "/", 4)
		if len(segments) >= 3 {
			return fmt.Sprintf("https://%s/%s/%s", segments[0], segments[1], segments[2]), nil
		}
	}

	return "", []string{
		fmt.Sprintf("Cannot auto-resolve non-GitHub Go module %q", modulePath),
		"Tip: use the repository_url qualifier to specify the source repository",
	}
}

// resolveNPMRepo queries the npm registry to find the repository URL for a package.
func resolveNPMRepo(purl packageurl.PackageURL, baseURL string) (string, []string) {
	name := purl.Name
	if purl.Namespace != "" {
		name = purl.Namespace + "/" + name
	}

	resp, err := httpClient.Get(baseURL + "/" + name)
	if err != nil {
		return "", []string{fmt.Sprintf("npm registry request failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", []string{fmt.Sprintf("npm registry returned HTTP %d for package %q", resp.StatusCode, name)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", []string{fmt.Sprintf("failed to read npm registry response: %v", err)}
	}

	var data struct {
		Repository struct {
			URL string `json:"url"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", []string{fmt.Sprintf("failed to parse npm registry response: %v", err)}
	}

	if data.Repository.URL == "" {
		return "", []string{fmt.Sprintf("npm package %q has no repository URL", name)}
	}

	return normalizeRepoURL(data.Repository.URL), nil
}

// resolvePyPIRepo queries the PyPI API to find the repository URL for a package.
func resolvePyPIRepo(purl packageurl.PackageURL, baseURL string) (string, []string) {
	resp, err := httpClient.Get(baseURL + "/pypi/" + purl.Name + "/json")
	if err != nil {
		return "", []string{fmt.Sprintf("PyPI request failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", []string{fmt.Sprintf("PyPI returned HTTP %d for package %q", resp.StatusCode, purl.Name)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", []string{fmt.Sprintf("failed to read PyPI response: %v", err)}
	}

	var data struct {
		Info struct {
			ProjectURLs map[string]string `json:"project_urls"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", []string{fmt.Sprintf("failed to parse PyPI response: %v", err)}
	}

	// Search project_urls for source/repo keys (case-insensitive)
	sourceKeys := []string{"Source", "Source Code", "Repository", "Code", "Homepage", "GitHub"}
	for _, key := range sourceKeys {
		for urlKey, urlVal := range data.Info.ProjectURLs {
			if strings.EqualFold(urlKey, key) && strings.Contains(urlVal, "github.com") {
				return normalizeRepoURL(urlVal), nil
			}
		}
	}

	return "", []string{fmt.Sprintf("PyPI package %q has no recognizable repository URL in project_urls", purl.Name)}
}

// resolveCargoRepo queries crates.io to find the repository URL for a Rust crate.
func resolveCargoRepo(purl packageurl.PackageURL, baseURL string) (string, []string) {
	req, err := http.NewRequest("GET", baseURL+"/api/v1/crates/"+purl.Name, nil)
	if err != nil {
		return "", []string{fmt.Sprintf("failed to create crates.io request: %v", err)}
	}
	// crates.io requires a User-Agent header
	req.Header.Set("User-Agent", "allscan (https://github.com/craslaw/allscan)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", []string{fmt.Sprintf("crates.io request failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", []string{fmt.Sprintf("crates.io returned HTTP %d for crate %q", resp.StatusCode, purl.Name)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", []string{fmt.Sprintf("failed to read crates.io response: %v", err)}
	}

	var data struct {
		Crate struct {
			Repository string `json:"repository"`
		} `json:"crate"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", []string{fmt.Sprintf("failed to parse crates.io response: %v", err)}
	}

	if data.Crate.Repository == "" {
		return "", []string{fmt.Sprintf("crate %q has no repository URL", purl.Name)}
	}

	return normalizeRepoURL(data.Crate.Repository), nil
}

// resolveGemRepo queries RubyGems to find the repository URL for a gem.
func resolveGemRepo(purl packageurl.PackageURL, baseURL string) (string, []string) {
	resp, err := httpClient.Get(baseURL + "/api/v1/gems/" + purl.Name + ".json")
	if err != nil {
		return "", []string{fmt.Sprintf("RubyGems request failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", []string{fmt.Sprintf("RubyGems returned HTTP %d for gem %q", resp.StatusCode, purl.Name)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", []string{fmt.Sprintf("failed to read RubyGems response: %v", err)}
	}

	var data struct {
		SourceCodeURI string `json:"source_code_uri"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", []string{fmt.Sprintf("failed to parse RubyGems response: %v", err)}
	}

	if data.SourceCodeURI == "" {
		return "", []string{fmt.Sprintf("gem %q has no source_code_uri", purl.Name)}
	}

	return normalizeRepoURL(data.SourceCodeURI), nil
}

// resolveVersionTag searches the remote tags for a tag matching the pURL version.
// pURL versions often don't match git tags exactly (e.g., pURL "0.10.75" may correspond
// to git tag "openssl-v0.10.75" or "v0.10.75"). This function tries exact match first,
// then falls back to suffix matching.
// Returns the matched tag name and commit hash, or empty strings if no match is found.
func resolveVersionTag(repoURL, version string) (tagName, commitHash string) {
	return resolveVersionTagFromOutput(repoURL, version, nil)
}

// resolveVersionTagFromOutput is the testable core of resolveVersionTag.
// If lsRemoteOutput is nil, it runs git ls-remote against the repo URL.
func resolveVersionTagFromOutput(repoURL, version string, lsRemoteOutput []byte) (tagName, commitHash string) {
	if lsRemoteOutput == nil {
		cmd := exec.Command("git", "ls-remote", "--tags", repoURL)
		output, err := cmd.Output()
		if err != nil {
			log.Printf("⚠️  Could not list tags for %s: %v", repoURL, err)
			return "", ""
		}
		lsRemoteOutput = output
	}

	// Parse all tags and their dereferenced commits
	type tagInfo struct {
		name string
		hash string
	}
	var tags []tagInfo
	derefHashes := make(map[string]string)

	lines := strings.Split(strings.TrimSpace(string(lsRemoteOutput)), "\n")
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
			tagName := strings.TrimPrefix(base, "refs/tags/")
			derefHashes[tagName] = hash
			continue
		}

		if !strings.HasPrefix(ref, "refs/tags/") {
			continue
		}

		name := strings.TrimPrefix(ref, "refs/tags/")
		tags = append(tags, tagInfo{name: name, hash: hash})
	}

	// Build candidate version strings to match against tag names.
	// For version "0.10.75", try: "0.10.75", "v0.10.75"
	candidates := []string{version}
	if !strings.HasPrefix(version, "v") {
		candidates = append(candidates, "v"+version)
	}

	// Pass 1: exact match
	for _, tag := range tags {
		for _, candidate := range candidates {
			if tag.name == candidate {
				hash := tag.hash
				if deref, ok := derefHashes[tag.name]; ok {
					hash = deref
				}
				return tag.name, hash
			}
		}
	}

	// Pass 2: tag ends with the version (e.g., "openssl-v0.10.75" matches "0.10.75")
	for _, tag := range tags {
		for _, candidate := range candidates {
			if strings.HasSuffix(tag.name, "-"+candidate) || strings.HasSuffix(tag.name, "/"+candidate) {
				hash := tag.hash
				if deref, ok := derefHashes[tag.name]; ok {
					hash = deref
				}
				return tag.name, hash
			}
		}
	}

	return "", ""
}

// resolvePURLVersion resolves a pURL version to a RepositoryConfig by finding
// the matching git tag and using its commit hash for cloning.
// The original pURL version is preserved in PURLVersion for SBOM naming.
func resolvePURLVersion(repoURL, version string) RepositoryConfig {
	tagName, commitHash := resolveVersionTag(repoURL, version)
	if tagName != "" {
		shortHash := commitHash
		if len(shortHash) > 7 {
			shortHash = shortHash[:7]
		}
		log.Printf("🏷️  Matched pURL version %s → tag %s (%s)", version, tagName, shortHash)
		return RepositoryConfig{URL: repoURL, Version: tagName, Commit: shortHash, PURLVersion: version}
	}

	// No matching tag found — fall back to using the version directly as a tag name.
	// This will work when the pURL version exactly matches the git tag.
	log.Printf("⚠️  No tag matching version %q found, trying as literal tag", version)
	return RepositoryConfig{URL: repoURL, Version: version, PURLVersion: version}
}

// resolvePURLToTarget resolves a pURL string from --purl flag into a RepositoryConfig.
// Returns nil (with no error) if the user chose to skip after a failed resolution.
func resolvePURLToTarget(purlStr string) (*RepositoryConfig, error) {
	repoURL, version, warnings, err := resolvePURL(purlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve pURL: %w", err)
	}

	if repoURL == "" {
		fmt.Println("\n⚠️  Could not resolve source repository from pURL:")
		for _, w := range warnings {
			fmt.Printf("   - %s\n", w)
		}
		fmt.Println("\nWithout a source repository, this pURL will be skipped.")
		if !promptYesNo("Continue without this target? [y/N]: ") {
			return nil, fmt.Errorf("aborted: could not resolve repository from pURL")
		}
		return nil, nil
	}

	for _, w := range warnings {
		log.Printf("⚠️  %s", w)
	}
	log.Printf("📦 Resolved pURL %s → %s", purlStr, repoURL)

	if version != "" {
		target := resolvePURLVersion(repoURL, version)
		return &target, nil
	}
	target := resolveRepoTarget(repoURL)
	return &target, nil
}

// resolvePURLEntries resolves any RepositoryConfig entries that have a PURL field
// set instead of a URL. The PURL is resolved to a URL (and optionally a version),
// and the entry is updated in place. Entries that fail to resolve are skipped with a warning.
func resolvePURLEntries(repos []RepositoryConfig) []RepositoryConfig {
	var resolved []RepositoryConfig
	for _, repo := range repos {
		if repo.PURL == "" {
			resolved = append(resolved, repo)
			continue
		}

		repoURL, version, warnings, err := resolvePURL(repo.PURL)
		if err != nil {
			log.Printf("⚠️  Skipping pURL %s: %v", repo.PURL, err)
			continue
		}
		if repoURL == "" {
			log.Printf("⚠️  Skipping pURL %s: could not resolve repository", repo.PURL)
			for _, w := range warnings {
				log.Printf("   %s", w)
			}
			continue
		}

		for _, w := range warnings {
			log.Printf("⚠️  %s", w)
		}
		log.Printf("📦 Resolved pURL %s → %s", repo.PURL, repoURL)

		repo.URL = repoURL
		if version != "" {
			repo.PURLVersion = version
		}
		if repo.Version == "" && repo.Branch == "" && repo.Commit == "" {
			if version != "" {
				// Resolve pURL version to a matching git tag + commit
				target := resolvePURLVersion(repoURL, version)
				repo.Version = target.Version
				repo.Commit = target.Commit
			} else {
				// No version info at all — resolve latest tag
				target := resolveRepoTarget(repoURL)
				repo.Version = target.Version
				repo.Branch = target.Branch
				repo.Commit = target.Commit
			}
		}
		resolved = append(resolved, repo)
	}
	return resolved
}

// normalizeRepoURL normalizes various git URL formats to a clean HTTPS URL.
// Handles git+https://, git://, ssh://, git@host:path, and trailing .git or /.
func normalizeRepoURL(raw string) string {
	s := strings.TrimSpace(raw)

	// Strip git+ prefix (e.g., git+https://...)
	s = strings.TrimPrefix(s, "git+")

	// Convert git@host:path to https://host/path
	if after, ok := strings.CutPrefix(s, "git@"); ok {
		s = "https://" + strings.Replace(after, ":", "/", 1)
	}

	// Convert git:// and ssh:// to https://
	s = strings.Replace(s, "git://", "https://", 1)
	s = strings.Replace(s, "ssh://", "https://", 1)

	// Remove trailing / then .git (order matters for ".git/" case)
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")

	return s
}
