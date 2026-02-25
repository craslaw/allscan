package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
