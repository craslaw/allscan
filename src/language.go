package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// languageExtensions maps file extensions to language names
var languageExtensions = map[string]string{
	// Go
	".go": "go",

	// Python
	".py":  "python",
	".pyw": "python",
	".pyx": "python",

	// JavaScript/TypeScript
	".js":   "javascript",
	".jsx":  "javascript",
	".mjs":  "javascript",
	".cjs":  "javascript",
	".ts":   "typescript",
	".tsx":  "typescript",
	".mts":  "typescript",
	".cts":  "typescript",
	".vue":  "javascript",
	".svelte": "javascript",

	// Java
	".java": "java",
	".kt":   "kotlin",
	".kts":  "kotlin",

	// C/C++
	".c":   "c",
	".h":   "c",
	".cpp": "cpp",
	".cc":  "cpp",
	".cxx": "cpp",
	".hpp": "cpp",
	".hxx": "cpp",

	// C#
	".cs": "csharp",

	// Ruby
	".rb":   "ruby",
	".rake": "ruby",
	".gemspec": "ruby",

	// PHP
	".php": "php",

	// Rust
	".rs": "rust",

	// Swift
	".swift": "swift",

	// Scala
	".scala": "scala",
	".sc":    "scala",

	// Shell
	".sh":   "shell",
	".bash": "shell",
	".zsh":  "shell",

	// Perl
	".pl": "perl",
	".pm": "perl",

	// Lua
	".lua": "lua",

	// R
	".r": "r",
	".R": "r",

	// Elixir
	".ex":  "elixir",
	".exs": "elixir",

	// Erlang
	".erl": "erlang",
	".hrl": "erlang",

	// Haskell
	".hs":  "haskell",
	".lhs": "haskell",

	// Clojure
	".clj":  "clojure",
	".cljs": "clojure",
	".cljc": "clojure",

	// Dart
	".dart": "dart",

	// Objective-C
	".m":  "objective-c",
	".mm": "objective-c",

	// Groovy
	".groovy": "groovy",
	".gvy":    "groovy",
}

// manifestLanguages maps manifest/config files to languages
var manifestLanguages = map[string]string{
	"go.mod":         "go",
	"go.sum":         "go",
	"package.json":   "javascript",
	"yarn.lock":      "javascript",
	"package-lock.json": "javascript",
	"pnpm-lock.yaml": "javascript",
	"requirements.txt": "python",
	"setup.py":       "python",
	"pyproject.toml": "python",
	"Pipfile":        "python",
	"Pipfile.lock":   "python",
	"pom.xml":        "java",
	"build.gradle":   "java",
	"build.gradle.kts": "kotlin",
	"settings.gradle": "java",
	"Gemfile":        "ruby",
	"Gemfile.lock":   "ruby",
	"composer.json":  "php",
	"composer.lock":  "php",
	"Cargo.toml":     "rust",
	"Cargo.lock":     "rust",
	"Package.swift":  "swift",
	"build.sbt":      "scala",
	"mix.exs":        "elixir",
	"rebar.config":   "erlang",
	"pubspec.yaml":   "dart",
	"Makefile":       "c", // Often indicates C/C++ projects
	"CMakeLists.txt": "c",
}

// githubLanguageMap maps GitHub's language names to our internal names
var githubLanguageMap = map[string]string{
	"Go":          "go",
	"Python":      "python",
	"JavaScript":  "javascript",
	"TypeScript":  "typescript",
	"Java":        "java",
	"Kotlin":      "kotlin",
	"C":           "c",
	"C++":         "cpp",
	"C#":          "csharp",
	"Ruby":        "ruby",
	"PHP":         "php",
	"Rust":        "rust",
	"Swift":       "swift",
	"Scala":       "scala",
	"Shell":       "shell",
	"Perl":        "perl",
	"Lua":         "lua",
	"R":           "r",
	"Elixir":      "elixir",
	"Erlang":      "erlang",
	"Haskell":     "haskell",
	"Clojure":     "clojure",
	"Dart":        "dart",
	"Objective-C": "objective-c",
	"Groovy":      "groovy",
	"Vue":         "javascript",
	"Svelte":      "javascript",
}

// DetectedLanguages holds the result of language detection
type DetectedLanguages struct {
	Languages  []string       // List of detected languages
	FileCounts map[string]int // Count of files per language (bytes for GitHub API)
	Source     string         // "github-api" or "filesystem"
}

// parseGitHubURL extracts owner and repo from a GitHub URL
// Supports: https://github.com/owner/repo, git@github.com:owner/repo.git, etc.
func parseGitHubURL(repoURL string) (owner, repo string, ok bool) {
	// HTTPS format: https://github.com/owner/repo or https://github.com/owner/repo.git
	httpsRe := regexp.MustCompile(`github\.com/([^/]+)/([^/\.]+)`)
	if matches := httpsRe.FindStringSubmatch(repoURL); len(matches) == 3 {
		return matches[1], matches[2], true
	}

	// SSH format: git@github.com:owner/repo.git
	sshRe := regexp.MustCompile(`github\.com:([^/]+)/([^/\.]+)`)
	if matches := sshRe.FindStringSubmatch(repoURL); len(matches) == 3 {
		return matches[1], matches[2], true
	}

	return "", "", false
}

// detectLanguagesFromGitHub uses GitHub's API to detect repository languages
// Returns nil if the API call fails or the repo is not on GitHub
func detectLanguagesFromGitHub(repoURL string) (*DetectedLanguages, error) {
	owner, repo, ok := parseGitHubURL(repoURL)
	if !ok {
		return nil, fmt.Errorf("not a GitHub URL: %s", repoURL)
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN not set")
	}

	// Build API URL: https://api.github.com/repos/{owner}/{repo}/languages
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/languages", owner, repo)

	// Create request with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Parse response: {"Go": 12345, "Python": 6789, ...}
	var langBytes map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&langBytes); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Convert to our format
	languages := make([]string, 0, len(langBytes))
	fileCounts := make(map[string]int)

	for ghLang, bytes := range langBytes {
		// Map GitHub language name to our internal name
		internalName := strings.ToLower(ghLang)
		if mapped, ok := githubLanguageMap[ghLang]; ok {
			internalName = mapped
		}
		languages = append(languages, internalName)
		fileCounts[internalName] = bytes
	}

	return &DetectedLanguages{
		Languages:  languages,
		FileCounts: fileCounts,
		Source:     "github-api",
	}, nil
}

// detectLanguages detects languages in a repository
// For GitHub repos, it tries the API first for speed, then falls back to filesystem scan
func detectLanguages(repoPath string, repoURL string) (*DetectedLanguages, error) {
	// Try GitHub API first if we have a GitHub URL
	if repoURL != "" && !strings.HasPrefix(repoURL, "local://") {
		detected, err := detectLanguagesFromGitHub(repoURL)
		if err == nil {
			return detected, nil
		}
		// Log the fallback reason at debug level
		log.Printf("    📡 GitHub API unavailable (%v), scanning filesystem", err)
	}

	// Fall back to filesystem detection
	return detectLanguagesFromFilesystem(repoPath)
}

// detectLanguagesFromFilesystem scans a directory and returns the languages found
func detectLanguagesFromFilesystem(repoPath string) (*DetectedLanguages, error) {
	languageCounts := make(map[string]int)

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip hidden directories and common non-source directories
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") ||
			   name == "node_modules" ||
			   name == "vendor" ||
			   name == "__pycache__" ||
			   name == "venv" ||
			   name == ".venv" ||
			   name == "target" ||
			   name == "build" ||
			   name == "dist" ||
			   name == "bin" ||
			   name == "obj" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check manifest files first (higher confidence)
		filename := info.Name()
		if lang, ok := manifestLanguages[filename]; ok {
			languageCounts[lang]++
			return nil
		}

		// Check file extension
		ext := filepath.Ext(filename)
		if ext != "" {
			if lang, ok := languageExtensions[ext]; ok {
				languageCounts[lang]++
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Convert map to slice of languages
	languages := make([]string, 0, len(languageCounts))
	for lang := range languageCounts {
		languages = append(languages, lang)
	}

	return &DetectedLanguages{
		Languages:  languages,
		FileCounts: languageCounts,
		Source:     "filesystem",
	}, nil
}

// Percentages returns raw percentage (0–100) for each language based on FileCounts.
// Works with both byte counts (GitHub API) and file counts (filesystem).
func (d *DetectedLanguages) Percentages() map[string]float64 {
	if d == nil || len(d.FileCounts) == 0 {
		return nil
	}
	total := 0
	for _, n := range d.FileCounts {
		total += n
	}
	if total == 0 {
		return nil
	}
	pcts := make(map[string]float64, len(d.FileCounts))
	for lang, n := range d.FileCounts {
		pcts[lang] = float64(n) * 100.0 / float64(total)
	}
	return pcts
}

// hasLanguage checks if a specific language was detected
func (d *DetectedLanguages) hasLanguage(lang string) bool {
	for _, l := range d.Languages {
		if strings.EqualFold(l, lang) {
			return true
		}
	}
	return false
}

// hasAnyLanguage checks if any of the specified languages were detected
func (d *DetectedLanguages) hasAnyLanguage(languages []string) bool {
	for _, lang := range languages {
		if d.hasLanguage(lang) {
			return true
		}
	}
	return false
}

// logDetectedLanguages logs the detected languages in a friendly format
func logDetectedLanguages(detected *DetectedLanguages) {
	if len(detected.Languages) == 0 {
		log.Printf("  🔍 No specific languages detected")
		return
	}

	// Build a summary string with just language names (counts differ between API/filesystem)
	source := "filesystem"
	if detected.Source == "github-api" {
		source = "GitHub API"
	}
	log.Printf("  🔍 Detected languages (%s): %s", source, strings.Join(detected.Languages, ", "))
}

