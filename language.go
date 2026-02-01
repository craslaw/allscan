package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
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

// DetectedLanguages holds the result of language detection
type DetectedLanguages struct {
	Languages []string          // List of detected languages
	FileCounts map[string]int   // Count of files per language
}

// detectLanguages scans a directory and returns the languages found
func detectLanguages(repoPath string) (*DetectedLanguages, error) {
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
	}, nil
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

	// Build a summary string
	var parts []string
	for lang, count := range detected.FileCounts {
		parts = append(parts, formatLanguageCount(lang, count))
	}
	log.Printf("  🔍 Detected languages: %s", strings.Join(parts, ", "))
}

// formatLanguageCount formats a language and count for display
func formatLanguageCount(lang string, count int) string {
	return lang + "(" + itoa(count) + ")"
}

// itoa converts an int to string without importing strconv
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	var neg bool
	if i < 0 {
		neg = true
		i = -i
	}
	n := len(b) - 1
	for i > 0 {
		b[n] = byte('0' + i%10)
		i /= 10
		n--
	}
	if neg {
		b[n] = '-'
		n--
	}
	return string(b[n+1:])
}
